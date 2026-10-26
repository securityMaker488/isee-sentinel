from __future__ import annotations

import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import sqlite3
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("forensics_worker", Path(__file__).with_name("analyze_artifact.py"))
assert SPEC and SPEC.loader
worker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(worker)


def ethernet(payload: bytes, protocol: int = 0x0800) -> bytes:
    return bytes(12) + struct.pack("!H", protocol) + payload


def ipv4(payload: bytes, protocol: int = 17, fragment: int = 0) -> bytes:
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, fragment, 64, protocol, 0, bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])) + payload


def udp() -> bytes:
    return ethernet(ipv4(struct.pack("!HHHH", 54321, 53, 8, 0)))


def pcap(packets: list[bytes], endian: str = "<", nano: bool = False, link: int = 1) -> bytes:
    result = struct.pack(endian + "IHHIIII", 0xA1B23C4D if nano else 0xA1B2C3D4, 2, 4, 0, 0, 65535, link)
    for packet in packets:
        result += struct.pack(endian + "IIII", 1700000000, 123, len(packet), len(packet)) + packet
    return result


def block(kind: int, body: bytes, endian: str = "<") -> bytes:
    assert len(body) % 4 == 0
    length = len(body) + 12
    return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)


def pcapng(packet: bytes, endian: str = "<", simple: bool = False, nanoseconds: bool = True, offset: int = 0) -> bytes:
    result = block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1), endian)
    options = struct.pack(endian + "HHB3x", 9, 1, 9 if nanoseconds else 6)
    options += struct.pack(endian + "HHq", 14, 8, offset) + bytes(4)
    result += block(1, struct.pack(endian + "HHI", 1, 0, 65535) + options, endian)
    padding = bytes((-len(packet)) % 4)
    if simple:
        return result + block(3, struct.pack(endian + "I", len(packet)) + packet + padding, endian)
    timestamp = 1700000000 * (1000000000 if nanoseconds else 1000000) + 123
    return result + block(6, struct.pack(endian + "IIIII", 0, timestamp >> 32, timestamp & 0xFFFFFFFF, len(packet), len(packet)) + packet + padding, endian)


class ForensicsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="sentinel-forensic-test-")
        self.directory = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def analyze(self, data: bytes, kind: str, **kwargs):
        file = self.directory / "artifact.bin"
        file.write_bytes(data)
        return worker.analyze_file(file, kind=kind, consent=True, **kwargs)

    def test_consent_limits_path_and_input_hash(self):
        file = self.directory / "capture.pcap"
        file.write_bytes(pcap([udp()]))
        with self.assertRaises(worker.ForensicError):
            worker.analyze_file(file, kind="pcap", consent=False)
        report = worker.analyze_file(file, kind="pcap", consent=True)
        self.assertEqual(report["input"]["sha256"], worker.digest(file.read_bytes()))
        self.assertTrue(report["input"]["unchanged"])
        self.assertNotIn(str(self.directory), json.dumps(report))
        with self.assertRaises(worker.ForensicError):
            worker.analyze_file(self.directory, kind="pcap", consent=True)
        with self.assertRaises(worker.ForensicError):
            self.analyze(bytes(worker.MAX_BYTES + 1), "pcap")

    def test_pcap_all_endian_and_precision_variants(self):
        for endian in ("<", ">"):
            for nano in (False, True):
                report = self.analyze(pcap([udp(), udp()], endian, nano), "pcap")
                self.assertEqual(report["metrics"]["packets"], 2)
                self.assertEqual(report["metrics"]["flows"], 1)
                flow = report["flows"][0]
                self.assertEqual((flow["protocol"], flow["sourcePort"], flow["destinationPort"]), ("UDP", 54321, 53))
                self.assertEqual(flow["packets"], 2)
                self.assertTrue(flow["firstSeen"].endswith(".000000123Z" if nano else ".000123000Z"))

    def test_tcp_flags_vlan_arp_and_ipv6(self):
        tcp = struct.pack("!HHIIBBHHH", 1234, 443, 0, 0, 0x50, 0x03, 1024, 0, 0)
        vlan = bytes(12) + struct.pack("!HHH", 0x8100, 1, 0x0800) + ipv4(tcp, 6)
        arp = ethernet(struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + bytes(6) + bytes([192, 0, 2, 1]) + bytes(6) + bytes([192, 0, 2, 2]), 0x0806)
        ipv6 = struct.pack("!IHBB16s16s", 6 << 28, 4, 58, 64, bytes.fromhex("20010db8000000000000000000000001"), bytes.fromhex("20010db8000000000000000000000002")) + bytes([128, 0, 0, 0])
        report = self.analyze(pcap([vlan, arp, ethernet(ipv6, 0x86DD)]), "pcap")
        self.assertEqual([flow["protocol"] for flow in report["flows"]], ["TCP", "ARP", "ICMPv6"])
        self.assertEqual(report["flows"][0]["synPackets"], 1)
        self.assertEqual(report["flows"][0]["finPackets"], 1)
        self.assertEqual(report["flows"][2]["source"], "2001:db8::1")

    def test_fragments_and_unsupported_link_types_are_explicit(self):
        report = self.analyze(pcap([ethernet(ipv4(bytes(8), fragment=1))]), "pcap")
        self.assertEqual(report["flows"][0]["protocol"], "IPv4-fragment")
        self.assertEqual(report["metrics"]["fragmentedPackets"], 1)
        report = self.analyze(pcap([udp()], link=999), "pcap")
        self.assertEqual(report["metrics"]["unsupportedOrMalformedPackets"], 1)
        self.assertEqual(report["flows"], [])

    def test_pcapng_endian_resolution_offset_and_no_timestamp(self):
        for endian in ("<", ">"):
            for nano in (False, True):
                report = self.analyze(pcapng(udp(), endian, nanoseconds=nano, offset=5), "pcap")
                self.assertEqual(report["metrics"]["format"], "pcapng")
                self.assertTrue(report["flows"][0]["firstSeen"].startswith("2023-11-14T22:13:25."))
                self.assertTrue(report["flows"][0]["firstSeen"].endswith(".000000123Z" if nano else ".000123000Z"))
        report = self.analyze(pcapng(udp(), simple=True), "pcap")
        self.assertIsNone(report["flows"][0]["firstSeen"])
        self.assertEqual(report["metrics"]["packetsWithoutTimestamp"], 1)

    def test_pcapng_multiple_sections_reset_interfaces(self):
        report = self.analyze(pcapng(udp(), "<") + pcapng(udp(), ">"), "pcap")
        self.assertEqual(report["metrics"]["packets"], 2)

    def test_capture_malformed_lengths_and_timestamps_rejected(self):
        invalid = [b"PCAP", pcap([udp()])[:-1], pcapng(udp())[:-1], pcapng(udp())[:-4] + bytes(4)]
        invalid.append(pcap([]) + struct.pack("<IIII", 1, 1000000, 0, 0))
        invalid.append(pcap([]) + struct.pack("<IIII", 1, 0, 4, 3) + bytes(4))
        for data in invalid:
            with self.assertRaises(worker.ForensicError):
                self.analyze(data, "pcap")

    def test_flow_overflow_counts_omitted_packets_without_losing_totals(self):
        second = ethernet(ipv4(struct.pack("!HHHH", 123, 443, 8, 0)))
        with patch.object(worker, "MAX_FLOWS", 1):
            report = self.analyze(pcap([udp(), second, udp()]), "pcap")
        self.assertEqual(report["metrics"]["packets"], 3)
        self.assertEqual(report["metrics"]["flowsOmittedPackets"], 1)
        self.assertTrue(report["metrics"]["flowsTruncated"])
        self.assertEqual(report["flows"][0]["packets"], 2)

    def make_database(self, count: int = 2) -> Path:
        file = self.directory / "export.sqlite"
        with sqlite3.connect(file) as connection:
            connection.execute('CREATE TABLE "events" (id INTEGER PRIMARY KEY, value TEXT, bytes BLOB)')
            connection.executemany('INSERT INTO "events" VALUES (?, ?, ?)', ((index, "PRIVATE_VALUE", b"PRIVATE_BLOB") for index in range(count)))
            connection.execute('CREATE VIEW "secret_view" AS SELECT * FROM events')
        connection.close()
        return file

    def test_sqlite_schema_count_hash_only_rows_and_original_unchanged(self):
        file = self.make_database()
        before = file.read_bytes()
        report = worker.analyze_file(file, kind="sqlite", consent=True, table="events")
        self.assertEqual(file.read_bytes(), before)
        self.assertEqual(report["tables"][0]["rowCount"], 2)
        self.assertEqual(len(report["rows"]), 2)
        self.assertEqual(set(report["rows"][0]), {"ordinal", "sha256"})
        self.assertNotIn("PRIVATE_VALUE", json.dumps(report))
        self.assertNotIn("PRIVATE_BLOB", json.dumps(report))
        self.assertFalse(report["metrics"]["valuesIncluded"])

    def test_sqlite_include_values_is_explicit_and_never_exports_blobs(self):
        file = self.make_database()
        report = worker.analyze_file(file, kind="sqlite", consent=True, table="events", include_values=True)
        self.assertIn("PRIVATE_VALUE", json.dumps(report))
        self.assertNotIn("PRIVATE_BLOB", json.dumps(report))
        with self.assertRaises(worker.ForensicError):
            worker.analyze_file(file, kind="sqlite", consent=True, include_values=True)

    def test_sqlite_table_selection_injection_view_and_write_authorization(self):
        file = self.make_database()
        for table in ('events"; DROP TABLE events; --', "secret_view", "missing"):
            with self.assertRaises(worker.ForensicError):
                worker.analyze_file(file, kind="sqlite", consent=True, table=table)
        self.assertEqual(worker._authorizer(sqlite3.SQLITE_DELETE, "events", None, "main", None), sqlite3.SQLITE_DENY)
        self.assertEqual(worker._authorizer(sqlite3.SQLITE_ATTACH, None, None, None, None), sqlite3.SQLITE_DENY)
        self.assertEqual(worker._authorizer(sqlite3.SQLITE_FUNCTION, None, "load_extension", None, None), sqlite3.SQLITE_DENY)
        with sqlite3.connect(file) as connection:
            connection.set_authorizer(worker._authorizer)
            with self.assertRaises(sqlite3.DatabaseError):
                connection.execute("DELETE FROM events")
        connection.close()

    def test_sqlite_explicit_row_limit_and_no_wal_or_shm_creation(self):
        file = self.make_database(1002)
        report = worker.analyze_file(file, kind="sqlite", consent=True, table="events")
        self.assertEqual(len(report["rows"]), 1000)
        self.assertTrue(report["metrics"]["rowsTruncated"])
        self.assertEqual(report["tables"][0]["rowCount"], 1002)
        self.assertFalse(Path(str(file) + "-wal").exists())
        self.assertFalse(Path(str(file) + "-shm").exists())

    def test_plist_xml_binary_datetime_only_and_redaction(self):
        value = {"secret-key": "PRIVATE_VALUE", "actualDate": dt.datetime(2026, 10, 24, 12, 30), "number": 1700000000, "dateString": "2026-01-01T00:00:00Z", "data": b"PRIVATE_BLOB"}
        for format_name in (plistlib.FMT_XML, plistlib.FMT_BINARY):
            report = self.analyze(plistlib.dumps(value, fmt=format_name), "plist")
            self.assertEqual(len(report["timeline"]), 1)
            self.assertEqual(report["timeline"][0]["occurredAt"], "2026-10-24T12:30:00Z")
            self.assertNotIn("PRIVATE_VALUE", json.dumps(report))
            self.assertNotIn("PRIVATE_BLOB", json.dumps(report))
            self.assertNotIn("secret-key", json.dumps(report))

    def test_plist_duplicate_keys_entities_unknown_tags_and_deep_input_rejected(self):
        invalid = [
            b'<plist><dict><key>x</key><string>a</string><key>x</key><string>b</string></dict></plist>',
            b'<!DOCTYPE plist [<!ENTITY x "secret">]><plist><string>&x;</string></plist>',
            b'<plist><unknown/></plist>',
            b'<plist>' + b'<array>' * 50 + b'<string>x</string>' + b'</array>' * 50 + b'</plist>',
            b'bplist00' + bytes(32),
        ]
        for data in invalid:
            with self.assertRaises(worker.ForensicError):
                self.analyze(data, "plist")

    def test_original_change_is_rejected(self):
        file = self.directory / "change.pcap"
        file.write_bytes(pcap([udp()]))
        real = worker.analyze_pcap
        def changed(data):
            result = real(data)
            # Windows read sharing intentionally prevents mutation while the worker holds the file.
            if os.name == "nt":
                with self.assertRaises(PermissionError):
                    file.write_bytes(b"changed")
                return result
            file.write_bytes(b"changed")
            return result
        with patch.object(worker, "analyze_pcap", changed):
            if os.name == "nt":
                self.assertTrue(worker.analyze_file(file, kind="pcap", consent=True)["input"]["unchanged"])
            else:
                with self.assertRaises(worker.ForensicError):
                    worker.analyze_file(file, kind="pcap", consent=True)

    def test_isolated_cli_json_and_nonsecret_errors(self):
        file = self.directory / "sample.pcap"
        file.write_bytes(pcap([udp()]))
        command = [sys.executable, "-I", "-B", str(Path(worker.__file__).absolute()), "--file", str(file), "--kind", "pcap"]
        rejected = subprocess.run(command, capture_output=True, timeout=10, check=False)
        self.assertEqual(rejected.returncode, 2)
        self.assertEqual(rejected.stdout, b"")
        self.assertNotIn(str(file).encode(), rejected.stderr)
        accepted = subprocess.run(command + ["--consent"], capture_output=True, timeout=10, check=False)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        report = json.loads(accepted.stdout)
        self.assertEqual(report["engineVersion"], "1.0.0")
        self.assertLess(len(accepted.stdout), worker.MAX_OUTPUT)


if __name__ == "__main__":
    unittest.main()
