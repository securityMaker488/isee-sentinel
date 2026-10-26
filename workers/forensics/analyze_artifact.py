"""Bounded, explicit-file forensic triage. Standard library only; no capture or execution."""
from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import plistlib
import sqlite3
import stat
import struct
import sys
import tempfile
import time
import xml.parsers.expat
from typing import Any

MAX_BYTES = 16 * 1024 * 1024
MAX_OUTPUT = 4 * 1024 * 1024
MAX_PACKETS = 100000
MAX_FLOWS = 4096
MAX_NODES = 50000
MAX_DEPTH = 48
MAX_ROWS = 1000
UTC = dt.timezone.utc


class ForensicError(ValueError):
    """Content-free diagnostic safe for stderr."""


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compact(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _open_read_only(path: Path) -> int:
    if os.name != "nt":
        if not hasattr(os, "O_NOFOLLOW"):
            raise ForensicError("no no-follow file adapter on this platform")
        return os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    import msvcrt
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    close = kernel.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    handle = create(str(path), 0x80000000, 0x00000001, None, 3, 0x00200000, None)
    if handle == wintypes.HANDLE(-1).value:
        raise ForensicError("file cannot be opened read-only")
    try:
        return msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except Exception:
        close(handle)
        raise ForensicError("file handle unavailable") from None


def _metadata(path: Path) -> os.stat_result:
    value = path.lstat()
    if stat.S_ISLNK(value.st_mode) or getattr(value, "st_file_attributes", 0) & 0x400:
        raise ForensicError("symbolic links and reparse points are not supported")
    return value


def _timestamp(nanoseconds: int | None) -> str | None:
    if nanoseconds is None:
        return None
    seconds, remainder = divmod(nanoseconds, 1000000000)
    try:
        value = dt.datetime(1970, 1, 1, tzinfo=UTC) + dt.timedelta(seconds=seconds)
    except (OverflowError, ValueError):
        raise ForensicError("capture timestamp outside supported calendar range") from None
    return value.strftime("%Y-%m-%dT%H:%M:%S") + f".{remainder:09d}Z"


def _transport(data: bytes, start: int, end: int, protocol: int) -> tuple[str, int | None, int | None, int]:
    names = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}
    name = names.get(protocol, f"IP-{protocol}")
    if protocol == 6:
        if end - start < 20:
            return name, None, None, 0
        header = (data[start + 12] >> 4) * 4
        if header < 20 or start + header > end:
            return name, None, None, 0
        source, destination = struct.unpack_from("!HH", data, start)
        return name, source, destination, data[start + 13]
    if protocol == 17:
        if end - start < 8:
            return name, None, None, 0
        source, destination, length = struct.unpack_from("!HHH", data, start)
        if length < 8:
            return name, None, None, 0
        return name, source, destination, 0
    return name, None, None, 0


def _decode_packet(data: bytes, link: int) -> dict[str, Any] | None:
    start = 0
    if link == 1:
        if len(data) < 14:
            return None
        protocol = struct.unpack_from("!H", data, 12)[0]
        start = 14
        for _ in range(2):
            if protocol not in (0x8100, 0x88A8):
                break
            if len(data) < start + 4:
                return None
            protocol = struct.unpack_from("!H", data, start + 2)[0]
            start += 4
    elif link in (101, 228, 229):
        if not data:
            return None
        protocol = {4: 0x0800, 6: 0x86DD}.get(data[0] >> 4, 0)
        if link in (228, 229) and protocol != {228: 0x0800, 229: 0x86DD}[link]:
            return None
    else:
        return None
    if protocol == 0x0806:
        if len(data) < start + 28:
            return None
        hardware, network, hardware_len, network_len, opcode = struct.unpack_from("!HHBBH", data, start)
        if (hardware, network, hardware_len, network_len) != (1, 0x0800, 6, 4):
            return None
        return {"family": "ARP", "protocol": "ARP", "source": str(ipaddress.ip_address(data[start + 14:start + 18])), "destination": str(ipaddress.ip_address(data[start + 24:start + 28])), "sourcePort": None, "destinationPort": None, "flags": 0, "fragmented": False, "arpOpcode": opcode}
    if protocol == 0x0800:
        if len(data) < start + 20 or data[start] >> 4 != 4:
            return None
        header = (data[start] & 15) * 4
        total = struct.unpack_from("!H", data, start + 2)[0]
        if header < 20 or total < header or len(data) < start + header:
            return None
        end = min(len(data), start + total)
        fragment = struct.unpack_from("!H", data, start + 6)[0]
        fragmented = bool(fragment & 0x3FFF)
        source = str(ipaddress.ip_address(data[start + 12:start + 16]))
        destination = str(ipaddress.ip_address(data[start + 16:start + 20]))
        if fragment & 0x1FFF:
            name, sport, dport, flags = "IPv4-fragment", None, None, 0
        else:
            name, sport, dport, flags = _transport(data, start + header, end, data[start + 9])
        family = "IPv4"
    elif protocol == 0x86DD:
        if len(data) < start + 40 or data[start] >> 4 != 6:
            return None
        payload_len = struct.unpack_from("!H", data, start + 4)[0]
        end = min(len(data), start + 40 + payload_len)
        source = str(ipaddress.ip_address(data[start + 8:start + 24]))
        destination = str(ipaddress.ip_address(data[start + 24:start + 40]))
        next_header, cursor, fragmented = data[start + 6], start + 40, False
        nonfirst = False
        for _ in range(8):
            if next_header not in (0, 43, 44, 51, 60):
                break
            if cursor + 2 > end:
                return None
            following = data[cursor]
            if next_header == 44:
                length = 8
                if cursor + length > end:
                    return None
                fragment = struct.unpack_from("!H", data, cursor + 2)[0]
                fragmented = True
                nonfirst = bool(fragment & 0xFFF8)
            elif next_header == 51:
                length = (data[cursor + 1] + 2) * 4
            else:
                length = (data[cursor + 1] + 1) * 8
            if cursor + length > end:
                return None
            cursor += length
            next_header = following
            if nonfirst:
                break
        else:
            return None
        if nonfirst:
            name, sport, dport, flags = "IPv6-fragment", None, None, 0
        else:
            name, sport, dport, flags = _transport(data, cursor, end, next_header)
        family = "IPv6"
    else:
        return None
    return {"family": family, "protocol": name, "source": source, "destination": destination, "sourcePort": sport, "destinationPort": dport, "flags": flags, "fragmented": fragmented}


class PacketSummary:
    def __init__(self) -> None:
        self.metrics: dict[str, Any] = {"packets": 0, "capturedBytes": 0, "originalBytes": 0, "truncatedPackets": 0, "decodedPackets": 0, "unsupportedOrMalformedPackets": 0, "fragmentedPackets": 0, "packetsWithoutTimestamp": 0, "flowsOmittedPackets": 0, "flowsTruncated": False, "unknownBlocks": 0}
        self.flows: dict[tuple[Any, ...], dict[str, Any]] = {}
        self.first: int | None = None
        self.last: int | None = None

    def add(self, data: bytes, original: int, timestamp: int | None, link: int) -> None:
        self.metrics["packets"] += 1
        if self.metrics["packets"] > MAX_PACKETS:
            raise ForensicError("capture exceeds 100000 packets")
        self.metrics["capturedBytes"] += len(data)
        self.metrics["originalBytes"] += original
        self.metrics["truncatedPackets"] += int(len(data) < original)
        if timestamp is not None:
            _timestamp(timestamp)
            self.first = timestamp if self.first is None else min(self.first, timestamp)
            self.last = timestamp if self.last is None else max(self.last, timestamp)
        else:
            self.metrics["packetsWithoutTimestamp"] += 1
        packet = _decode_packet(data, link)
        if packet is None:
            self.metrics["unsupportedOrMalformedPackets"] += 1
            return
        self.metrics["decodedPackets"] += 1
        self.metrics["fragmentedPackets"] += int(packet["fragmented"])
        key = tuple(packet.get(name) for name in ("family", "protocol", "source", "destination", "sourcePort", "destinationPort"))
        flow = self.flows.get(key)
        if flow is None:
            if len(self.flows) >= MAX_FLOWS:
                self.metrics["flowsOmittedPackets"] += 1
                self.metrics["flowsTruncated"] = True
                return
            flow = {name: packet[name] for name in ("family", "protocol", "source", "destination", "sourcePort", "destinationPort")}
            flow.update({"packets": 0, "capturedBytes": 0, "originalBytes": 0, "firstNs": None, "lastNs": None, "synPackets": 0, "finPackets": 0, "resetPackets": 0})
            self.flows[key] = flow
        flow["packets"] += 1
        flow["capturedBytes"] += len(data)
        flow["originalBytes"] += original
        flow["synPackets"] += int(bool(packet["flags"] & 2))
        flow["finPackets"] += int(bool(packet["flags"] & 1))
        flow["resetPackets"] += int(bool(packet["flags"] & 4))
        if timestamp is not None:
            flow["firstNs"] = timestamp if flow["firstNs"] is None else min(flow["firstNs"], timestamp)
            flow["lastNs"] = timestamp if flow["lastNs"] is None else max(flow["lastNs"], timestamp)

    def result(self, format_name: str) -> dict[str, Any]:
        flows = []
        for original in self.flows.values():
            flow = dict(original)
            flow["firstSeen"] = _timestamp(flow.pop("firstNs"))
            flow["lastSeen"] = _timestamp(flow.pop("lastNs"))
            flows.append(flow)
        self.metrics.update({"format": format_name, "flows": len(flows), "firstSeen": _timestamp(self.first), "lastSeen": _timestamp(self.last)})
        return {"metrics": self.metrics, "flows": flows, "summary": f"{self.metrics['packets']} packets; {len(flows)} directional flows retained.", "limitations": ["Offline capture metadata only. No live capture, DNS resolution, payload export, TLS decryption, stream reassembly, checksum validation or attack verdict.", "Supported link types: Ethernet (up to two VLAN tags), raw IP, IPv4 and IPv6. Other or incomplete frames are counted explicitly. Noninitial fragments are separate flows; at most eight IPv6 extensions are traversed.", "Flows are directional aggregates, not TCP sessions. A maximum of 4096 flow keys is retained; omission counters identify overflow. Timestamps preserve nanoseconds where available, without validating the source clock."]}


def _options(data: bytes, endian: str) -> list[tuple[int, bytes]]:
    result = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            raise ForensicError("truncated pcapng options")
        code, length = struct.unpack_from(endian + "HH", data, offset)
        offset += 4
        if code == 0:
            if length != 0 or any(data[offset:]):
                raise ForensicError("invalid pcapng option terminator")
            return result
        padded = (length + 3) & ~3
        if padded > len(data) - offset:
            raise ForensicError("pcapng option outside block")
        result.append((code, data[offset:offset + length]))
        offset += padded
        if len(result) > 1000:
            raise ForensicError("too many pcapng options")
    return result


def analyze_pcap(data: bytes) -> dict[str, Any]:
    summary = PacketSummary()
    magic = data[:4]
    formats = {b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\xa1\xb2\xc3\xd4": (">", 1000), b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1)}
    if magic in formats:
        if len(data) < 24:
            raise ForensicError("truncated pcap header")
        endian, multiplier = formats[magic]
        major, minor, _reserved1, _reserved2, snaplen, network = struct.unpack_from(endian + "HHIIII", data, 4)
        if (major, minor) != (2, 4) or snaplen == 0 or snaplen > MAX_BYTES:
            raise ForensicError("unsupported pcap version or snapshot length")
        link = network & 0xFFFF
        offset = 24
        while offset < len(data):
            if len(data) - offset < 16:
                raise ForensicError("truncated pcap record header")
            seconds, fraction, captured, original = struct.unpack_from(endian + "IIII", data, offset)
            offset += 16
            if fraction >= 1000000000 // multiplier or captured > original or captured > snaplen or captured > len(data) - offset:
                raise ForensicError("invalid pcap record length or timestamp")
            summary.add(data[offset:offset + captured], original, seconds * 1000000000 + fraction * multiplier, link)
            offset += captured
        return summary.result("pcap")
    if magic != b"\x0a\x0d\x0d\x0a":
        raise ForensicError("unsupported capture signature")
    offset, blocks = 0, 0
    endian: str | None = None
    interfaces: list[tuple[int, int, int, int]] = []
    while offset < len(data):
        blocks += 1
        if blocks > 200000 or len(data) - offset < 12:
            raise ForensicError("truncated pcapng block or too many blocks")
        section = data[offset:offset + 4] == b"\x0a\x0d\x0d\x0a"
        if section:
            marker = data[offset + 8:offset + 12]
            endian = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}.get(marker)
            if endian is None:
                raise ForensicError("invalid pcapng byte-order magic")
        if endian is None:
            raise ForensicError("pcapng section header is required")
        block_type, length = struct.unpack_from(endian + "II", data, offset)
        if length < 12 or length % 4 or length > len(data) - offset or struct.unpack_from(endian + "I", data, offset + length - 4)[0] != length:
            raise ForensicError("pcapng block lengths do not match")
        body = data[offset + 8:offset + length - 4]
        if section:
            if length < 28 or struct.unpack_from(endian + "HH", body, 4) != (1, 0):
                raise ForensicError("unsupported pcapng section version")
            _options(body[16:], endian)
            interfaces = []
        elif block_type == 1:
            if len(body) < 8 or len(interfaces) >= 256:
                raise ForensicError("invalid pcapng interface")
            link, reserved, snaplen = struct.unpack_from(endian + "HHI", body)
            if reserved != 0 or snaplen > MAX_BYTES:
                raise ForensicError("invalid pcapng snapshot length")
            resolution, tsoffset, seen = 1000000, 0, set()
            for code, value in _options(body[8:], endian):
                if code in (9, 14):
                    if code in seen:
                        raise ForensicError("duplicate pcapng timestamp option")
                    seen.add(code)
                if code == 9:
                    if len(value) != 1:
                        raise ForensicError("invalid pcapng timestamp resolution")
                    exponent = value[0] & 0x7F
                    if exponent > (63 if value[0] & 0x80 else 18):
                        raise ForensicError("unsupported pcapng timestamp resolution")
                    resolution = (2 if value[0] & 0x80 else 10) ** exponent
                elif code == 14:
                    if len(value) != 8:
                        raise ForensicError("invalid pcapng timestamp offset")
                    tsoffset = struct.unpack(endian + "q", value)[0]
            interfaces.append((link, snaplen, resolution, tsoffset))
        elif block_type == 6:
            if len(body) < 20:
                raise ForensicError("truncated pcapng packet header")
            interface, high, low, captured, original = struct.unpack_from(endian + "IIIII", body)
            if interface >= len(interfaces):
                raise ForensicError("unknown pcapng interface")
            link, snaplen, resolution, tsoffset = interfaces[interface]
            padded = (captured + 3) & ~3
            if captured > original or (snaplen and captured > snaplen) or padded > len(body) - 20:
                raise ForensicError("invalid pcapng packet length")
            _options(body[20 + padded:], endian)
            timestamp = (((high << 32) | low) * 1000000000 // resolution) + tsoffset * 1000000000
            summary.add(body[20:20 + captured], original, timestamp, link)
        elif block_type == 3:
            if len(body) < 4 or not interfaces:
                raise ForensicError("invalid pcapng simple packet")
            original = struct.unpack_from(endian + "I", body)[0]
            link, snaplen, _resolution, _offset = interfaces[0]
            captured = min(original, snaplen) if snaplen else original
            if ((captured + 3) & ~3) != len(body) - 4:
                raise ForensicError("invalid pcapng simple packet length")
            summary.add(body[4:4 + captured], original, None, link)
        elif block_type == 2:
            raise ForensicError("obsolete pcapng Packet Blocks are unsupported; export Enhanced Packet Blocks")
        else:
            summary.metrics["unknownBlocks"] += 1
        offset += length
    return summary.result("pcapng")


def _quote_identifier(name: str) -> str:
    if not name or len(name) > 256 or any(ord(char) < 32 for char in name):
        raise ForensicError("invalid SQLite identifier")
    return '"' + name.replace('"', '""') + '"'


def _safe_value(value: Any, include_values: bool) -> Any:
    if isinstance(value, bytes):
        return {"type": "blob", "bytes": len(value), "sha256": digest(value)}
    if isinstance(value, str):
        encoded = value.encode("utf-8", "surrogatepass")
        result: dict[str, Any] = {"type": "text", "bytes": len(encoded), "sha256": digest(encoded)}
        if include_values:
            result.update({"value": value[:1024], "truncated": len(value) > 1024})
        return result
    if isinstance(value, float) and not math.isfinite(value):
        return {"type": "nonfinite", "value": str(value)}
    return value


def _authorizer(action: int, first: str | None, second: str | None, database: str | None, source: str | None) -> int:
    if source is not None or database not in (None, "main"):
        return sqlite3.SQLITE_DENY
    if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ):
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_FUNCTION and (second or "").lower() == "count":
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_PRAGMA and first in ("table_xinfo", "table_list"):
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def analyze_sqlite(data: bytes, table: str | None, include_values: bool) -> dict[str, Any]:
    if data[:16] != b"SQLite format 3\x00":
        raise ForensicError("unsupported SQLite signature")
    if include_values and table is None:
        raise ForensicError("--include-values requires an explicit --table")
    if table is not None:
        _quote_identifier(table)
    # A private immutable snapshot isolates SQLite from the original path and all WAL/SHM sidecars.
    with tempfile.TemporaryDirectory(prefix="sentinel-forensic-") as directory:
        snapshot = Path(directory) / "snapshot.sqlite"
        descriptor = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
        connection = sqlite3.connect(snapshot.as_uri() + "?mode=ro&immutable=1", uri=True, timeout=1)
        try:
            connection.enable_load_extension(False)
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA temp_store=MEMORY")
            connection.execute("PRAGMA cache_size=-4096")
            connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 1024 * 1024)
            connection.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, 256)
            connection.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 65536)
            connection.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)
            deadline, steps = time.monotonic() + 5, [0]
            def progress() -> int:
                steps[0] += 1000
                return int(steps[0] > 1000000 or time.monotonic() > deadline)
            connection.set_progress_handler(progress, 1000)
            connection.set_authorizer(_authorizer)
            schema = connection.execute("SELECT name,type,sql FROM sqlite_schema ORDER BY name LIMIT 257").fetchall()
            if len(schema) > 256:
                raise ForensicError("SQLite schema exceeds 256 objects")
            tables = []
            allowed: dict[str, list[str]] = {}
            for name, kind, sql in schema:
                if kind != "table" or name.startswith("sqlite_"):
                    continue
                _quote_identifier(name)
                virtual = isinstance(sql, str) and sql.lstrip().upper().startswith("CREATE VIRTUAL TABLE")
                if virtual:
                    tables.append({"name": name, "supported": False, "reason": "virtual tables are not queried"})
                    continue
                columns = connection.execute("PRAGMA table_xinfo(" + _quote_identifier(name) + ")").fetchall()
                if len(columns) > 64:
                    raise ForensicError("SQLite table exceeds 64 columns")
                normal = [row[1] for row in columns if row[6] == 0]
                for column in normal:
                    _quote_identifier(column)
                count = connection.execute("SELECT count(*) FROM " + _quote_identifier(name)).fetchone()[0]
                tables.append({"name": name, "supported": True, "rowCount": count, "columns": [{"name": row[1], "declaredType": str(row[2])[:80], "notNull": bool(row[3]), "primaryKeyOrder": row[5], "generatedOrHidden": bool(row[6])} for row in columns]})
                allowed[name] = normal
            result: dict[str, Any] = {"metrics": {"format": "sqlite3", "sqliteRuntime": sqlite3.sqlite_version, "schemaObjects": len(schema), "tables": len(tables), "valuesIncluded": include_values, "rowsReturned": 0, "rowsTruncated": False}, "tables": tables, "rows": [], "summary": f"{len(tables)} user tables inspected in a private read-only snapshot.", "limitations": ["Logical inspection of one exported SQLite main file. WAL, SHM, journal, views, triggers and virtual tables are not executed or merged. Use a consistent closed export; this worker does not acquire live applications or recover deleted records.", "Original bytes are hashed before and after. Queries run on a temporary immutable snapshot with extension loading disabled, trusted_schema OFF, a deny-by-default authorizer and bounded VM time. Runtime SQLite must still be kept patched.", "An explicit table exports at most 1000 rows in storage traversal order, without a promised ordering. Row digests cover typed values; text and blob content is omitted by default. --include-values exposes text prefixes and scalar values locally; blobs remain hashes."]}
            if table is not None:
                if table not in allowed or not allowed[table]:
                    raise ForensicError("requested table is absent or unsupported")
                sql = "SELECT " + ",".join(_quote_identifier(name) for name in allowed[table]) + " FROM " + _quote_identifier(table) + " LIMIT ?"
                rows = connection.execute(sql, (MAX_ROWS + 1,)).fetchall()
                result["metrics"].update({"selectedTable": table, "rowsReturned": min(len(rows), MAX_ROWS), "rowsTruncated": len(rows) > MAX_ROWS})
                for index, row in enumerate(rows[:MAX_ROWS]):
                    typed = [_safe_value(value, False) for value in row]
                    item: dict[str, Any] = {"ordinal": index, "sha256": digest(compact(typed))}
                    if include_values:
                        item["values"] = [_safe_value(value, True) for value in row]
                    result["rows"].append(item)
            return result
        except ForensicError:
            raise
        except sqlite3.Error:
            raise ForensicError("SQLite is malformed, unsupported or exceeded the query budget") from None
        finally:
            connection.close()


def _plist_preflight(data: bytes) -> None:
    if data.startswith(b"bplist00"):
        if len(data) < 40:
            raise ForensicError("truncated binary plist")
        _unused, offset_size, ref_size, objects, top, table = struct.unpack(">6sBBQQQ", data[-32:])
        if not 1 <= offset_size <= 8 or not 1 <= ref_size <= 8 or not 1 <= objects <= MAX_NODES or top >= objects or table < 8 or table + objects * offset_size > len(data) - 32:
            raise ForensicError("binary plist trailer outside supported limits")
        return
    parser = xml.parsers.expat.ParserCreate()
    depth, count = [0], [0]
    allowed = {"plist", "dict", "key", "array", "string", "data", "date", "true", "false", "integer", "real"}
    def start(name: str, attributes: dict[str, str]) -> None:
        depth[0] += 1
        count[0] += 1
        if name not in allowed or depth[0] > MAX_DEPTH or count[0] > MAX_NODES:
            raise ForensicError("plist XML exceeds the supported structure")
    def end(_name: str) -> None:
        depth[0] -= 1
    def entity(*_args: Any) -> None:
        raise ForensicError("plist entity declarations are not accepted")
    def external(*_args: Any) -> int:
        raise ForensicError("external plist entities are not accepted")
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.EntityDeclHandler = entity
    parser.ExternalEntityRefHandler = external
    parser.Parse(data, True)


def analyze_plist(data: bytes) -> dict[str, Any]:
    _plist_preflight(data)
    class UniqueDict(dict):
        def __setitem__(self, key: Any, value: Any) -> None:
            if key in self:
                raise ForensicError("duplicate plist dictionary keys are not accepted")
            super().__setitem__(key, value)
    root = plistlib.loads(data, dict_type=UniqueDict)
    stack = [(root, "$", 0, frozenset())]
    nodes, strings, binary_bytes = 0, 0, 0
    timeline = []
    while stack:
        value, path, depth, ancestors = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise ForensicError("plist exceeds the node or depth limit")
        if isinstance(value, (dict, list)):
            if id(value) in ancestors:
                raise ForensicError("cyclic plist objects are not accepted")
            parents = ancestors | {id(value)}
            values = list(value.values()) if isinstance(value, dict) else value
            for index in range(len(values) - 1, -1, -1):
                stack.append((values[index], f"{path}/{index}", depth + 1, parents))
        elif isinstance(value, dt.datetime):
            if len(timeline) >= 2000:
                raise ForensicError("plist exceeds 2000 datetime records")
            timestamp = (value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)).isoformat().replace("+00:00", "Z")
            timeline.append({"occurredAt": timestamp, "eventType": "plist.datetime", "source": "plist-export", "location": path, "evidenceHash": digest(compact({"location": path, "datetime": timestamp}))})
        elif isinstance(value, str):
            strings += 1
        elif isinstance(value, bytes):
            binary_bytes += len(value)
    timeline.sort(key=lambda item: (item["occurredAt"], item["location"]))
    return {"metrics": {"format": "binary-plist" if data.startswith(b"bplist00") else "xml-plist", "nodes": nodes, "strings": strings, "embeddedBinaryBytes": binary_bytes, "datetimes": len(timeline)}, "timeline": timeline, "summary": f"{nodes} plist values; {len(timeline)} explicit datetime records normalized to UTC.", "limitations": ["Reads an explicitly exported plist, not a connected device, backup account or live application. It does not decrypt data, resolve NSKeyedArchiver UID references, recover deleted records or acquire a disk/phone.", "Only actual plist datetime values enter the timeline. Numeric/string values are never guessed as timestamps. Datetime presence does not establish what event occurred or whether the source clock was accurate.", "Dictionary keys, string values and embedded binary data are omitted. Locations use ordinal dictionary/list positions in the supplied artifact; the full original SHA-256 is required to interpret them."]}


def analyze_file(path: Path, *, kind: str, consent: bool, table: str | None = None, include_values: bool = False) -> dict[str, Any]:
    if not consent:
        raise ForensicError("explicit --consent is required")
    if kind not in ("pcap", "sqlite", "plist") or (kind != "sqlite" and (table is not None or include_values)):
        raise ForensicError("unsupported kind or options for that kind")
    if ".." in path.parts or not path.name or len(path.name) > 240 or any(ord(char) < 32 for char in str(path)):
        raise ForensicError("unsupported file path")
    if os.name == "nt" and (str(path).startswith(("\\\\", "//")) or any(char == ":" and index != 1 for index, char in enumerate(str(path)))):
        raise ForensicError("network, device and alternate-stream paths are not accepted")
    path = path.absolute()
    try:
        for parent in [*reversed(path.parents), path]:
            _metadata(parent)
        descriptor = _open_read_only(path)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or getattr(before, "st_file_attributes", 0) & 0x400 or not 0 < before.st_size <= MAX_BYTES:
                raise ForensicError("only regular nonempty files up to 16 MiB are accepted")
            data = stream.read(MAX_BYTES + 1)
            if len(data) != before.st_size or len(data) > MAX_BYTES:
                raise ForensicError("input changed or exceeded the size limit")
            initial_hash = digest(data)
            if kind == "pcap":
                result = analyze_pcap(data)
            elif kind == "sqlite":
                result = analyze_sqlite(data, table, include_values)
            else:
                result = analyze_plist(data)
            stream.seek(0)
            final = stream.read(MAX_BYTES + 1)
            after = os.fstat(stream.fileno())
            current = _metadata(path)
            if digest(final) != initial_hash or (before.st_size, before.st_mtime_ns, before.st_ino, before.st_dev) != (after.st_size, after.st_mtime_ns, after.st_ino, after.st_dev) or (current.st_ino, current.st_dev) != (before.st_ino, before.st_dev):
                raise ForensicError("input changed during analysis")
        report = {"schemaVersion": "1.0", "engine": "Sentinel Offline Forensics", "engineVersion": "1.0.0", "kind": kind, "input": {"name": path.name, "sha256": initial_hash, "bytes": len(data), "unchanged": True}, **result}
        if len(compact(report)) > MAX_OUTPUT:
            raise ForensicError("report exceeds 4 MiB; choose a smaller artifact or omit values")
        return report
    except ForensicError:
        raise
    except (OSError, ValueError, TypeError, OverflowError, RecursionError, struct.error, xml.parsers.expat.ExpatError, plistlib.InvalidFileException, sqlite3.Error):
        raise ForensicError("artifact unavailable, malformed or outside supported limits") from None


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline explicit-file forensic metadata; no acquisition, network or execution.")
    parser.add_argument("--consent", action="store_true")
    parser.add_argument("--file", required=True, type=Path)
    parser.add_argument("--kind", required=True, choices=("pcap", "sqlite", "plist"))
    parser.add_argument("--table")
    parser.add_argument("--include-values", action="store_true", help="Local SQLite opt-in; text prefixes and scalar values may contain sensitive data")
    args = parser.parse_args()
    try:
        report = analyze_file(args.file, kind=args.kind, consent=args.consent, table=args.table, include_values=args.include_values)
        sys.stdout.buffer.write(compact(report) + b"\n")
        return 0
    except ForensicError as error:
        print(f"forensics-worker: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
