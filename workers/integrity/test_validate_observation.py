import hashlib
import json
import os
from pathlib import Path
import tempfile
import subprocess
import unittest

from validate_observation import MAX_DOCUMENT_BYTES, ObservationError, load_observation, validate_observation


def observation():
    # Explicit fixture: no claim that these values are real telemetry.
    return {"schemaVersion": 1, "observationId": "a" * 64, "assetId": "00000000-0000-4000-8000-000000000001",
            "observedAtEpochMs": 1792764000000, "source": "sentinel-agent", "type": "integrity.observation", "synthetic": False,
            "host": {"os": "windows", "architecture": "x86_64", "agentProcessId": 1234, "agentVersion": "0.1.0"},
            "file": {"pathLabel": "not-opened.txt", "pathId": "c" * 64, "bytes": 3, "sha256": "b" * 64}}


class IntegrityValidationTests(unittest.TestCase):
    def test_schema_allows_windows_and_linux(self):
        for host_os in ["windows", "linux"]:
            value = observation()
            value["host"]["os"] = host_os
            self.assertIs(validate_observation(value), value)

    def test_rejects_unknown_fields_versions_and_boolean_integers(self):
        for update in [{"schemaVersion": 2}, {"schemaVersion": True}, {"observedAtEpochMs": True}, {"synthetic": 0}, {"token": "secret"}, {"assetId": "other"}, {"source": "untrusted-agent"}]:
            with self.subTest(update=update), self.assertRaises(ObservationError):
                validate_observation(observation() | update)

    def test_hash_and_basename_boundaries(self):
        for field, value in [("pathId", "x" * 64), ("pathId", "a" * 63), ("pathId", True), ("sha256", "z" * 64), ("sha256", "a" * 63), ("bytes", 1024 * 1024 + 1), ("bytes", True), ("pathLabel", "../secret"), ("pathLabel", "C:\\secret"), ("pathLabel", "file\x00name")]:
            candidate = observation()
            candidate["file"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ObservationError):
                validate_observation(candidate)

    def test_reads_one_document_without_opening_observed_source_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "observation.json"
            path.write_text(json.dumps(observation()), encoding="utf-8")
            original = path.read_bytes()
            self.assertEqual(load_observation(path, consent=True), observation())
            self.assertEqual(path.read_bytes(), original)
            self.assertFalse((Path(directory) / "not-opened.txt").exists())

    def test_consent_precedes_reading_and_traversal_is_rejected(self):
        with self.assertRaisesRegex(ObservationError, "consent"):
            load_observation(Path("missing"), consent=False)
        with self.assertRaisesRegex(ObservationError, "traversal"):
            load_observation(Path("folder/../file"), consent=True)

    def test_bounded_json_parser_rejects_duplicate_nan_multi_record_and_invalid_utf8(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "observation.json"
            for payload in [b'{"schemaVersion":1,"schemaVersion":1}', b'{"value":NaN}', b'{}\n{}', b'\xff', b'x' * (MAX_DOCUMENT_BYTES + 1)]:
                path.write_bytes(payload)
                with self.subTest(payload_size=len(payload)), self.assertRaises(ObservationError):
                    load_observation(path, consent=True)

    @unittest.skipIf(os.name == "nt", "Windows symlink creation requires developer mode or privileges; no elevation requested")
    def test_unix_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.write_text(json.dumps(observation()), encoding="utf-8")
            link = Path(directory) / "link"
            link.symlink_to(target)
            with self.assertRaisesRegex(ObservationError, "links"):
                load_observation(link, consent=True)

    @unittest.skipUnless(os.name == "nt", "Windows path adapter")
    def test_windows_network_device_stream_paths_are_rejected(self):
        for path in [r"\\server\share\file", r"\\?\C:\file", r"C:\file:secret"]:
            with self.subTest(path=path), self.assertRaises(ObservationError):
                load_observation(Path(path), consent=True)

    def test_real_rust_observation_is_accepted_without_content_disclosure(self):
        executable = Path(__file__).resolve().parents[2] / "packages" / "endpoint-agent" / "target" / "debug" / ("sentinel-agent.exe" if os.name == "nt" else "sentinel-agent")
        if not executable.is_file():
            self.skipTest("build the Rust agent with cargo test before cross-language validation")
        with tempfile.TemporaryDirectory() as directory:
            chosen = Path(directory) / "test-config.txt"
            content = b"authorized local test fixture\n"
            chosen.write_bytes(content)
            result = subprocess.run([str(executable), "--consent", "--asset-id", observation()["assetId"], "--file", str(chosen)], check=True, capture_output=True, timeout=10)
            self.assertNotIn(content.strip(), result.stdout)
            self.assertNotIn(directory.encode(), result.stdout)
            document = Path(directory) / "observation.ndjson"
            document.write_bytes(result.stdout)
            actual = load_observation(document, consent=True)
            self.assertEqual(actual["file"]["sha256"], hashlib.sha256(content).hexdigest())
            self.assertEqual(actual["file"]["bytes"], len(content))
            self.assertEqual(actual["file"]["pathLabel"], chosen.name)
            self.assertFalse(actual["synthetic"])


if __name__ == "__main__":
    unittest.main()
