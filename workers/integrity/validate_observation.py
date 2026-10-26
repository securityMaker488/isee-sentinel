"""Offline validation only. Never opens a path mentioned inside an observation."""
from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any

MAX_DOCUMENT_BYTES = 64 * 1024
MAX_OBSERVED_FILE_BYTES = 1024 * 1024
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class ObservationError(ValueError):
    """A bounded, content-free validation error suitable for CLI output."""


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ObservationError("duplicate JSON keys are not accepted")
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise ObservationError("non-finite JSON numbers are not accepted")


def _keys(value: Any, keys: set[str]) -> bool:
    return type(value) is dict and set(value) == keys


def _integer(value: Any, minimum: int, maximum: int) -> bool:
    return type(value) is int and minimum <= value <= maximum


def validate_observation(value: Any) -> dict[str, Any]:
    if not _keys(value, {"schemaVersion", "observationId", "assetId", "observedAtEpochMs", "source", "type", "synthetic", "host", "file"}):
        raise ObservationError("observation has unknown or missing fields")
    if type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1:
        raise ObservationError("unsupported observation schema version")
    if not isinstance(value["assetId"], str) or not UUID.fullmatch(value["assetId"]):
        raise ObservationError("asset ID is not a canonical UUID")
    if not isinstance(value["observationId"], str) or not SHA256.fullmatch(value["observationId"]):
        raise ObservationError("observation ID is not a SHA-256 identifier")
    if not _integer(value["observedAtEpochMs"], 0, 9007199254740991):
        raise ObservationError("timestamp must be Unix epoch milliseconds in the safe integer range")
    if value["source"] != "sentinel-agent" or value["type"] != "integrity.observation" or value["synthetic"] is not False:
        raise ObservationError("unexpected observation source, type or synthetic flag")
    host = value["host"]
    if not _keys(host, {"os", "architecture", "agentProcessId", "agentVersion"}):
        raise ObservationError("invalid host metadata fields")
    if host["os"] not in {"linux", "windows"}:
        raise ObservationError("only Linux and Windows adapters are defined")
    if not isinstance(host["architecture"], str) or not re.fullmatch(r"[a-z0-9_]{2,32}", host["architecture"]):
        raise ObservationError("invalid architecture")
    if not _integer(host["agentProcessId"], 1, 4294967295):
        raise ObservationError("invalid agent process ID")
    if not isinstance(host["agentVersion"], str) or not re.fullmatch(r"\d{1,5}\.\d{1,5}\.\d{1,5}", host["agentVersion"]):
        raise ObservationError("invalid agent version")
    file = value["file"]
    if not _keys(file, {"pathLabel", "pathId", "bytes", "sha256"}):
        raise ObservationError("invalid file observation fields")
    label = file["pathLabel"]
    if not isinstance(label, str) or not label or len(label.encode("utf-8")) > 240 or label in {".", ".."} or any(ord(ch) < 32 or ord(ch) == 127 or ch in "/\\:" for ch in label):
        raise ObservationError("file label must be a basename, never a path")
    if not _integer(file["bytes"], 0, MAX_OBSERVED_FILE_BYTES):
        raise ObservationError("observed file is outside the supported size limit")
    if not isinstance(file["sha256"], str) or not SHA256.fullmatch(file["sha256"]):
        raise ObservationError("invalid SHA-256 digest format")
    if not isinstance(file["pathId"], str) or not SHA256.fullmatch(file["pathId"]):
        raise ObservationError("invalid path identifier format")
    return value


def _open_no_follow(path: Path) -> int:
    if os.name != "nt":
        if not hasattr(os, "O_NOFOLLOW"):
            raise ObservationError("platform has no supported no-follow adapter")
        return os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    # Python's Windows os.open lacks O_NOFOLLOW. Open a reparse-point handle and inspect it before reading.
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
        raise ObservationError("observation file could not be opened read-only")
    try:
        return msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except Exception:
        close(handle)
        raise ObservationError("observation file handle is unavailable") from None


def load_observation(path: Path, *, consent: bool) -> dict[str, Any]:
    if not consent:
        raise ObservationError("explicit --consent is required")
    if ".." in path.parts or not str(path):
        raise ObservationError("parent traversal is not accepted")
    if os.name == "nt":
        text = str(path)
        if text.startswith(("\\\\", "//")) or any(ch == ":" and index != 1 for index, ch in enumerate(text)):
            raise ObservationError("network, device and alternate-stream paths are not accepted")
    try:
        for candidate in [*reversed(path.parents), path]:
            metadata = candidate.lstat()
            if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & 0x400:
                raise ObservationError("symbolic links and reparse points are not accepted")
        descriptor = _open_no_follow(path)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or getattr(before, "st_file_attributes", 0) & 0x400:
                raise ObservationError("only regular observation files are accepted")
            if before.st_size > MAX_DOCUMENT_BYTES:
                raise ObservationError("observation document exceeds 64 KiB")
            payload = stream.read(MAX_DOCUMENT_BYTES + 1)
            after = os.fstat(stream.fileno())
            if len(payload) > MAX_DOCUMENT_BYTES:
                raise ObservationError("observation document exceeds 64 KiB")
            if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns or len(payload) != after.st_size:
                raise ObservationError("observation document changed during read")
        parsed = json.loads(payload.decode("utf-8"), object_pairs_hook=_object, parse_constant=_reject_constant)
        return validate_observation(parsed)
    except ObservationError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError):
        raise ObservationError("observation document is unavailable or invalid JSON") from None


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate one offline AgentObservation v1 JSON document; no network or source-file access.")
    parser.add_argument("--consent", action="store_true")
    parser.add_argument("--file", type=Path, required=True)
    args = parser.parse_args()
    try:
        observation = load_observation(args.file, consent=args.consent)
    except ObservationError as error:
        print(f"integrity-worker: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"schemaVersion": 1, "valid": True, "assetId": observation["assetId"], "observationId": observation["observationId"],
                      "contentHashVerified": False, "sourceAuthenticated": False, "integration": "offline_only"}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
