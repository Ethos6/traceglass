from __future__ import annotations

import hashlib
import os
import re
import shutil
import sqlite3
import struct
import subprocess
import zipfile
from pathlib import Path
from typing import Any

__version__ = "0.1.0"

MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_STRINGS = 40
MAX_STRING_BYTES = 240
MAX_ARCHIVE_ENTRIES = 500
COMMAND_TIMEOUT = 8


class InspectionError(Exception):
    """An input could not be inspected safely or completely."""


def _run(argv: list[str], timeout: int = COMMAND_TIMEOUT) -> tuple[str | None, str | None]:
    """Run a fixed argv without a shell; return stdout or a concise warning."""
    try:
        proc = subprocess.run(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, errors="replace", timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return None, f"tool unavailable: {argv[0]}"
    except subprocess.TimeoutExpired:
        return None, f"timed out after {timeout}s: {argv[0]}"
    if proc.returncode:
        detail = (proc.stderr or proc.stdout).strip().splitlines()
        return None, f"{argv[0]} exited {proc.returncode}" + (f": {detail[0][:180]}" if detail else "")
    return proc.stdout, None


def _classify(head: bytes) -> str:
    if head.startswith(b"\x7fELF"):
        return "ELF"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06") or head.startswith(b"PK\x07\x08"):
        return "ZIP"
    if head.startswith(b"SQLite format 3\x00"):
        return "SQLite"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head[:4] in (b"\x00asm",):
        return "WebAssembly"
    return "unknown"


def _strings(path: Path) -> list[dict[str, Any]]:
    data = path.read_bytes()
    results: list[dict[str, Any]] = []
    for match in re.finditer(rb"[\x20-\x7e]{6,}", data):
        raw = match.group(0)
        results.append({"offset": match.start(), "text": raw[:MAX_STRING_BYTES].decode("ascii"),
                        "truncated": len(raw) > MAX_STRING_BYTES})
        if len(results) == MAX_STRINGS:
            break
    return results


def _elf(path: Path) -> tuple[dict[str, Any], list[str]]:
    warnings: list[str] = []
    header, warning = _run(["readelf", "-hW", str(path)])
    if warning:
        warnings.append(warning)
    dynamic, warning = _run(["readelf", "-dW", str(path)])
    if warning:
        warnings.append(warning)
    symbols, warning = _run(["nm", "-D", "--defined-only", str(path)])
    if warning:
        warnings.append(warning)
    fields: dict[str, Any] = {}
    if header:
        patterns = {
            "class": r"Class:\s+(.+)", "endianness": r"Data:\s+(.+)",
            "type": r"Type:\s+(.+)", "machine": r"Machine:\s+(.+)",
            "entry_point": r"Entry point address:\s+(.+)",
        }
        for key, pattern in patterns.items():
            match = re.search(pattern, header)
            if match:
                fields[key] = match.group(1).strip()
    needed = re.findall(r"\(NEEDED\).*?Shared library: \[(.*?)\]", dynamic or "")
    exports = []
    for line in (symbols or "").splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[-1] != "UND":
            exports.append(parts[-1])
            if len(exports) >= 80:
                break
    fields["needed_libraries"] = needed
    fields["defined_dynamic_symbols"] = exports
    return fields, warnings


def _zip(path: Path) -> tuple[dict[str, Any], list[str]]:
    try:
        with zipfile.ZipFile(path, "r") as archive:
            entries = archive.infolist()
            listed = [{"name": e.filename, "compressed_bytes": e.compress_size,
                       "uncompressed_bytes": e.file_size, "header_offset": e.header_offset}
                      for e in entries[:MAX_ARCHIVE_ENTRIES]]
            return {"entry_count": len(entries), "listing_truncated": len(entries) > MAX_ARCHIVE_ENTRIES,
                    "entries": listed}, []
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        return {}, [f"ZIP metadata could not be read: {type(exc).__name__}"]


def inspect_file(filename: str | os.PathLike[str]) -> dict[str, Any]:
    path = Path(filename).expanduser()
    try:
        stat = path.stat()
    except OSError as exc:
        raise InspectionError(f"cannot stat input: {exc.strerror or type(exc).__name__}") from exc
    if not path.is_file():
        raise InspectionError("input must be a regular file")
    if stat.st_size > MAX_FILE_BYTES:
        raise InspectionError(f"input exceeds the {MAX_FILE_BYTES}-byte safety limit")
    try:
        with path.open("rb") as stream:
            head = stream.read(64)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise InspectionError(f"cannot read input: {exc.strerror or type(exc).__name__}") from exc
    kind = _classify(head)
    result: dict[str, Any] = {
        "schema_version": 1,
        "input": {"name": path.name, "size_bytes": stat.st_size, "sha256": digest},
        "classification": kind,
        "analysis": {},
        "evidence": [],
        "warnings": [],
        "execution_performed": False,
    }
    analysis: dict[str, Any] = result["analysis"]
    if kind == "ELF":
        elf, warnings = _elf(path)
        analysis["elf"] = elf
        result["warnings"].extend(warnings)
        result["evidence"].append({"source": "readelf -hW", "fields": [k for k in elf if k not in ("needed_libraries", "defined_dynamic_symbols")]})
        if elf.get("needed_libraries"):
            result["evidence"].append({"source": "readelf -dW", "field": "needed_libraries"})
        if elf.get("defined_dynamic_symbols"):
            result["evidence"].append({"source": "nm -D --defined-only", "field": "defined_dynamic_symbols"})
        analysis["strings"] = _strings(path)
        result["evidence"].append({"source": "ASCII byte scan", "field": "strings", "offsets_are_file_byte_offsets": True})
    elif kind == "ZIP":
        data, warnings = _zip(path)
        analysis["zip"] = data
        result["warnings"].extend(warnings)
        result["evidence"].append({"source": "Python zipfile central directory", "field": "zip"})
    elif kind == "SQLite":
        try:
            uri = path.resolve().as_uri() + "?mode=ro"
            with sqlite3.connect(uri, uri=True, timeout=2) as db:
                tables = db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT 100").fetchall()
                analysis["sqlite"] = {"tables": [row[0] for row in tables]}
                result["evidence"].append({"source": "SQLite read-only schema query", "field": "sqlite.tables"})
        except sqlite3.Error as exc:
            result["warnings"].append(f"SQLite metadata could not be read: {type(exc).__name__}")
    elif kind == "WebAssembly":
        analysis["wasm"] = {"version_bytes": head[4:8].hex()}
        result["evidence"].append({"source": "WebAssembly magic and version header", "field": "wasm.version_bytes"})
    elif kind == "gzip":
        analysis["gzip"] = {"header_bytes": head[:10].hex()}
        result["evidence"].append({"source": "gzip header bytes", "field": "gzip.header_bytes"})
    else:
        analysis["preview"] = head[:32].hex()
        result["evidence"].append({"source": "first 32 bytes", "field": "preview"})
    return result


def main() -> None:
    import argparse
    import json
    import sys
    parser = argparse.ArgumentParser(prog="traceglass", description="Evidence-first static inspection for Linux binaries and archives.")
    parser.add_argument("--version", action="version", version=f"traceglass {__version__}")
    parser.add_argument("target", help="file to inspect; targets are never executed or extracted")
    parser.add_argument("--json", action="store_true", help="emit the machine-readable report (default)")
    args = parser.parse_args()
    try:
        report = inspect_file(args.target)
    except InspectionError as exc:
        print(f"traceglass: {exc}", file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
