from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

from traceglass import InspectionError, inspect_file


class TraceglassTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.elf = cls.root / "probe"
        cls.lib = cls.root / "libprobe.so"
        cls.c = cls.root / "probe.c"
        cls.c.write_text('#include <stdio.h>\nint exported_probe(void){return 7;}\nint main(void){puts("traceglass-fixture-marker");return 0;}\n')
        subprocess.run(["cc", "-O0", "-g", "-rdynamic", str(cls.c), "-o", str(cls.elf)], check=True)
        subprocess.run(["cc", "-shared", "-fPIC", "-O0", "-x", "c", "-", "-o", str(cls.lib)],
                       input="int exported_shared_probe(void){return 11;}\n", text=True, check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_elf_header_dependencies_symbols_strings(self):
        report = inspect_file(self.elf)
        self.assertEqual(report["classification"], "ELF")
        elf = report["analysis"]["elf"]
        self.assertTrue(elf["machine"])
        self.assertTrue(elf["needed_libraries"])
        self.assertIn("exported_probe", elf["defined_dynamic_symbols"])
        self.assertIn("traceglass-fixture-marker", [x["text"] for x in report["analysis"]["strings"]])
        self.assertFalse(report["execution_performed"])

    def test_shared_object_exports(self):
        report = inspect_file(self.lib)
        self.assertEqual(report["classification"], "ELF")
        self.assertIn("exported_shared_probe", report["analysis"]["elf"]["defined_dynamic_symbols"])

    def test_zip_listing_without_extraction(self):
        archive = self.root / "probe.apk"
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr("AndroidManifest.xml", b"manifest-fixture")
            z.writestr("lib/x86_64/libprobe.so", b"not-extracted")
        report = inspect_file(archive)
        self.assertEqual(report["classification"], "ZIP")
        self.assertEqual(report["analysis"]["zip"]["entry_count"], 2)
        self.assertTrue(all("name" in e for e in report["analysis"]["zip"]["entries"]))

    def test_sqlite_schema_read_only(self):
        db_path = self.root / "sample.db"
        with sqlite3.connect(db_path) as db:
            db.execute("CREATE TABLE sample (id INTEGER)")
        report = inspect_file(db_path)
        self.assertEqual(report["classification"], "SQLite")
        self.assertEqual(report["analysis"]["sqlite"]["tables"], ["sample"])

    def test_wasm_signature(self):
        wasm = self.root / "tiny.wasm"
        wasm.write_bytes(b"\0asm\x01\0\0\0")
        report = inspect_file(wasm)
        self.assertEqual(report["classification"], "WebAssembly")
        self.assertEqual(report["analysis"]["wasm"]["version_bytes"], "01000000")

    def test_gzip_signature(self):
        gz = self.root / "tiny.gz"
        gz.write_bytes(b"\x1f\x8b\x08\0\0\0\0\0\0\x03payload")
        self.assertEqual(inspect_file(gz)["classification"], "gzip")

    def test_unknown_input_gets_hash_and_preview(self):
        blob = self.root / "blob.bin"
        blob.write_bytes(b"opaque bytes")
        report = inspect_file(blob)
        self.assertEqual(report["classification"], "unknown")
        self.assertEqual(len(report["input"]["sha256"]), 64)
        self.assertEqual(report["analysis"]["preview"], blob.read_bytes().hex())

    def test_rejects_directory_and_missing_path(self):
        with self.assertRaises(InspectionError):
            inspect_file(self.root)
        with self.assertRaises(InspectionError):
            inspect_file(self.root / "missing")

    def test_cli_json_is_valid_and_repeatable(self):
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]))
        outputs = [subprocess.check_output(["python3", "traceglass.py", str(self.elf), "--json"], env=env, text=True) for _ in range(2)]
        first, second = map(json.loads, outputs)
        self.assertEqual(first["input"]["sha256"], second["input"]["sha256"])
        self.assertEqual(first["analysis"]["elf"], second["analysis"]["elf"])


if __name__ == "__main__":
    unittest.main()
