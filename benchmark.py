#!/usr/bin/env python3
"""Build local Linux fixtures, run tests, and measure end-to-end inspections."""
from __future__ import annotations

import json
import os
import platform
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def timed(cmd: list[str], env: dict[str, str]) -> tuple[float, str]:
    start = time.perf_counter()
    output = subprocess.check_output(cmd, cwd=ROOT, env=env, text=True, stderr=subprocess.STDOUT)
    return time.perf_counter() - start, output


def main() -> None:
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    with tempfile.TemporaryDirectory(prefix="traceglass-bench-") as td:
        work = Path(td)
        source = work / "bench.c"
        exe = work / "probe"
        shared = work / "libprobe.so"
        archive = work / "probe.zip"
        source.write_text('#include <stdio.h>\nint answer(void){return 42;}\nint main(void){puts("traceglass-bench");return answer()==42?0:1;}\n')
        subprocess.run(["cc", "-O2", "-g", "-rdynamic", str(source), "-o", str(exe)], check=True)
        subprocess.run(["cc", "-shared", "-fPIC", "-x", "c", "-", "-o", str(shared)], input="int library_answer(void){return 43;}\n", text=True, check=True)
        subprocess.run(["python3", "-c", "import zipfile,sys;z=zipfile.ZipFile(sys.argv[1],'w');z.writestr('META-INF/MANIFEST.MF','Manifest-Version: 1.0');z.writestr('lib/x86_64/libprobe.so','fixture');z.close()", str(archive)], check=True)
        tests_time, tests_output = timed(["python3", "-m", "unittest", "-v", "test_traceglass"], env)
        runs: dict[str, list[float]] = {}
        for name, path in (("elf_executable", exe), ("elf_shared_object", shared), ("zip_archive", archive)):
            samples = []
            for _ in range(3):
                duration, output = timed(["python3", "traceglass.py", str(path), "--json"], env)
                report = json.loads(output)
                expected = "ZIP" if name == "zip_archive" else "ELF"
                if report["classification"] != expected or report["execution_performed"] is not False:
                    raise SystemExit(f"invalid report for {name}")
                samples.append(duration)
            runs[name] = samples
        print("Traceglass Linux benchmark")
        print(f"OS: {platform.platform()}")
        print(f"Python: {platform.python_version()}")
        print("Compiler: " + subprocess.check_output(["cc", "--version"], text=True).splitlines()[0])
        print("Artifacts built locally: 1 ELF executable, 1 ELF shared object, 1 ZIP archive")
        print(f"Test suite: 9 passed; {tests_time:.3f}s total")
        for name, samples in runs.items():
            print(f"{name}: n=3, median={statistics.median(samples):.4f}s, min={min(samples):.4f}s, max={max(samples):.4f}s")
        print("Measured wall time includes Python interpreter startup and JSON serialization; no model/provider costs are measured.")
        if "Ran 9 tests" not in tests_output:
            raise SystemExit("test runner output did not report the expected 9 tests")


if __name__ == "__main__":
    main()
