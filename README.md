# Traceglass

**Evidence-first static inspection for Linux binaries and software archives.** Traceglass combines a small local CLI with a portable agent skill. It records what was observed, where the observation came from, and which claims remain unknown.

It reads target files and archive metadata. It does not execute binaries, extract archives, make network requests, or require an AI API key.

## Install

Requirements: Python 3.10+ and, for ELF metadata, GNU `readelf` and `nm` (usually provided by `binutils`).

```bash
python3 -m pip install .
traceglass ./path/to/file --json
```

From a checkout without installing:

```bash
python3 traceglass.py ./path/to/file --json
```

## Current coverage

| Input | What is inspected |
|---|---|
| ELF executable/shared object | Header class, byte order, type, architecture, entry point, dynamic dependencies, exported dynamic symbols, printable ASCII strings with file offsets |
| ZIP/JAR/APK | Central-directory names, compressed/uncompressed sizes, and header offsets; no extraction |
| SQLite | Table names through a read-only connection |
| WebAssembly | Magic and version header |
| gzip / unknown | Signature/header or a short byte preview |

Every report includes a SHA-256, input size, evidence source labels, warnings, and `execution_performed: false`. Reports use sorted JSON keys and omit absolute paths to make repeat runs comparable. The CLI caps inputs at 512 MiB, strings at 40 items, and archive listings at 500 entries.

## Example

```json
{
  "classification": "ELF",
  "execution_performed": false,
  "input": {"name": "tool", "sha256": "…", "size_bytes": 12345},
  "analysis": {
    "elf": {
      "class": "ELF64",
      "machine": "Advanced Micro Devices X86-64",
      "needed_libraries": ["libc.so.6"]
    }
  },
  "evidence": [{"source": "readelf -hW", "fields": ["class", "machine"]}]
}
```

## Reproducible Linux suite

The benchmark builds a native executable and shared library with the local C compiler, creates a ZIP fixture locally, runs nine automated checks, then times three complete CLI invocations per artifact. It requires Python 3, a C compiler, `readelf`, and `nm`; no target binaries or model services are downloaded.

```bash
python3 benchmark.py
```

The measured run from this Ubuntu host is recorded in [RESULTS.md](RESULTS.md).

Published figures must be regenerated on the machine being described. Runtime numbers include Python startup and JSON output, are not a comparison with another project, and should not be generalized to other hardware.

## Safe analysis notes

- A hash identifies the inspected bytes; it does not establish provenance or safety.
- Missing metadata can mean the file is stripped, unsupported, truncated, or the relevant tool is unavailable.
- Static strings and imports are clues, not proof of runtime behavior.
- Do not run unknown binaries on a normal workstation. Use an isolated disposable environment for authorized dynamic analysis.

## License

MIT. See [LICENSE](LICENSE).
