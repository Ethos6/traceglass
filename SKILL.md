---
name: traceglass
description: Inspect Linux binaries and software archives with reproducible local evidence. Use for ELF, APK/JAR/ZIP, SQLite, WebAssembly, and unknown files when asked to identify format, dependencies, symbols, strings, or embedded file metadata.
---

# Traceglass

Start with `python3 -m pip install .` and `traceglass TARGET --json`. The report records the SHA-256, file size, classification, evidence source, and warnings. Keep the report beside analysis notes so every factual claim can be tied to its source.

## Evidence rules

- Treat the input as untrusted. Traceglass reads metadata and bytes; it never runs a target and never extracts an archive.
- State **observed** for a report field, **inferred** for a conclusion derived from observed fields, and **unknown** if the inspected evidence does not establish it. Static inspection does not establish runtime behavior.
- Quote symbol names, dependency names, and strings exactly. Include offsets for strings and the input SHA-256 in notes.
- A missing dependency or symbol in a truncated report is unknown, not absent. Check warnings and truncation fields.
- If a tool is missing, report that limitation. Do not install tools or fetch target files unless requested.

## Follow-up commands

- ELF: use `readelf -lW FILE` for program segments, `readelf -SW FILE` for sections, and `objdump -d FILE` for disassembly. Save command output and cite the exact symbol or offset.
- ZIP/APK/JAR: inspect names and sizes only first; use a separate disposable directory for any later extraction, and treat extracted files as untrusted.
- Go executable: if Go is installed, `go version -m FILE` reports embedded build metadata. It is an optional follow-up and is not inferred from strings alone.
- Native behavior: static code is not proof of behavior. Run only in a disposable sandbox when explicitly authorized.

## Reproducibility

Run `python3 benchmark.py` on Linux. It compiles its own C fixtures and creates its own ZIP fixture, so it does not download proprietary apps or call an AI provider. Benchmark values are specific to the recorded machine and include process startup.
