# Recorded Linux run

Captured on 2026-10-24 by `python3 benchmark.py` in the development environment. Regenerate locally before comparing results; timings vary by host.

| Environment | Measured value |
|---|---|
| OS/kernel | Ubuntu 24.04.3 LTS; Linux 6.18.55 x86_64; glibc 2.39 |
| Python | 3.12.14 |
| C compiler | Ubuntu GCC 13.3.0 |
| Automated checks | 9 passed in 0.242 s |
| Locally generated targets | 1 ELF executable, 1 ELF shared object, 1 ZIP archive |

Each target was inspected three times in a fresh CLI process. Median end-to-end wall time (minimum–maximum):

| Target | Median | Min | Max |
|---|---:|---:|---:|
| ELF executable | 0.0522 s | 0.0478 s | 0.0538 s |
| ELF shared object | 0.0545 s | 0.0494 s | 0.0548 s |
| ZIP archive | 0.0494 s | 0.0451 s | 0.0511 s |

Timings include interpreter startup, file hashing, available metadata commands, and JSON serialization. This is a local smoke benchmark, not a comparison against another product, and it measures no AI model or provider costs.
