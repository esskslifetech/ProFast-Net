# Contributing to ProFast-Net

Thanks for taking the time to help. This project is deliberately small and
dependency-light: the Go daemon uses the standard library only, the C++ core has
no third-party dependencies, and the Python control plane needs `psutil` and
`rich` (plus `PySide6` for the GUI). Please keep it that way unless a change
genuinely needs more.

## Before you start

- Open an issue before a large feature or refactor, so the design can be agreed
  on before the code exists.
- Security problems never go in an issue. Follow [SECURITY.md](SECURITY.md).
- By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development loop

| Layer | Install / configure | Check |
| --- | --- | --- |
| Python | `python -m pip install -e "python[dev]"` | `cd python && python -m pytest -q` and `ruff check python/src python/tests` |
| Native | `cmake -S native -B build/native -G Ninja -DCMAKE_BUILD_TYPE=Release` then `cmake --build build/native` | `ctest --test-dir build/native --output-on-failure` |
| Go | Go 1.22+ | `cd core && gofmt -l . && go vet ./... && go test ./...` |
| Kernel tier | Needs a WDK, clang-bpf or an Apple entitlement — see the README next to each program | Reviewed, not built by CI |

Run the Python and Go suites at minimum for any change that touches both
engines. `pfbench selftest` prints the canonical vectors if you need to see what
the native core derives.

## The one rule that matters

Mirage locators and SPA tokens must stay byte-identical in C++, Go and Python.
If you change the derivation, the wire format or the epoch rules, update all of
the following in the same pull request:

- `native/tests/native_tests.cpp`
- `core/internal/mirage/mirage_test.go`
- `python/tests/test_mirage.py`
- `docs/PROTOCOL.md`

A change that breaks the vectors is a compatibility break for every peer in a
cluster, not just a failing test.

## Style

- **Python** — `ruff` rules `E,F,I,UP,B`, 100 columns, type hints where they
  clarify a boundary. Prefer an explicit error over a silent fallback; the code
  reports "skipped" rather than pretending a privileged step succeeded.
- **Go** — `gofmt` clean, stdlib only, errors wrapped with context. New daemon
  methods need a matching entry in `docs/PROTOCOL.md` and a test in `core`.
- **C++** — C++17, clean under `-Wall -Wextra` (or `/W4` on MSVC), no exceptions
  or allocations that cross the C ABI boundary. Cryptographic code needs
  known-answer tests, not just round-trip tests.
- **Docs** — behaviour changes need a README or `docs/` update. Keep the existing
  tone: state what the tool does, and state what it refuses to do.

Comments explain why, not what. Match the surrounding density; several modules
have no comments at all and that is intentional.

## Commits and pull requests

- One logical change per commit. Imperative subject line, roughly 72 characters.
- The body explains the reason and any trade-off; the diff already shows the
  change.
- Fill in the pull request template, including the checklist.
- Keep CI green. A red job is a request for a fix, not for a reviewer.

## License

ProFast-Net is MIT licensed. There is no CLA: by opening a pull request you
agree that your contribution is released under the same MIT terms. Only submit
code you have the right to license that way.
