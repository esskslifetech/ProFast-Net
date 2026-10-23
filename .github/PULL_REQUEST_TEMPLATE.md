## What changed

<!-- A short description of the change. -->

## Why

<!-- The problem it solves and any trade-off worth knowing about. -->
Closes #

## Type of change

- [ ] Bug fix
- [ ] Feature
- [ ] Documentation
- [ ] Build, CI or tooling
- [ ] Kernel tier (WFP / XDP / NetworkExtension)

## Affected layers

- [ ] Native core (C++)
- [ ] Go daemon (`profastd`)
- [ ] Python control plane (CLI / TUI / GUI / reference daemon)
- [ ] Docs

## Checklist

- [ ] The change is covered by a test, or the reason it cannot be is explained above
- [ ] `cd python && python -m pytest -q` and `ruff check python/src python/tests` pass
- [ ] `cd core && gofmt -l . && go vet ./... && go test ./...` pass
- [ ] `cmake --build build/native && ctest --test-dir build/native` passes (native changes)
- [ ] Mirage/SPA vectors updated together in C++, Go, Python and `docs/PROTOCOL.md`
- [ ] No secrets, endpoint files, cluster secrets or machine-specific paths are committed
- [ ] Documentation reflects the new behaviour
- [ ] I agree this contribution is licensed under MIT

## Notes for reviewers
