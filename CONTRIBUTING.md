# Contributing to go-pkicmp

This document outlines the essential workflows and guidelines for contributing to `go-pkicmp`.

Run linters:
```bash
make lint       # Run golangci-lint
make fmt-check  # Fail if any tracked Go file is not gofmt-formatted
make fix        # Run go fix
```

Unit tests are fast and have no external dependencies. They run under the race
detector, because the documented server deployment sweeps expired transactions
from a background goroutine while serving requests:
```bash
make test  # Run all unit tests
```

Every parser in `pkicmp` consumes bytes chosen by a peer, and message protection
is verified before anything establishes who that peer is. Fuzz targets cover
whole-message parsing, MAC protection parameters and signature verification:
```bash
make fuzz                # 30 seconds per target, as CI runs it
make fuzz FUZZTIME=10m   # a longer local hunt
```

CI runs `make fmt-check`, `make lint`, `make test` and `make fuzz` on every push
and pull request.

Integration tests verify compatibility against EJBCA, OpenSSL, and the Siemens CMP Test Suite.

> [!IMPORTANT]
> **Prerequisites**: Docker, OpenSSL 3.2+, Git, and `uv`.

To run the integration tests, follow this lifecycle:
```bash
make setup             # Spin up EJBCA docker container and clone cmp-test-suite
make test-integration  # Run the full integration test suite
make teardown          # Stop and clean up containers
```

For a full list of available targets, run `make help`.
