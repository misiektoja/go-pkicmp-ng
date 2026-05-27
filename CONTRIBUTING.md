# Contributing to go-pkicmp

This document outlines the essential workflows and guidelines for contributing to `go-pkicmp`.

## Essential Workflows

Run linters:
```bash
make lint  # Run golangci-lint
make fix   # Run go fix
```

Unit tests are fast and have no external dependencies:
```bash
make test  # Run all unit tests
```

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
