# What this changes

<!-- What the change does and why. Link the issue it closes. -->

## Validation

<!-- Which of these you ran, and anything that failed. -->

- [ ] `make test`
- [ ] `make lint`
- [ ] `make fuzz`, for a parsing or protection change
- [ ] `make test-integration`, for a protocol change
- [ ] Exercised against a real CMP peer, for a protocol change

<!-- Name the peer and its version, without hostnames or credentials. -->

## Documentation and release notes

- [ ] User-facing behavior is documented in the package documentation and the README
- [ ] `RELEASE_NOTES.md` carries an entry, or the change is not user facing
- [ ] A protocol change cites the RFC section and has a negative test

## Anything a reviewer should know

<!-- Trade-offs, follow-up work, or parts you are unsure about. -->

<!-- Never include shared secrets, private keys, full CSRs, CMP messages captured from a production
     system or production endpoint details in a pull request. -->
