# Changelog

## 2026-08-11

### Documentation
- Added a standalone public README explaining the offline ownership-proof use
  case, supported key formats, command examples, and private-key handling.
- Added build instructions, cross-compilation examples, GitHub Actions binary
  artifact coverage, and a public security-reporting policy.
- Added the MIT License with the Sommelier copyright notice, which must be
  retained in redistributed copies or substantial portions of the software.

## 2026-07-02

### Tests
- Made LeaseSet key rejection coverage self-contained by generating non-sensitive invalid key material during the test run.

### Notes
- No private key material, local filesystem paths, private domains, or deployment details are documented here.
- Owner authentication messages should be signed exactly as shown by the addressbook server, including any nonce lines.
