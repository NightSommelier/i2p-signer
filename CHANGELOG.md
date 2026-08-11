# Changelog

## v0.1.0 - 2026-08-11

### Added
- First standalone public release with MIT licensing, security policy, and
  GitHub Actions builds for Linux, macOS, and Windows.
- Automated tagged-release publishing with five binaries and SHA-256 checksums.

## 2026-08-11

### Documentation
- Added a standalone public README explaining the offline ownership-proof use
  case, supported key formats, command examples, and private-key handling.
- Added build instructions, cross-compilation examples, GitHub Actions binary
  artifact coverage, and a public security-reporting policy.
- Added the MIT License with the Sommelier copyright notice, which must be
  retained in redistributed copies or substantial portions of the software.

### Changed
- Made key-format naming and public documentation independent of the former
  parent project.
- Ignored local binary and cross-compilation output directories.

## 2026-07-02

### Tests
- Made LeaseSet key rejection coverage self-contained by generating non-sensitive invalid key material during the test run.

### Notes
- No private key material, local filesystem paths, private domains, or deployment details are documented here.
- Ownership challenge messages should be signed exactly as shown by the service, including any nonce lines.
