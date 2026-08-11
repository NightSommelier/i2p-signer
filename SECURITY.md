# Security Policy

## Supported Versions

Security fixes are made in the current default branch and the latest published
release. Users should update to the newest available binary before reporting a
problem already fixed upstream.

## Reporting a Vulnerability

Do not open a public GitHub issue for a suspected vulnerability.

Use GitHub's private vulnerability-reporting feature on the repository when it
is available. If it is not enabled, email [admin@matrix.co.ua](mailto:admin@matrix.co.ua)
and request a private channel.

Include a clear description, affected version or commit, reproducible steps,
and the security impact. Do not include real private keys, seed files,
destinations tied to private services, access tokens, or production URLs.
Use synthetic key material and placeholders in any proof of concept.

## Scope

Relevant reports include issues in key-file parsing, Ed25519 signing,
private-key handling, binary build or release integrity, and documentation that
could cause unsafe key disclosure. Reports about third-party I2P services or
keys not controlled by this project should be directed to their maintainers.
