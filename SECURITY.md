# Security policy

## Supported versions

Only the latest release receives security fixes while the project is in alpha.

## Reporting a vulnerability

Please use GitHub private vulnerability reporting. Do not include real vault contents, credentials, access tokens, personal information, or proprietary paths in an issue.

## Scope and guarantees

The scanner is designed to avoid source writes, network requests, symlink traversal, and body persistence. A report still contains structural metadata such as paths, hashes, sizes, and link targets. Store reports with the same care as the source vault.

The tool does not provide malware scanning, cryptographic erasure, business-content validation, or a guarantee that an operating-system-level attacker cannot observe process memory.

