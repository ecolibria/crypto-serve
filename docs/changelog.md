# Changelog

All notable changes to CryptoServe are documented here.

This project follows [Semantic Versioning](https://semver.org/) and [Keep a Changelog](https://keepachangelog.com/).

---

## [Unreleased]

### Added
- Comprehensive MkDocs Material documentation site
- Context Discovery CLI tool
- Algorithm Policy engine
- Metrics dashboard
- Post-quantum cryptography (ML-KEM, ML-DSA) support
- Security whitepaper

### Changed
- Upgraded to Python 3.11+ requirement
- Improved key derivation with HKDF-SHA256

### Fixed
- SQLAlchemy context instance warning
- Datetime deprecation warnings

---

## [0.3.0] - 2024-01-15

### Added
- **Post-Quantum Cryptography**: ML-KEM-768 and ML-DSA-65 support
- **Hybrid Encryption**: Combined classical + PQC for defense in depth
- **Key Commitment**: Protection against invisible salamanders attack
- **FIPS Mode**: FIPS 140-2 compliant operation mode
- **Batch Operations**: Efficient bulk encrypt/decrypt APIs

### Changed
- Key hierarchy now supports PQC algorithms
- Context model extended to 5 layers
- Improved audit logging granularity

### Security
- Added key commitment scheme to prevent ciphertext malleability
- Implemented constant-time comparison for all sensitive operations

---

## [0.2.0] - 2023-10-01

### Added
- **Policy Engine**: Declarative cryptographic policies
- **KMS Integration**: AWS KMS and Google Cloud KMS support
- **Key Rotation**: Automatic and manual key rotation
- **Python SDK**: Full-featured Python client library
- **Identity Management**: Service identity authentication

### Changed
- Migrated from Flask to FastAPI
- Database schema refactored for multi-tenancy
- API versioning (v1 prefix)

### Fixed
- Memory leak in long-running encryption jobs
- Race condition in concurrent key access

---

## [0.1.0] - 2023-07-01

### Added
- Initial release
- **Core Encryption**: AES-256-GCM encryption/decryption
- **Context System**: Logical grouping for encryption keys
- **REST API**: Full CRUD operations
- **SQLite/PostgreSQL**: Database support
- **Docker**: Containerized deployment
- **Basic Authentication**: API key authentication

### Security
- All cryptographic operations use secure defaults
- No plaintext key storage

---

## Versioning Policy

- **Major (X.0.0)**: Breaking API changes
- **Minor (0.X.0)**: New features, backwards compatible
- **Patch (0.0.X)**: Bug fixes, security patches

## Deprecation Policy

- Deprecated features are marked in release notes
- Minimum 2 minor versions before removal
- Security fixes may bypass deprecation period

---

[Unreleased]: https://github.com/keytum/crypto-serve/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/keytum/crypto-serve/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/keytum/crypto-serve/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/keytum/crypto-serve/releases/tag/v0.1.0
