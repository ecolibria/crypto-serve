# Changelog

All notable changes to CryptoServe will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-01-03

### Added

#### 5-Layer Context Model
- Data Identity layer: sensitivity classification (low/medium/high/critical), PII/PHI/PCI flags
- Regulatory layer: compliance framework support (HIPAA, GDPR, PCI-DSS, SOC2)
- Threat Model layer: quantum resistance requirements, protection lifetime
- Access Patterns layer: frequency-based optimization, latency requirements
- Technical layer: hardware acceleration, key size requirements
- Automatic algorithm selection based on all 5 layers

#### Policy Engine
- Customizable cryptographic policy rules
- Three severity levels: block, warn, info
- Default policies for common security requirements
- Policy evaluation API for testing before deployment
- Context-specific policy scoping
- CI/CD integration support via `/api/policies/check` endpoint

#### Admin Dashboard
- Overview with KPI cards (users, identities, operations, success rate)
- User management with search and pagination
- Global identity management with filtering
- Audit log viewer with export (CSV/JSON)
- Context management with key rotation
- Usage analytics with charts
- System health monitoring

#### Frontend Improvements
- Policies page with interactive policy evaluator
- Dashboard navigation with policies link
- Mobile-responsive layout improvements

#### Backend Features
- PostgreSQL-based context configuration storage
- Context-derived cryptographic requirements
- Algorithm recommendation engine
- Admin API endpoints with role-based access

### Security
- AES-256-GCM encryption by default
- HKDF-SHA256 key derivation
- JWT-based identity tokens
- Full audit logging
- Policy enforcement at runtime

### Infrastructure
- Docker Compose deployment
- GitHub OAuth integration
- CI/CD integration documentation

## [0.1.0] - 2024-12-01

### Added
- Initial release
- Basic encrypt/decrypt operations
- Context-based key management
- Identity management
- Personalized SDK generation
- GitHub OAuth authentication
- Audit logging
