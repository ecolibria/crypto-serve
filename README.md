<p align="center">
  <img src="docs/assets/logo.svg" alt="CryptoServe" width="120" height="120">
</p>

<h1 align="center">CryptoServe</h1>

<p align="center">
  <strong>Cryptography-as-a-Service with Zero Configuration SDKs</strong>
</p>

<p align="center">
  <a href="https://github.com/keytum/crypto-serve/actions"><img src="https://img.shields.io/github/actions/workflow/status/keytum/crypto-serve/ci.yml?branch=main&style=flat-square" alt="Build Status"></a>
  <a href="https://github.com/keytum/crypto-serve/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg?style=flat-square" alt="License"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/python-3.11+-blue.svg?style=flat-square" alt="Python 3.11+"></a>
  <a href="https://keytum.github.io/crypto-serve/"><img src="https://img.shields.io/badge/docs-latest-brightgreen.svg?style=flat-square" alt="Documentation"></a>
</p>

<p align="center">
  <a href="https://keytum.github.io/crypto-serve/">Documentation</a> |
  <a href="https://keytum.github.io/crypto-serve/getting-started/quickstart/">Quick Start</a> |
  <a href="https://keytum.github.io/crypto-serve/api-reference/">API Reference</a> |
  <a href="https://keytum.github.io/crypto-serve/security/whitepaper/">Security Whitepaper</a>
</p>

---

## What is CryptoServe?

CryptoServe is a **cryptography-as-a-service platform** that eliminates the complexity of implementing encryption correctly. Download a personalized SDK with your identity embedded, then encrypt and decrypt with a single line of code:

```python
from cryptoserve import crypto

# No configuration needed - identity is embedded in your SDK
ciphertext = crypto.encrypt("sensitive data", context="user-pii")
plaintext = crypto.decrypt(ciphertext)
```

### Why CryptoServe?

| Traditional Approach | CryptoServe |
|---------------------|-------------|
| Configure crypto libraries | Zero configuration |
| Manage encryption keys | Keys managed server-side |
| Implement key rotation | Automatic key rotation |
| Track algorithm compliance | Policy engine enforces standards |
| Build audit logging | Full audit trail included |
| Handle PQC migration | Post-quantum ready |

## Key Features

### Zero-Configuration SDKs
Download a personalized SDK with your identity embedded. No API keys to configure, no secrets to manage.

### 5-Layer Context Model
Intelligent algorithm selection based on:
- **Data Identity** - Sensitivity level and classification
- **Regulatory** - Compliance requirements (HIPAA, PCI-DSS, GDPR)
- **Threat Model** - Protection duration and attack vectors
- **Access Patterns** - Usage frequency and latency needs
- **Technical** - Hardware capabilities and constraints

### Post-Quantum Ready
First-class support for NIST-standardized post-quantum algorithms:
- **ML-KEM** (FIPS 203) - Quantum-safe key encapsulation
- **ML-DSA** (FIPS 204) - Quantum-safe digital signatures
- **Hybrid modes** - Classical + PQC for defense in depth

### Enterprise-Grade Security
- AES-256-GCM with key commitment
- HKDF key derivation with domain separation
- Ed25519 JWT authentication
- Complete audit logging
- FIPS 140-2/140-3 compliance modes

### Self-Service Dashboard
Web interface for:
- Identity management
- SDK downloads
- Context configuration
- Policy management
- Audit log viewing
- Usage analytics

## Quick Start

### 1. Start the Server

```bash
git clone https://github.com/keytum/crypto-serve.git
cd crypto-serve
cp .env.example .env
# Edit .env with your GitHub OAuth credentials
docker compose up -d
```

### 2. Create an Identity

1. Open http://localhost:3001
2. Sign in with GitHub
3. Create a new identity
4. Copy the SDK install command

### 3. Use the SDK

```bash
pip install http://localhost:8001/sdk/download/YOUR_TOKEN/python
```

```python
from cryptoserve import crypto

# Encrypt with context-aware algorithm selection
encrypted = crypto.encrypt_string("Hello, World!", context="user-pii")

# Decrypt (context extracted from ciphertext)
decrypted = crypto.decrypt_string(encrypted)
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Client Applications                          │
│                    (Python SDK / TypeScript SDK)                     │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                            API Gateway                               │
│                         (Authentication)                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐   │
│   │   Identity   │   │   Context    │   │      Policy          │   │
│   │   Service    │   │   Service    │   │      Engine          │   │
│   └──────────────┘   └──────────────┘   └──────────────────────┘   │
│                                                                      │
│   ┌──────────────────────────────────────────────────────────────┐  │
│   │                      Crypto Engine                            │  │
│   │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────────────┐  │  │
│   │  │ AES-GCM │  │ ChaCha20│  │ CBC+MAC │  │ Hybrid PQC      │  │  │
│   │  │         │  │ Poly1305│  │         │  │ (ML-KEM+AES)    │  │  │
│   │  └─────────┘  └─────────┘  └─────────┘  └─────────────────┘  │  │
│   └──────────────────────────────────────────────────────────────┘  │
│                                                                      │
│   ┌──────────────────────────────────────────────────────────────┐  │
│   │                     Key Management                            │  │
│   │           (HKDF Derivation / KMS Integration)                 │  │
│   └──────────────────────────────────────────────────────────────┘  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     PostgreSQL / SQLite                              │
│              (Identities, Contexts, Audit Logs)                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Documentation

| Section | Description |
|---------|-------------|
| [Getting Started](https://keytum.github.io/crypto-serve/getting-started/) | Installation and first steps |
| [Concepts](https://keytum.github.io/crypto-serve/concepts/) | Architecture, context model, key management |
| [Guides](https://keytum.github.io/crypto-serve/guides/) | How-to guides for common tasks |
| [API Reference](https://keytum.github.io/crypto-serve/api-reference/) | Complete API documentation |
| [SDK Reference](https://keytum.github.io/crypto-serve/sdk/) | Python and TypeScript SDK docs |
| [Security](https://keytum.github.io/crypto-serve/security/) | Security whitepaper and threat model |

## Supported Algorithms

### Symmetric Encryption

| Algorithm | Key Size | Use Case | FIPS |
|-----------|----------|----------|------|
| AES-256-GCM | 256-bit | Default, high security | Yes |
| AES-128-GCM | 128-bit | Performance-sensitive | Yes |
| ChaCha20-Poly1305 | 256-bit | No AES-NI hardware | No |
| AES-256-CBC + HMAC | 256-bit | Legacy compatibility | Yes |

### Post-Quantum

| Algorithm | Standard | Security Level |
|-----------|----------|----------------|
| ML-KEM-768 | FIPS 203 | Level 3 (192-bit) |
| ML-KEM-1024 | FIPS 203 | Level 5 (256-bit) |
| ML-DSA-65 | FIPS 204 | Level 3 (192-bit) |
| ML-DSA-87 | FIPS 204 | Level 5 (256-bit) |

### Hybrid Modes

| Mode | Components | Recommendation |
|------|------------|----------------|
| `AES-256-GCM+ML-KEM-768` | Classical + PQC | Recommended for long-term data |
| `AES-256-GCM+ML-KEM-1024` | Classical + PQC | Maximum security |

## Configuration

### Environment Variables

```bash
# Required
GITHUB_CLIENT_ID=your_client_id
GITHUB_CLIENT_SECRET=your_client_secret
CRYPTOSERVE_MASTER_KEY=your-secure-master-key
JWT_SECRET_KEY=your-jwt-secret

# Optional
FIPS_MODE=disabled|preferred|enabled
LOG_LEVEL=INFO
DATABASE_URL=sqlite:///./cryptoserve.db
```

### GitHub OAuth Setup

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Create a new OAuth App
3. Set Homepage URL: `http://localhost:3001`
4. Set Callback URL: `http://localhost:8001/auth/github/callback`
5. Copy credentials to `.env`

## Development

### Prerequisites

- Python 3.11+
- Node.js 18+
- Docker (optional)

### Local Development

```bash
# Backend
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8001

# Frontend (new terminal)
cd frontend
npm install
npm run dev

# SDK development
cd sdk/python
pip install -e ".[dev]"
pytest
```

### Running Tests

```bash
cd backend
pytest -v --cov=app --cov-report=term-missing
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Workflow

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## Security

For security vulnerabilities, please see our [Security Policy](SECURITY.md) or email security@cryptoserve.io.

For detailed security information, see our [Security Whitepaper](https://keytum.github.io/crypto-serve/security/whitepaper/).

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [cryptography](https://cryptography.io/) - Core cryptographic primitives
- [liboqs](https://openquantumsafe.org/) - Post-quantum algorithms
- [FastAPI](https://fastapi.tiangolo.com/) - API framework
- [Next.js](https://nextjs.org/) - Frontend framework

---

<p align="center">
  Made with care for developers who want encryption done right.
</p>
