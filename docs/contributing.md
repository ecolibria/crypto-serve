# Contributing to CryptoServe

Thank you for your interest in contributing to CryptoServe! This guide will help you get started.

## Code of Conduct

We are committed to providing a welcoming and inclusive environment. Please read and follow our [Code of Conduct](https://github.com/ecolibria/crypto-serve/blob/main/CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting Bugs

1. **Check existing issues** to avoid duplicates
2. **Use the bug report template** when creating an issue
3. **Include reproduction steps** with minimal code examples
4. **Provide environment details** (OS, Python version, etc.)

### Suggesting Features

1. **Check the roadmap** to see if it's already planned
2. **Open a discussion** before creating a PR for large changes
3. **Describe the use case** and why it's valuable

### Security Vulnerabilities

**Do not open public issues for security vulnerabilities.**

Please email security@cryptoserve.dev with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact

We will respond within 48 hours.

---

## Development Setup

### Prerequisites

- Python 3.11+
- Docker and Docker Compose
- Node.js 18+ (for frontend/docs)
- Git

### Clone and Setup

```bash
# Clone the repository
git clone https://github.com/ecolibria/crypto-serve.git
cd crypto-serve

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install dependencies
cd backend
pip install -e ".[dev]"

# Run tests to verify setup
pytest
```

### Running Locally

```bash
# Start all services
docker compose up -d

# Or run backend directly
cd backend
uvicorn app.main:app --reload --port 8000
```

### Running Tests

```bash
# All tests
pytest

# With coverage
pytest --cov=app --cov-report=html

# Specific test file
pytest tests/test_crypto.py

# Run only fast tests
pytest -m "not slow"
```

---

## Code Style

### Python

We use **Ruff** for linting and formatting:

```bash
# Format code
ruff format .

# Lint code
ruff check .

# Fix auto-fixable issues
ruff check --fix .
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add ML-KEM post-quantum support
fix: resolve key rotation race condition
docs: update encryption guide
test: add policy engine edge cases
refactor: simplify context resolution
chore: update dependencies
```

### Type Hints

All code must have type hints:

```python
# Good
def encrypt(data: bytes, context: str) -> EncryptionResult:
    ...

# Bad
def encrypt(data, context):
    ...
```

---

## Pull Request Process

### Before Submitting

1. **Run the full test suite** and ensure all tests pass
2. **Add tests** for new functionality
3. **Update documentation** if needed
4. **Run linting** and fix any issues

### PR Checklist

- [ ] Tests pass locally
- [ ] Code follows style guidelines
- [ ] Documentation updated (if applicable)
- [ ] Commit messages follow conventions
- [ ] No sensitive data in commits

### Review Process

1. **Automated checks** run on all PRs
2. **One approval** required from maintainers
3. **Address feedback** promptly
4. **Squash and merge** after approval

---

## Project Structure

```
crypto-serve/
├── backend/
│   ├── app/
│   │   ├── api/          # API endpoints
│   │   ├── core/         # Core business logic
│   │   ├── crypto/       # Cryptographic operations
│   │   ├── models/       # Database models
│   │   └── services/     # Business services
│   ├── tests/            # Test suite
│   └── alembic/          # Database migrations
├── frontend/             # React dashboard
├── sdk/
│   ├── python/           # Python SDK
│   └── typescript/       # TypeScript SDK
├── docs/                 # Documentation (MkDocs)
└── deploy/               # Deployment configurations
```

---

## Testing Guidelines

### Test Categories

| Type | Location | Purpose |
|------|----------|---------|
| Unit | `tests/unit/` | Test individual functions |
| Integration | `tests/integration/` | Test component interactions |
| E2E | `tests/e2e/` | Test full workflows |

### Writing Tests

```python
import pytest
from app.crypto import encrypt, decrypt

class TestEncryption:
    """Tests for encryption operations."""

    def test_encrypt_decrypt_roundtrip(self):
        """Data should decrypt to original plaintext."""
        plaintext = b"sensitive data"
        ciphertext = encrypt(plaintext, context="test")
        result = decrypt(ciphertext)
        assert result == plaintext

    def test_encrypt_with_aad(self):
        """AAD should be authenticated but not encrypted."""
        plaintext = b"data"
        aad = b"metadata"
        ciphertext = encrypt(plaintext, context="test", aad=aad)

        # Decryption with wrong AAD should fail
        with pytest.raises(DecryptionError):
            decrypt(ciphertext, aad=b"wrong")

    @pytest.mark.slow
    def test_bulk_encryption_performance(self):
        """Bulk encryption should complete within time limit."""
        # Performance test code
```

### Test Coverage

We aim for **80%+ coverage** on core modules:

- `app/crypto/` - 90%+
- `app/core/` - 85%+
- `app/api/` - 75%+

---

## Documentation

### Building Docs

```bash
# Install docs dependencies
pip install -e ".[docs]"

# Serve locally
mkdocs serve

# Build for production
mkdocs build
```

### Writing Docs

- Use clear, concise language
- Include code examples
- Add diagrams for complex concepts
- Keep API docs in sync with code

---

## Release Process

Releases are managed by maintainers:

1. **Version bump** in `pyproject.toml`
2. **Update CHANGELOG.md**
3. **Create release PR**
4. **Tag after merge** (`v1.2.3`)
5. **Automated publish** to PyPI

---

## Getting Help

- **Documentation**: [cryptoserve.dev](https://ecolibria.github.io/crypto-serve/)
- **Discussions**: [GitHub Discussions](https://github.com/ecolibria/crypto-serve/discussions)
- **Discord**: [Join our community](https://discord.gg/cryptoserve)

Thank you for contributing!
