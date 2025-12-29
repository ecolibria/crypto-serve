# CryptoServe SDK

Zero-config cryptographic operations for Python.

## Installation

Download your personalized SDK from the CryptoServe dashboard:

```bash
pip install https://your-cryptoserve-server/sdk/download/YOUR_TOKEN/python
```

## Usage

```python
from cryptoserve import crypto

# Encrypt data
ciphertext = crypto.encrypt(b"sensitive data", context="user-pii")

# Decrypt data
plaintext = crypto.decrypt(ciphertext, context="user-pii")

# String helpers (returns base64)
encrypted = crypto.encrypt_string("my secret", context="user-pii")
decrypted = crypto.decrypt_string(encrypted, context="user-pii")
```

## Available Contexts

Contexts define the encryption policy. Common contexts:

- `user-pii` - Personal identifiable information (GDPR, CCPA)
- `payment-data` - Payment card data (PCI-DSS)
- `session-tokens` - Auth tokens and session data
- `health-data` - Medical records (HIPAA)
- `general` - General purpose encryption

Your SDK may have access to a subset of these based on your identity.

## Identity Info

```python
from cryptoserve import crypto

# Check your identity
info = crypto.get_identity()
print(info["allowed_contexts"])
```

## Error Handling

```python
from cryptoserve import crypto
from cryptoserve.client import (
    AuthenticationError,
    AuthorizationError,
    ContextNotFoundError,
)

try:
    ciphertext = crypto.encrypt(data, context="user-pii")
except AuthenticationError:
    # Token expired or invalid
    pass
except AuthorizationError:
    # Not allowed to use this context
    pass
except ContextNotFoundError:
    # Context doesn't exist
    pass
```

## License

Apache License 2.0
