# SDK Examples

Common patterns and use cases for CryptoServe SDKs.

## Basic Encryption

### Encrypt and Decrypt a String

=== "Python"

    ```python
    from cryptoserve import crypto

    # Encrypt
    secret = "My secret message"
    encrypted = crypto.encrypt_string(secret, context="user-pii")

    # Decrypt
    decrypted = crypto.decrypt_string(encrypted)
    assert decrypted == secret
    ```

=== "TypeScript"

    ```typescript
    import { crypto } from '@cryptoserve/sdk';

    // Encrypt
    const secret = "My secret message";
    const encrypted = await crypto.encrypt(secret, { context: "user-pii" });

    // Decrypt
    const decrypted = await crypto.decrypt(encrypted);
    console.assert(decrypted === secret);
    ```

### Encrypt Binary Data

=== "Python"

    ```python
    from cryptoserve import crypto

    # Read a file
    with open("document.pdf", "rb") as f:
        data = f.read()

    # Encrypt
    encrypted = crypto.encrypt(data, context="documents")

    # Save encrypted file
    with open("document.pdf.enc", "wb") as f:
        f.write(encrypted)

    # Later, decrypt
    with open("document.pdf.enc", "rb") as f:
        encrypted = f.read()

    decrypted = crypto.decrypt(encrypted)
    ```

=== "TypeScript"

    ```typescript
    import { crypto } from '@cryptoserve/sdk';
    import { readFile, writeFile } from 'fs/promises';

    // Read a file
    const data = await readFile('document.pdf');

    // Encrypt
    const encrypted = await crypto.encrypt(data, { context: 'documents' });

    // Save encrypted file
    await writeFile('document.pdf.enc', encrypted);
    ```

---

## JSON Encryption

### Encrypt User Data

=== "Python"

    ```python
    from cryptoserve import crypto

    user = {
        "name": "John Doe",
        "ssn": "123-45-6789",
        "email": "john@example.com",
        "address": {
            "street": "123 Main St",
            "city": "New York"
        }
    }

    # Encrypt entire object
    encrypted = crypto.encrypt_json(user, context="user-pii")

    # Decrypt
    decrypted_user = crypto.decrypt_json(encrypted)
    print(decrypted_user["name"])  # "John Doe"
    ```

=== "TypeScript"

    ```typescript
    import { crypto } from '@cryptoserve/sdk';

    interface User {
      name: string;
      ssn: string;
      email: string;
    }

    const user: User = {
      name: "John Doe",
      ssn: "123-45-6789",
      email: "john@example.com"
    };

    // Encrypt
    const encrypted = await crypto.encryptObject(user, { context: "user-pii" });

    // Decrypt with type safety
    const decrypted = await crypto.decryptObject<User>(encrypted);
    console.log(decrypted.name); // TypeScript knows this is string
    ```

---

## Associated Data (AAD)

Use associated data to bind ciphertext to a specific context:

=== "Python"

    ```python
    from cryptoserve import crypto

    user_id = "user_12345"
    secret_data = "sensitive information"

    # Encrypt with AAD
    encrypted = crypto.encrypt_string(
        secret_data,
        context="user-pii",
        associated_data=f"user:{user_id}".encode()
    )

    # Decrypt - AAD must match
    decrypted = crypto.decrypt_string(
        encrypted,
        associated_data=f"user:{user_id}".encode()
    )

    # Wrong AAD fails
    try:
        crypto.decrypt_string(
            encrypted,
            associated_data=b"user:wrong_id"
        )
    except DecryptionError:
        print("AAD mismatch - decryption failed")
    ```

=== "TypeScript"

    ```typescript
    import { crypto } from '@cryptoserve/sdk';

    const userId = "user_12345";
    const secretData = "sensitive information";

    // Encrypt with AAD
    const encrypted = await crypto.encrypt(secretData, {
      context: "user-pii",
      associatedData: `user:${userId}`
    });

    // Decrypt - AAD must match
    const decrypted = await crypto.decrypt(encrypted, {
      associatedData: `user:${userId}`
    });
    ```

---

## Database Integration

### SQLAlchemy Model

```python
from sqlalchemy import Column, String, create_engine
from sqlalchemy.orm import declarative_base, Session
from sqlalchemy.ext.hybrid import hybrid_property
from cryptoserve import crypto

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'

    id = Column(String, primary_key=True)
    email = Column(String, unique=True)
    _ssn = Column("ssn_encrypted", String)
    _credit_card = Column("credit_card_encrypted", String)

    @hybrid_property
    def ssn(self):
        if self._ssn:
            return crypto.decrypt_string(self._ssn)
        return None

    @ssn.setter
    def ssn(self, value):
        if value:
            self._ssn = crypto.encrypt_string(value, context="user-pii")
        else:
            self._ssn = None

    @hybrid_property
    def credit_card(self):
        if self._credit_card:
            return crypto.decrypt_string(self._credit_card)
        return None

    @credit_card.setter
    def credit_card(self, value):
        if value:
            self._credit_card = crypto.encrypt_string(
                value, context="payment-data"
            )
        else:
            self._credit_card = None


# Usage
user = User(
    id="user_123",
    email="john@example.com",
    ssn="123-45-6789",  # Automatically encrypted
    credit_card="4111111111111111"  # Automatically encrypted
)
session.add(user)
session.commit()

# Reading decrypts automatically
print(user.ssn)  # "123-45-6789"
```

### Django Model

```python
from django.db import models
from cryptoserve import crypto


class EncryptedCharField(models.TextField):
    """Custom field that encrypts/decrypts automatically."""

    def __init__(self, context, *args, **kwargs):
        self.context = context
        super().__init__(*args, **kwargs)

    def from_db_value(self, value, expression, connection):
        if value is None:
            return None
        return crypto.decrypt_string(value)

    def get_prep_value(self, value):
        if value is None:
            return None
        return crypto.encrypt_string(value, context=self.context)


class Patient(models.Model):
    name = models.CharField(max_length=100)
    ssn = EncryptedCharField(context="user-pii")
    diagnosis = EncryptedCharField(context="health-data")

    class Meta:
        db_table = 'patients'


# Usage
patient = Patient.objects.create(
    name="John Doe",
    ssn="123-45-6789",  # Encrypted before storage
    diagnosis="Confidential medical information"
)

# Reading decrypts automatically
patient = Patient.objects.get(id=1)
print(patient.ssn)  # "123-45-6789"
```

---

## API Integration

### FastAPI Service

```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptoserve import crypto
from cryptoserve.exceptions import CryptoServeError

app = FastAPI()


class CreateUserRequest(BaseModel):
    email: str
    ssn: str


class UserResponse(BaseModel):
    id: str
    email: str
    ssn_encrypted: str


@app.post("/users", response_model=UserResponse)
async def create_user(request: CreateUserRequest):
    try:
        encrypted_ssn = crypto.encrypt_string(
            request.ssn,
            context="user-pii"
        )
        return UserResponse(
            id="user_123",
            email=request.email,
            ssn_encrypted=encrypted_ssn
        )
    except CryptoServeError as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/users/{user_id}/ssn")
async def get_user_ssn(user_id: str, encrypted_ssn: str):
    try:
        ssn = crypto.decrypt_string(encrypted_ssn)
        return {"ssn": ssn}
    except CryptoServeError as e:
        raise HTTPException(status_code=400, detail=str(e))
```

### Express.js Service

```typescript
import express from 'express';
import { crypto } from '@cryptoserve/sdk';
import { CryptoServeError } from '@cryptoserve/sdk/errors';

const app = express();
app.use(express.json());

app.post('/users', async (req, res) => {
  try {
    const { email, ssn } = req.body;
    const encryptedSsn = await crypto.encrypt(ssn, { context: 'user-pii' });

    res.json({
      id: 'user_123',
      email,
      ssn_encrypted: encryptedSsn
    });
  } catch (error) {
    if (error instanceof CryptoServeError) {
      res.status(500).json({ error: error.message });
    }
    throw error;
  }
});

app.listen(3000);
```

---

## Batch Processing

### Process Multiple Records

```python
from cryptoserve import crypto

# Prepare batch
records = [
    {"id": "1", "ssn": "111-11-1111"},
    {"id": "2", "ssn": "222-22-2222"},
    {"id": "3", "ssn": "333-33-3333"},
]

# Batch encrypt
encrypt_items = [
    {"data": r["ssn"].encode(), "context": "user-pii"}
    for r in records
]
results = crypto.batch_encrypt(encrypt_items)

# Pair results with records
for record, result in zip(records, results):
    if result.success:
        record["ssn_encrypted"] = result.ciphertext.decode()
    else:
        print(f"Failed to encrypt {record['id']}: {result.error}")

# Batch decrypt
decrypt_items = [
    {"ciphertext": r["ssn_encrypted"].encode()}
    for r in records
]
decrypted = crypto.batch_decrypt(decrypt_items)
```

---

## Error Handling

### Comprehensive Error Handling

```python
from cryptoserve import crypto
from cryptoserve.exceptions import (
    CryptoServeError,
    DecryptionError,
    AuthorizationError,
    ContextNotFoundError,
    PolicyViolationError,
    NetworkError,
    TokenExpiredError
)


def safe_encrypt(data: str, context: str) -> str | None:
    """Encrypt with comprehensive error handling."""
    try:
        return crypto.encrypt_string(data, context=context)

    except AuthorizationError as e:
        # Identity not authorized for this context
        logger.error(f"Authorization failed: {e}")
        raise PermissionError(f"Not authorized for context: {context}")

    except ContextNotFoundError as e:
        # Context doesn't exist
        logger.error(f"Context not found: {e}")
        raise ValueError(f"Invalid context: {context}")

    except PolicyViolationError as e:
        # Blocked by policy
        logger.warning(f"Policy violation: {e.violations}")
        raise SecurityError(f"Operation blocked by policy")

    except NetworkError as e:
        # Connection issues
        logger.error(f"Network error: {e}")
        # Could retry here
        raise ConnectionError("CryptoServe unavailable")

    except CryptoServeError as e:
        # Catch-all for other errors
        logger.error(f"Encryption failed: {e}")
        raise


def safe_decrypt(ciphertext: str) -> str | None:
    """Decrypt with comprehensive error handling."""
    try:
        return crypto.decrypt_string(ciphertext)

    except DecryptionError as e:
        # Decryption failed (bad ciphertext, wrong key, etc.)
        logger.error(f"Decryption failed: {e}")
        return None

    except TokenExpiredError:
        # Token needs refresh (SDK handles this, but just in case)
        logger.warning("Token expired, retrying...")
        return crypto.decrypt_string(ciphertext)

    except CryptoServeError as e:
        logger.error(f"Decryption error: {e}")
        raise
```

---

## Testing

### Mock Mode for Tests

```python
import pytest
from cryptoserve import crypto
from cryptoserve.testing import enable_mock_mode, disable_mock_mode


@pytest.fixture(autouse=True)
def setup_mock():
    """Enable mock mode for all tests."""
    enable_mock_mode()
    yield
    disable_mock_mode()


def test_encrypt_decrypt():
    """Test basic encryption/decryption."""
    original = "test data"
    encrypted = crypto.encrypt_string(original, context="test")
    decrypted = crypto.decrypt_string(encrypted)
    assert decrypted == original


def test_json_encryption():
    """Test JSON encryption."""
    data = {"key": "value", "number": 42}
    encrypted = crypto.encrypt_json(data, context="test")
    decrypted = crypto.decrypt_json(encrypted)
    assert decrypted == data


def test_binary_encryption():
    """Test binary encryption."""
    data = b"\x00\x01\x02\x03"
    encrypted = crypto.encrypt(data, context="test")
    decrypted = crypto.decrypt(encrypted)
    assert decrypted == data
```
