# Getting Started with CryptoServe

This guide walks you through setting up CryptoServe and using the SDK.

## Prerequisites

- Docker and Docker Compose
- GitHub account (for authentication)

## Step 1: Configure GitHub OAuth

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Fill in:
   - Application name: `CryptoServe Local`
   - Homepage URL: `http://localhost:3000`
   - Authorization callback URL: `http://localhost:8000/auth/github/callback`
4. Click "Register application"
5. Copy the Client ID
6. Generate a Client Secret and copy it

## Step 2: Configure Environment

```bash
# Clone the repository
git clone https://github.com/yourusername/cryptoserve.git
cd cryptoserve

# Create environment file
cp .env.example .env
```

Edit `.env` with your GitHub credentials:

```bash
GITHUB_CLIENT_ID=your_client_id_here
GITHUB_CLIENT_SECRET=your_client_secret_here
```

## Step 3: Start Services

```bash
docker compose up -d
```

This starts:
- PostgreSQL database
- Backend API (port 8000)
- Frontend dashboard (port 3000)

Wait a minute for services to initialize, then open http://localhost:3000

## Step 4: Create Your First Identity

1. Click "Sign in with GitHub"
2. Authorize the application
3. You'll be redirected to the dashboard
4. Click "New Identity"
5. Fill in:
   - Name: `My First SDK`
   - Team: `engineering`
   - Environment: `development`
   - Select contexts: `user-pii`, `general`
6. Click "Create Identity"
7. Copy the install command

## Step 5: Install the SDK

```bash
pip install http://localhost:8000/sdk/download/YOUR_TOKEN/python
```

## Step 6: Use the SDK

```python
from cryptoserve import crypto

# Encrypt data
ciphertext = crypto.encrypt(b"Hello, World!", context="user-pii")
print(f"Encrypted: {ciphertext.hex()}")

# Decrypt data
plaintext = crypto.decrypt(ciphertext, context="user-pii")
print(f"Decrypted: {plaintext.decode()}")

# String helpers (for storing in databases)
encrypted = crypto.encrypt_string("secret", context="user-pii")
print(f"Encrypted (base64): {encrypted}")

decrypted = crypto.decrypt_string(encrypted, context="user-pii")
print(f"Decrypted: {decrypted}")
```

## Step 7: View Audit Logs

Go to http://localhost:3000/audit to see your operations logged.

## Next Steps

- [API Reference](./api-reference.md)
- [Context Configuration](./contexts.md)
- [Production Deployment](./deployment.md)

## Troubleshooting

### "Invalid or expired identity token"

Your token may have expired. Create a new identity from the dashboard.

### "Not authorized for context"

The identity doesn't have access to that context. Edit your identity to add the context.

### Database connection errors

Make sure PostgreSQL is running:

```bash
docker compose ps
```

If it's not healthy, check logs:

```bash
docker compose logs postgres
```
