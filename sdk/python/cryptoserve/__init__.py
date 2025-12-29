"""
CryptoServe SDK - Zero-config cryptographic operations.

Usage:
    from cryptoserve import crypto

    # Encrypt data
    ciphertext = crypto.encrypt(b"sensitive data", context="user-pii")

    # Decrypt data
    plaintext = crypto.decrypt(ciphertext, context="user-pii")

    # String helpers
    encrypted = crypto.encrypt_string("my secret", context="user-pii")
    decrypted = crypto.decrypt_string(encrypted, context="user-pii")
"""

from cryptoserve.client import CryptoClient
from cryptoserve._identity import IDENTITY

__version__ = "0.1.0"
__all__ = ["crypto", "CryptoClient"]

# Create singleton client
_client = None


def _get_client() -> CryptoClient:
    """Get or create the singleton client."""
    global _client
    if _client is None:
        _client = CryptoClient(
            server_url=IDENTITY["server_url"],
            token=IDENTITY["token"],
        )
    return _client


class crypto:
    """
    Main interface for CryptoServe.

    This class provides a simple, zero-config interface for cryptographic
    operations. The SDK comes pre-configured with your identity, so you
    can use it immediately after installation.

    Usage:
        from cryptoserve import crypto

        # Encrypt bytes
        ciphertext = crypto.encrypt(b"data", context="user-pii")

        # Decrypt bytes
        plaintext = crypto.decrypt(ciphertext, context="user-pii")

        # Encrypt string (returns base64)
        encrypted = crypto.encrypt_string("secret", context="user-pii")

        # Decrypt base64 string
        decrypted = crypto.decrypt_string(encrypted, context="user-pii")
    """

    @classmethod
    def encrypt(cls, plaintext: bytes | str, context: str) -> bytes:
        """
        Encrypt data.

        Args:
            plaintext: Data to encrypt (bytes or string)
            context: Crypto context (e.g., "user-pii", "payment-data")

        Returns:
            Encrypted ciphertext as bytes

        Raises:
            AuthenticationError: If identity token is invalid
            AuthorizationError: If not authorized for context
            ContextNotFoundError: If context doesn't exist
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        return _get_client().encrypt(plaintext, context)

    @classmethod
    def decrypt(cls, ciphertext: bytes, context: str) -> bytes:
        """
        Decrypt data.

        Args:
            ciphertext: Encrypted data from crypto.encrypt()
            context: Crypto context used for encryption

        Returns:
            Decrypted plaintext as bytes

        Raises:
            AuthenticationError: If identity token is invalid
            AuthorizationError: If not authorized for context
            CryptoServeError: If decryption fails
        """
        return _get_client().decrypt(ciphertext, context)

    @classmethod
    def encrypt_string(cls, plaintext: str, context: str) -> str:
        """
        Encrypt a string and return base64-encoded ciphertext.

        Convenient for storing encrypted data in databases or JSON.

        Args:
            plaintext: String to encrypt
            context: Crypto context

        Returns:
            Base64-encoded ciphertext
        """
        import base64
        ciphertext = cls.encrypt(plaintext.encode("utf-8"), context)
        return base64.b64encode(ciphertext).decode("ascii")

    @classmethod
    def decrypt_string(cls, ciphertext_b64: str, context: str) -> str:
        """
        Decrypt a base64-encoded ciphertext to string.

        Args:
            ciphertext_b64: Base64-encoded ciphertext from encrypt_string()
            context: Crypto context used for encryption

        Returns:
            Decrypted plaintext as string
        """
        import base64
        ciphertext = base64.b64decode(ciphertext_b64)
        plaintext = cls.decrypt(ciphertext, context)
        return plaintext.decode("utf-8")

    @classmethod
    def get_identity(cls) -> dict:
        """
        Get current identity information.

        Returns:
            Dict with identity_id, name, team, environment, allowed_contexts
        """
        return {
            "identity_id": IDENTITY["identity_id"],
            "name": IDENTITY["name"],
            "team": IDENTITY["team"],
            "environment": IDENTITY["environment"],
            "allowed_contexts": IDENTITY["allowed_contexts"],
        }
