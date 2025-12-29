"""CryptoServe API client."""

import base64
from typing import Optional

import requests


class CryptoServeError(Exception):
    """Base exception for CryptoServe errors."""
    pass


class AuthenticationError(CryptoServeError):
    """Authentication failed - invalid or expired token."""
    pass


class AuthorizationError(CryptoServeError):
    """Not authorized for this operation or context."""
    pass


class ContextNotFoundError(CryptoServeError):
    """The specified context does not exist."""
    pass


class ServerError(CryptoServeError):
    """Server encountered an error."""
    pass


class CryptoClient:
    """
    Client for CryptoServe API.

    This client handles communication with the CryptoServe server.
    In most cases, you should use the `crypto` class from the main
    module instead of this client directly.
    """

    def __init__(
        self,
        server_url: str,
        token: str,
        timeout: float = 30.0,
    ):
        """
        Initialize the client.

        Args:
            server_url: Base URL of the CryptoServe server
            token: Identity token (embedded in SDK)
            timeout: Request timeout in seconds
        """
        self.server_url = server_url.rstrip("/")
        self.token = token
        self.timeout = timeout

        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "cryptoserve-sdk/0.1.0",
        })

    def encrypt(self, plaintext: bytes, context: str) -> bytes:
        """
        Encrypt data.

        Args:
            plaintext: Data to encrypt
            context: Crypto context name

        Returns:
            Encrypted ciphertext

        Raises:
            AuthenticationError: If token is invalid
            AuthorizationError: If not authorized for context
            ContextNotFoundError: If context doesn't exist
            ServerError: If server returns an error
        """
        response = self.session.post(
            f"{self.server_url}/v1/crypto/encrypt",
            json={
                "plaintext": base64.b64encode(plaintext).decode("ascii"),
                "context": context,
            },
            timeout=self.timeout,
        )

        self._handle_response(response, context)

        data = response.json()
        return base64.b64decode(data["ciphertext"])

    def decrypt(self, ciphertext: bytes, context: str) -> bytes:
        """
        Decrypt data.

        Args:
            ciphertext: Encrypted data
            context: Crypto context name

        Returns:
            Decrypted plaintext

        Raises:
            AuthenticationError: If token is invalid
            AuthorizationError: If not authorized for context
            CryptoServeError: If decryption fails
            ServerError: If server returns an error
        """
        response = self.session.post(
            f"{self.server_url}/v1/crypto/decrypt",
            json={
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                "context": context,
            },
            timeout=self.timeout,
        )

        self._handle_response(response, context)

        data = response.json()
        return base64.b64decode(data["plaintext"])

    def _handle_response(self, response: requests.Response, context: str):
        """Handle API response and raise appropriate exceptions."""
        if response.status_code == 200:
            return

        try:
            detail = response.json().get("detail", "Unknown error")
        except Exception:
            detail = response.text or "Unknown error"

        if response.status_code == 401:
            raise AuthenticationError(
                f"Invalid or expired identity token: {detail}"
            )
        elif response.status_code == 403:
            raise AuthorizationError(
                f"Not authorized for context '{context}': {detail}"
            )
        elif response.status_code == 400:
            if "context" in detail.lower():
                raise ContextNotFoundError(detail)
            raise CryptoServeError(detail)
        else:
            raise ServerError(
                f"Server error ({response.status_code}): {detail}"
            )
