"""SDK package generator."""

import os
import shutil
import tempfile
import hashlib
from pathlib import Path

from app.config import get_settings
from app.models import Identity
from app.core.identity_manager import identity_manager

settings = get_settings()

# Get the templates directory relative to this file
TEMPLATES_DIR = Path(__file__).parent / "templates"


class SDKGenerator:
    """Generates personalized SDK packages."""

    def __init__(self):
        self.templates_dir = TEMPLATES_DIR

    def generate_python_sdk(self, identity: Identity, token: str) -> Path:
        """
        Generate a personalized Python SDK package.

        Returns the path to the generated wheel file.
        """
        # Create temporary directory for building
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            sdk_dir = temp_path / "cryptoserve"
            sdk_dir.mkdir()

            # Copy template files
            self._copy_template_files(sdk_dir)

            # Generate identity module
            self._generate_identity_module(sdk_dir, identity, token)

            # Generate setup.py
            identity_hash = hashlib.sha256(identity.id.encode()).hexdigest()[:8]
            self._generate_setup_py(temp_path, identity_hash)

            # Build wheel
            wheel_path = self._build_wheel(temp_path)

            # Move to output directory
            output_dir = Path(__file__).parent / "output"
            output_dir.mkdir(exist_ok=True)

            final_path = output_dir / wheel_path.name
            shutil.copy2(wheel_path, final_path)

            return final_path

    def _copy_template_files(self, target_dir: Path):
        """Copy SDK template files to target directory."""
        template_src = self.templates_dir / "python" / "cryptoserve"

        if template_src.exists():
            # Copy from template
            for file in template_src.glob("*.py"):
                if file.name != "_identity.py":  # Skip identity template
                    shutil.copy2(file, target_dir / file.name)
        else:
            # Generate minimal SDK inline
            self._generate_minimal_sdk(target_dir)

    def _generate_minimal_sdk(self, target_dir: Path):
        """Generate minimal SDK files inline (when templates don't exist)."""
        # __init__.py
        init_content = '''"""CryptoServe SDK - Zero-config cryptographic operations."""

from cryptoserve.client import CryptoClient
from cryptoserve._identity import IDENTITY

__version__ = "0.1.0"

# Create singleton client
_client = None


def _get_client() -> CryptoClient:
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

    Usage:
        from cryptoserve import crypto

        ciphertext = crypto.encrypt(b"data", context="user-pii")
        plaintext = crypto.decrypt(ciphertext, context="user-pii")
    """

    @classmethod
    def encrypt(cls, plaintext: bytes | str, context: str) -> bytes:
        """Encrypt data."""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        return _get_client().encrypt(plaintext, context)

    @classmethod
    def decrypt(cls, ciphertext: bytes, context: str) -> bytes:
        """Decrypt data."""
        return _get_client().decrypt(ciphertext, context)

    @classmethod
    def encrypt_string(cls, plaintext: str, context: str) -> str:
        """Encrypt string and return base64."""
        import base64
        ciphertext = cls.encrypt(plaintext.encode("utf-8"), context)
        return base64.b64encode(ciphertext).decode("ascii")

    @classmethod
    def decrypt_string(cls, ciphertext_b64: str, context: str) -> str:
        """Decrypt base64 string."""
        import base64
        ciphertext = base64.b64decode(ciphertext_b64)
        plaintext = cls.decrypt(ciphertext, context)
        return plaintext.decode("utf-8")
'''
        (target_dir / "__init__.py").write_text(init_content)

        # client.py
        client_content = '''"""CryptoServe API client."""

import base64
import requests


class CryptoServeError(Exception):
    """Base exception for CryptoServe errors."""
    pass


class AuthenticationError(CryptoServeError):
    """Authentication failed."""
    pass


class AuthorizationError(CryptoServeError):
    """Not authorized for this operation."""
    pass


class ContextNotFoundError(CryptoServeError):
    """Context does not exist."""
    pass


class CryptoClient:
    """Client for CryptoServe API."""

    def __init__(self, server_url: str, token: str):
        self.server_url = server_url.rstrip("/")
        self.token = token
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        })

    def encrypt(self, plaintext: bytes, context: str) -> bytes:
        """Encrypt data."""
        response = self.session.post(
            f"{self.server_url}/v1/crypto/encrypt",
            json={
                "plaintext": base64.b64encode(plaintext).decode("ascii"),
                "context": context,
            },
            timeout=30,
        )

        if response.status_code == 401:
            raise AuthenticationError("Invalid or expired identity token")
        elif response.status_code == 403:
            raise AuthorizationError(f"Not authorized for context: {context}")
        elif response.status_code == 400:
            data = response.json()
            raise ContextNotFoundError(data.get("detail", "Bad request"))
        elif response.status_code != 200:
            raise CryptoServeError(f"Server error: {response.status_code}")

        data = response.json()
        return base64.b64decode(data["ciphertext"])

    def decrypt(self, ciphertext: bytes, context: str) -> bytes:
        """Decrypt data."""
        response = self.session.post(
            f"{self.server_url}/v1/crypto/decrypt",
            json={
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                "context": context,
            },
            timeout=30,
        )

        if response.status_code == 401:
            raise AuthenticationError("Invalid or expired identity token")
        elif response.status_code == 403:
            raise AuthorizationError(f"Not authorized for context: {context}")
        elif response.status_code == 400:
            data = response.json()
            raise CryptoServeError(data.get("detail", "Bad request"))
        elif response.status_code != 200:
            raise CryptoServeError(f"Server error: {response.status_code}")

        data = response.json()
        return base64.b64decode(data["plaintext"])
'''
        (target_dir / "client.py").write_text(client_content)

    def _generate_identity_module(self, target_dir: Path, identity: Identity, token: str):
        """Generate the _identity.py module with embedded credentials."""
        content = f'''"""
CryptoServe Identity - AUTO-GENERATED
DO NOT EDIT - This file contains your SDK credentials.
"""

IDENTITY = {{
    "server_url": "{settings.backend_url}",
    "token": "{token}",
    "identity_id": "{identity.id}",
    "identity_type": "{identity.type.value}",
    "name": "{identity.name}",
    "team": "{identity.team}",
    "environment": "{identity.environment}",
    "allowed_contexts": {identity.allowed_contexts},
    "created_at": "{identity.created_at.isoformat()}",
    "expires_at": "{identity.expires_at.isoformat()}",
}}
'''
        (target_dir / "_identity.py").write_text(content)

    def _generate_setup_py(self, temp_path: Path, identity_hash: str):
        """Generate setup.py for the package."""
        content = f'''"""CryptoServe SDK setup."""

from setuptools import setup, find_packages

setup(
    name="cryptoserve",
    version="0.1.0.{identity_hash}",
    packages=find_packages(),
    install_requires=[
        "requests>=2.28.0",
    ],
    python_requires=">=3.9",
    description="CryptoServe SDK - Zero-config cryptographic operations",
    author="CryptoServe",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
'''
        (temp_path / "setup.py").write_text(content)

    def _build_wheel(self, temp_path: Path) -> Path:
        """Build wheel package."""
        import subprocess

        # Run pip wheel
        result = subprocess.run(
            ["python", "-m", "pip", "wheel", ".", "--no-deps", "-w", "dist"],
            cwd=temp_path,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            raise RuntimeError(f"Failed to build wheel: {result.stderr}")

        # Find the wheel file
        dist_dir = temp_path / "dist"
        wheels = list(dist_dir.glob("*.whl"))

        if not wheels:
            raise RuntimeError("No wheel file generated")

        return wheels[0]


# Singleton instance
sdk_generator = SDKGenerator()
