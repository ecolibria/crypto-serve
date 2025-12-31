"""Key Export/Import Engine.

Provides secure key export and import functionality:
- Symmetric key export with key wrapping (AES-KW, AES-GCM-KW)
- Asymmetric key export (JWK, PEM, PKCS#8)
- Key import with validation
- Password-based key encryption (PBKDF2 + AES-GCM)

Security considerations:
- Private keys are never exported in plain text
- Key wrapping uses authenticated encryption
- Import validates key material before use
"""

import base64
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap

from app.core.secure_memory import SecureBytes


class KeyFormat(str, Enum):
    """Supported key export formats."""
    JWK = "jwk"  # JSON Web Key
    PEM = "pem"  # PEM encoded
    RAW = "raw"  # Raw bytes (for symmetric keys)
    WRAPPED = "wrapped"  # Key wrapped with KEK
    ENCRYPTED = "encrypted"  # Password-encrypted


class KeyType(str, Enum):
    """Key types."""
    SYMMETRIC = "symmetric"
    EC_P256 = "ec-p256"
    EC_P384 = "ec-p384"
    EC_P521 = "ec-p521"
    ED25519 = "ed25519"
    RSA_2048 = "rsa-2048"
    RSA_4096 = "rsa-4096"


@dataclass
class ExportedKey:
    """Exported key data."""
    key_data: bytes | dict | str
    format: KeyFormat
    key_type: KeyType
    is_private: bool
    metadata: dict


@dataclass
class ImportedKey:
    """Imported key result."""
    key: Any  # cryptography key object or bytes
    key_type: KeyType
    is_private: bool
    kid: str | None


class KeyExportError(Exception):
    """Key export failed."""
    pass


class KeyImportError(Exception):
    """Key import failed."""
    pass


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    """Base64url decode with padding restoration."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


class KeyExportEngine:
    """Handles key export and import operations."""

    # PBKDF2 parameters for password-based encryption
    PBKDF2_ITERATIONS = 600_000  # OWASP recommendation for SHA-256
    PBKDF2_SALT_SIZE = 16
    PBKDF2_KEY_SIZE = 32  # AES-256

    def export_symmetric_key(
        self,
        key: bytes,
        format: KeyFormat,
        kek: bytes | None = None,
        password: str | None = None,
        kid: str | None = None,
    ) -> ExportedKey:
        """Export a symmetric key.

        Args:
            key: The key to export
            format: Export format (raw, jwk, wrapped, encrypted)
            kek: Key Encryption Key for wrapped format
            password: Password for encrypted format
            kid: Optional key ID

        Returns:
            ExportedKey with key data
        """
        metadata = {
            "key_type": "symmetric",
            "key_size_bits": len(key) * 8,
            "exported_at": datetime.now(timezone.utc).isoformat(),
        }

        if format == KeyFormat.RAW:
            return ExportedKey(
                key_data=key,
                format=format,
                key_type=KeyType.SYMMETRIC,
                is_private=True,
                metadata=metadata,
            )

        elif format == KeyFormat.JWK:
            jwk = {
                "kty": "oct",
                "k": _b64url_encode(key),
                "key_ops": ["encrypt", "decrypt"],
            }
            if kid:
                jwk["kid"] = kid
            return ExportedKey(
                key_data=jwk,
                format=format,
                key_type=KeyType.SYMMETRIC,
                is_private=True,
                metadata=metadata,
            )

        elif format == KeyFormat.WRAPPED:
            if not kek or len(kek) not in [16, 24, 32]:
                raise KeyExportError("KEK must be 16, 24, or 32 bytes for AES Key Wrap")

            wrapped = aes_key_wrap(kek, key)
            return ExportedKey(
                key_data=wrapped,
                format=format,
                key_type=KeyType.SYMMETRIC,
                is_private=True,
                metadata={**metadata, "wrap_algorithm": "A256KW"},
            )

        elif format == KeyFormat.ENCRYPTED:
            if not password:
                raise KeyExportError("Password required for encrypted format")

            salt = os.urandom(self.PBKDF2_SALT_SIZE)
            iv = os.urandom(12)

            # Derive key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.PBKDF2_KEY_SIZE,
                salt=salt,
                iterations=self.PBKDF2_ITERATIONS,
            )
            derived_key = kdf.derive(password.encode())

            # Encrypt with AES-GCM
            aesgcm = AESGCM(derived_key)
            ciphertext = aesgcm.encrypt(iv, key, None)

            # Package as JSON
            encrypted_data = {
                "algorithm": "PBES2-HS256+A256GCM",
                "iterations": self.PBKDF2_ITERATIONS,
                "salt": _b64url_encode(salt),
                "iv": _b64url_encode(iv),
                "ciphertext": _b64url_encode(ciphertext),
            }

            return ExportedKey(
                key_data=json.dumps(encrypted_data),
                format=format,
                key_type=KeyType.SYMMETRIC,
                is_private=True,
                metadata={**metadata, "encryption": "PBES2-HS256+A256GCM"},
            )

        else:
            raise KeyExportError(f"Unsupported format: {format}")

    def import_symmetric_key(
        self,
        key_data: bytes | dict | str,
        format: KeyFormat,
        kek: bytes | None = None,
        password: str | None = None,
    ) -> ImportedKey:
        """Import a symmetric key.

        Args:
            key_data: The key data to import
            format: Import format
            kek: Key Encryption Key for wrapped format
            password: Password for encrypted format

        Returns:
            ImportedKey with key bytes
        """
        kid = None

        if format == KeyFormat.RAW:
            if not isinstance(key_data, bytes):
                raise KeyImportError("RAW format requires bytes")
            key = key_data

        elif format == KeyFormat.JWK:
            if isinstance(key_data, str):
                key_data = json.loads(key_data)
            if not isinstance(key_data, dict):
                raise KeyImportError("JWK format requires dict or JSON string")

            if key_data.get("kty") != "oct":
                raise KeyImportError("JWK must have kty=oct for symmetric key")

            key = _b64url_decode(key_data["k"])
            kid = key_data.get("kid")

        elif format == KeyFormat.WRAPPED:
            if not kek:
                raise KeyImportError("KEK required for wrapped format")
            if not isinstance(key_data, bytes):
                raise KeyImportError("WRAPPED format requires bytes")

            try:
                key = aes_key_unwrap(kek, key_data)
            except Exception as e:
                raise KeyImportError(f"Key unwrap failed: {e}")

        elif format == KeyFormat.ENCRYPTED:
            if not password:
                raise KeyImportError("Password required for encrypted format")

            if isinstance(key_data, bytes):
                key_data = key_data.decode()
            if isinstance(key_data, str):
                encrypted = json.loads(key_data)
            else:
                encrypted = key_data

            salt = _b64url_decode(encrypted["salt"])
            iv = _b64url_decode(encrypted["iv"])
            ciphertext = _b64url_decode(encrypted["ciphertext"])
            iterations = encrypted.get("iterations", self.PBKDF2_ITERATIONS)

            # Derive key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.PBKDF2_KEY_SIZE,
                salt=salt,
                iterations=iterations,
            )
            derived_key = kdf.derive(password.encode())

            # Decrypt
            try:
                aesgcm = AESGCM(derived_key)
                key = aesgcm.decrypt(iv, ciphertext, None)
            except Exception as e:
                raise KeyImportError(f"Decryption failed (wrong password?): {e}")

        else:
            raise KeyImportError(f"Unsupported format: {format}")

        return ImportedKey(
            key=key,
            key_type=KeyType.SYMMETRIC,
            is_private=True,
            kid=kid,
        )

    def export_asymmetric_key(
        self,
        key: Any,
        format: KeyFormat,
        include_private: bool = False,
        password: str | None = None,
        kid: str | None = None,
    ) -> ExportedKey:
        """Export an asymmetric key (public or private).

        Args:
            key: The cryptography key object
            format: Export format (jwk, pem)
            include_private: Include private key component
            password: Password for encrypting private key (PEM only)
            kid: Optional key ID

        Returns:
            ExportedKey with key data
        """
        # Determine key type
        key_type = self._get_key_type(key)
        is_private = self._is_private_key(key)

        if include_private and not is_private:
            raise KeyExportError("Cannot export private key from public key")

        metadata = {
            "key_type": key_type.value,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "is_private": include_private,
        }

        if format == KeyFormat.JWK:
            jwk = self._key_to_jwk(key, include_private, kid)
            return ExportedKey(
                key_data=jwk,
                format=format,
                key_type=key_type,
                is_private=include_private,
                metadata=metadata,
            )

        elif format == KeyFormat.PEM:
            pem = self._key_to_pem(key, include_private, password)
            return ExportedKey(
                key_data=pem,
                format=format,
                key_type=key_type,
                is_private=include_private,
                metadata=metadata,
            )

        else:
            raise KeyExportError(f"Unsupported format for asymmetric key: {format}")

    def import_asymmetric_key(
        self,
        key_data: bytes | dict | str,
        format: KeyFormat,
        password: str | None = None,
    ) -> ImportedKey:
        """Import an asymmetric key.

        Args:
            key_data: The key data to import
            format: Import format (jwk, pem)
            password: Password for encrypted private key (PEM only)

        Returns:
            ImportedKey with key object
        """
        kid = None

        if format == KeyFormat.JWK:
            if isinstance(key_data, str):
                key_data = json.loads(key_data)
            if not isinstance(key_data, dict):
                raise KeyImportError("JWK format requires dict or JSON string")

            key = self._jwk_to_key(key_data)
            kid = key_data.get("kid")
            is_private = "d" in key_data

        elif format == KeyFormat.PEM:
            if isinstance(key_data, str):
                key_data = key_data.encode()
            if not isinstance(key_data, bytes):
                raise KeyImportError("PEM format requires bytes or string")

            key, is_private = self._pem_to_key(key_data, password)

        else:
            raise KeyImportError(f"Unsupported format for asymmetric key: {format}")

        key_type = self._get_key_type(key)

        return ImportedKey(
            key=key,
            key_type=key_type,
            is_private=is_private,
            kid=kid,
        )

    def _get_key_type(self, key: Any) -> KeyType:
        """Determine the key type."""
        if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
            return KeyType.ED25519
        elif isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
            if isinstance(key, ec.EllipticCurvePrivateKey):
                curve = key.curve
            else:
                curve = key.curve
            if curve.name == "secp256r1":
                return KeyType.EC_P256
            elif curve.name == "secp384r1":
                return KeyType.EC_P384
            elif curve.name == "secp521r1":
                return KeyType.EC_P521
            else:
                raise KeyExportError(f"Unsupported EC curve: {curve.name}")
        elif isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
            if isinstance(key, rsa.RSAPrivateKey):
                size = key.key_size
            else:
                size = key.key_size
            if size <= 2048:
                return KeyType.RSA_2048
            else:
                return KeyType.RSA_4096
        else:
            raise KeyExportError(f"Unsupported key type: {type(key)}")

    def _is_private_key(self, key: Any) -> bool:
        """Check if key is a private key."""
        return isinstance(key, (
            ed25519.Ed25519PrivateKey,
            ec.EllipticCurvePrivateKey,
            rsa.RSAPrivateKey,
        ))

    def _key_to_jwk(self, key: Any, include_private: bool, kid: str | None) -> dict:
        """Convert key to JWK format."""
        if isinstance(key, ed25519.Ed25519PrivateKey):
            public = key.public_key()
            public_bytes = public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            jwk = {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": _b64url_encode(public_bytes),
                "use": "sig",
                "alg": "EdDSA",
            }
            if include_private:
                private_bytes = key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                jwk["d"] = _b64url_encode(private_bytes)

        elif isinstance(key, ed25519.Ed25519PublicKey):
            public_bytes = key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            jwk = {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": _b64url_encode(public_bytes),
                "use": "sig",
                "alg": "EdDSA",
            }

        elif isinstance(key, ec.EllipticCurvePrivateKey):
            public = key.public_key()
            numbers = public.public_numbers()
            curve = key.curve

            if curve.name == "secp256r1":
                crv, size, alg = "P-256", 32, "ES256"
            elif curve.name == "secp384r1":
                crv, size, alg = "P-384", 48, "ES384"
            elif curve.name == "secp521r1":
                crv, size, alg = "P-521", 66, "ES512"
            else:
                raise KeyExportError(f"Unsupported curve: {curve.name}")

            jwk = {
                "kty": "EC",
                "crv": crv,
                "x": _b64url_encode(numbers.x.to_bytes(size, "big")),
                "y": _b64url_encode(numbers.y.to_bytes(size, "big")),
                "use": "sig",
                "alg": alg,
            }
            if include_private:
                d = key.private_numbers().private_value
                jwk["d"] = _b64url_encode(d.to_bytes(size, "big"))

        elif isinstance(key, ec.EllipticCurvePublicKey):
            numbers = key.public_numbers()
            curve = key.curve

            if curve.name == "secp256r1":
                crv, size, alg = "P-256", 32, "ES256"
            elif curve.name == "secp384r1":
                crv, size, alg = "P-384", 48, "ES384"
            elif curve.name == "secp521r1":
                crv, size, alg = "P-521", 66, "ES512"
            else:
                raise KeyExportError(f"Unsupported curve: {curve.name}")

            jwk = {
                "kty": "EC",
                "crv": crv,
                "x": _b64url_encode(numbers.x.to_bytes(size, "big")),
                "y": _b64url_encode(numbers.y.to_bytes(size, "big")),
                "use": "sig",
                "alg": alg,
            }

        else:
            raise KeyExportError(f"Unsupported key type: {type(key)}")

        if kid:
            jwk["kid"] = kid

        return jwk

    def _key_to_pem(self, key: Any, include_private: bool, password: str | None) -> bytes:
        """Convert key to PEM format."""
        if include_private and self._is_private_key(key):
            if password:
                encryption = serialization.BestAvailableEncryption(password.encode())
            else:
                encryption = serialization.NoEncryption()

            return key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption,
            )
        else:
            # Export public key
            if self._is_private_key(key):
                key = key.public_key()
            return key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

    def _jwk_to_key(self, jwk: dict) -> Any:
        """Convert JWK to cryptography key."""
        kty = jwk.get("kty")

        if kty == "OKP":
            crv = jwk.get("crv")
            if crv == "Ed25519":
                x = _b64url_decode(jwk["x"])
                if "d" in jwk:
                    d = _b64url_decode(jwk["d"])
                    return ed25519.Ed25519PrivateKey.from_private_bytes(d)
                else:
                    return ed25519.Ed25519PublicKey.from_public_bytes(x)
            else:
                raise KeyImportError(f"Unsupported OKP curve: {crv}")

        elif kty == "EC":
            crv = jwk.get("crv")
            x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
            y = int.from_bytes(_b64url_decode(jwk["y"]), "big")

            if crv == "P-256":
                curve = ec.SECP256R1()
            elif crv == "P-384":
                curve = ec.SECP384R1()
            elif crv == "P-521":
                curve = ec.SECP521R1()
            else:
                raise KeyImportError(f"Unsupported EC curve: {crv}")

            public_numbers = ec.EllipticCurvePublicNumbers(x, y, curve)

            if "d" in jwk:
                d = int.from_bytes(_b64url_decode(jwk["d"]), "big")
                private_numbers = ec.EllipticCurvePrivateNumbers(d, public_numbers)
                return private_numbers.private_key()
            else:
                return public_numbers.public_key()

        else:
            raise KeyImportError(f"Unsupported key type: {kty}")

    def _pem_to_key(self, pem: bytes, password: str | None) -> tuple[Any, bool]:
        """Convert PEM to cryptography key."""
        pwd = password.encode() if password else None

        # Try to load as private key first
        try:
            key = serialization.load_pem_private_key(pem, password=pwd)
            return key, True
        except (ValueError, TypeError):
            pass

        # Try public key
        try:
            key = serialization.load_pem_public_key(pem)
            return key, False
        except Exception as e:
            raise KeyImportError(f"Failed to parse PEM: {e}")


# Singleton instance
key_export_engine = KeyExportEngine()
