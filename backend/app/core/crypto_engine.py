"""Cryptographic operations engine."""

import os
import json
import base64
from dataclasses import dataclass
from datetime import datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Context, Identity, AuditLog
from app.core.key_manager import key_manager


class CryptoError(Exception):
    """Base crypto exception."""
    pass


class ContextNotFoundError(CryptoError):
    """Context does not exist."""
    pass


class AuthorizationError(CryptoError):
    """Identity not authorized for context."""
    pass


class DecryptionError(CryptoError):
    """Failed to decrypt data."""
    pass


@dataclass
class EncryptResult:
    """Result of encryption operation."""
    ciphertext: bytes
    algorithm: str
    key_id: str
    nonce: bytes
    context: str


class CryptoEngine:
    """Handles encryption and decryption operations."""

    HEADER_VERSION = 1

    async def encrypt(
        self,
        db: AsyncSession,
        plaintext: bytes,
        context_name: str,
        identity: Identity,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> bytes:
        """Encrypt data and return self-describing ciphertext."""
        start_time = datetime.utcnow()
        success = False
        error_message = None

        try:
            # Validate context exists
            result = await db.execute(
                select(Context).where(Context.name == context_name)
            )
            context = result.scalar_one_or_none()
            if not context:
                raise ContextNotFoundError(f"Unknown context: {context_name}")

            # Validate identity has access to context
            if context_name not in identity.allowed_contexts:
                raise AuthorizationError(
                    f"Identity not authorized for context: {context_name}"
                )

            # Get key for context
            key, key_id = await key_manager.get_or_create_key(db, context_name)

            # Encrypt with AES-256-GCM
            nonce = os.urandom(12)
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)

            # Pack into self-describing format
            packed = self._pack_ciphertext(
                ciphertext=ciphertext,
                nonce=nonce,
                key_id=key_id,
                context=context_name,
                algorithm=context.algorithm,
            )

            success = True
            return packed

        except Exception as e:
            error_message = str(e)
            raise

        finally:
            # Log to audit
            latency_ms = int(
                (datetime.utcnow() - start_time).total_seconds() * 1000
            )
            audit = AuditLog(
                operation="encrypt",
                context=context_name,
                success=success,
                error_message=error_message,
                identity_id=identity.id,
                identity_name=identity.name,
                team=identity.team,
                input_size_bytes=len(plaintext),
                output_size_bytes=len(packed) if success else None,
                latency_ms=latency_ms,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            db.add(audit)
            await db.commit()

    async def decrypt(
        self,
        db: AsyncSession,
        packed_ciphertext: bytes,
        context_name: str,
        identity: Identity,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> bytes:
        """Decrypt self-describing ciphertext."""
        start_time = datetime.utcnow()
        success = False
        error_message = None
        plaintext = b""

        try:
            # Validate identity has access to context
            if context_name not in identity.allowed_contexts:
                raise AuthorizationError(
                    f"Identity not authorized for context: {context_name}"
                )

            # Unpack ciphertext
            header, ciphertext = self._unpack_ciphertext(packed_ciphertext)

            # Validate context matches
            if header["ctx"] != context_name:
                raise DecryptionError(
                    f"Context mismatch: expected {context_name}, got {header['ctx']}"
                )

            # Get key
            key = await key_manager.get_key_by_id(db, header["kid"])
            if not key:
                raise DecryptionError(f"Key not found: {header['kid']}")

            # Decrypt
            nonce = base64.b64decode(header["nonce"])
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)

            success = True
            return plaintext

        except Exception as e:
            error_message = str(e)
            raise

        finally:
            # Log to audit
            latency_ms = int(
                (datetime.utcnow() - start_time).total_seconds() * 1000
            )
            audit = AuditLog(
                operation="decrypt",
                context=context_name,
                success=success,
                error_message=error_message,
                identity_id=identity.id,
                identity_name=identity.name,
                team=identity.team,
                input_size_bytes=len(packed_ciphertext),
                output_size_bytes=len(plaintext) if success else None,
                latency_ms=latency_ms,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            db.add(audit)
            await db.commit()

    def _pack_ciphertext(
        self,
        ciphertext: bytes,
        nonce: bytes,
        key_id: str,
        context: str,
        algorithm: str,
    ) -> bytes:
        """Pack ciphertext with header for self-describing format."""
        header = {
            "v": self.HEADER_VERSION,
            "ctx": context,
            "kid": key_id,
            "alg": algorithm,
            "nonce": base64.b64encode(nonce).decode("ascii"),
        }
        header_json = json.dumps(header, separators=(",", ":")).encode()
        header_len = len(header_json).to_bytes(2, "big")

        return header_len + header_json + ciphertext

    def _unpack_ciphertext(self, packed: bytes) -> tuple[dict, bytes]:
        """Unpack self-describing ciphertext."""
        if len(packed) < 3:
            raise DecryptionError("Invalid ciphertext: too short")

        header_len = int.from_bytes(packed[:2], "big")

        if len(packed) < 2 + header_len:
            raise DecryptionError("Invalid ciphertext: header truncated")

        header_json = packed[2:2 + header_len]
        ciphertext = packed[2 + header_len:]

        try:
            header = json.loads(header_json.decode())
        except json.JSONDecodeError as e:
            raise DecryptionError(f"Invalid ciphertext header: {e}")

        if header.get("v") != self.HEADER_VERSION:
            raise DecryptionError(
                f"Unsupported ciphertext version: {header.get('v')}"
            )

        return header, ciphertext


# Singleton instance
crypto_engine = CryptoEngine()
