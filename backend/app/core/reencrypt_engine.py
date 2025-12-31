"""Re-encryption Engine.

Provides server-side re-encryption without exposing plaintext to clients:
- Context-to-context re-encryption
- Key version migration
- Algorithm upgrade (e.g., AES-CBC to AES-GCM)
- Bulk re-encryption for compliance

Security model:
- Plaintext never leaves the server
- Atomic re-encryption (decrypt + encrypt in single operation)
- Audit logging for compliance
- Rate limiting to prevent abuse
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Identity
from app.core.crypto_engine import crypto_engine, CryptoError


class ReencryptionMode(str, Enum):
    """Re-encryption modes."""
    CONTEXT_MIGRATION = "context_migration"  # Move data to new context
    KEY_ROTATION = "key_rotation"  # Re-encrypt with new key version
    ALGORITHM_UPGRADE = "algorithm_upgrade"  # Upgrade cipher/mode
    COMPLIANCE = "compliance"  # Re-encrypt for compliance (audit trail)


@dataclass
class ReencryptionRequest:
    """Request to re-encrypt data."""
    ciphertext: bytes
    source_context: str
    target_context: str | None = None  # If None, use source context
    mode: ReencryptionMode = ReencryptionMode.CONTEXT_MIGRATION


@dataclass
class ReencryptionResult:
    """Result of re-encryption."""
    ciphertext: bytes
    source_context: str
    target_context: str
    source_algorithm: str
    target_algorithm: str
    source_key_version: int
    target_key_version: int
    reencrypted_at: datetime


@dataclass
class BulkReencryptionResult:
    """Result of bulk re-encryption."""
    total: int
    successful: int
    failed: int
    results: list[ReencryptionResult | None]
    errors: list[str | None]


class ReencryptionError(Exception):
    """Re-encryption failed."""
    pass


class ReencryptionEngine:
    """Handles re-encryption operations."""

    async def reencrypt(
        self,
        db: AsyncSession,
        ciphertext: bytes,
        source_context: str,
        identity: Identity,
        target_context: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> ReencryptionResult:
        """Re-encrypt data from source to target context.

        This is an atomic operation that decrypts and re-encrypts
        without exposing plaintext to the client.

        Args:
            db: Database session
            ciphertext: Encrypted data
            source_context: Original encryption context
            identity: Identity performing the operation
            target_context: New encryption context (None = same as source)
            ip_address: Client IP for audit
            user_agent: Client user agent for audit

        Returns:
            ReencryptionResult with new ciphertext
        """
        if target_context is None:
            target_context = source_context

        # Decrypt (server-side only)
        try:
            plaintext = await crypto_engine.decrypt(
                db=db,
                packed_ciphertext=ciphertext,
                context_name=source_context,
                identity=identity,
                ip_address=ip_address,
                user_agent=user_agent,
            )
        except CryptoError as e:
            raise ReencryptionError(f"Decryption failed: {e}")

        # Extract source metadata from ciphertext header
        source_metadata = self._extract_metadata(ciphertext)

        # Re-encrypt to target context
        try:
            result = await crypto_engine.encrypt(
                db=db,
                plaintext=plaintext,
                context_name=target_context,
                identity=identity,
                ip_address=ip_address,
                user_agent=user_agent,
            )
        except CryptoError as e:
            raise ReencryptionError(f"Re-encryption failed: {e}")

        # Extract target metadata
        target_metadata = self._extract_metadata(result.ciphertext)

        return ReencryptionResult(
            ciphertext=result.ciphertext,
            source_context=source_context,
            target_context=target_context,
            source_algorithm=source_metadata.get("algorithm", "unknown"),
            target_algorithm=result.algorithm,
            source_key_version=source_metadata.get("key_version", 0),
            target_key_version=target_metadata.get("key_version", 1),
            reencrypted_at=datetime.now(timezone.utc),
        )

    async def bulk_reencrypt(
        self,
        db: AsyncSession,
        ciphertexts: list[bytes],
        source_context: str,
        identity: Identity,
        target_context: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        stop_on_error: bool = False,
    ) -> BulkReencryptionResult:
        """Re-encrypt multiple ciphertexts.

        Args:
            db: Database session
            ciphertexts: List of encrypted data
            source_context: Original encryption context
            identity: Identity performing the operation
            target_context: New encryption context
            ip_address: Client IP for audit
            user_agent: Client user agent for audit
            stop_on_error: Stop on first error if True

        Returns:
            BulkReencryptionResult with results and errors
        """
        results: list[ReencryptionResult | None] = []
        errors: list[str | None] = []
        successful = 0
        failed = 0

        for ciphertext in ciphertexts:
            try:
                result = await self.reencrypt(
                    db=db,
                    ciphertext=ciphertext,
                    source_context=source_context,
                    identity=identity,
                    target_context=target_context,
                    ip_address=ip_address,
                    user_agent=user_agent,
                )
                results.append(result)
                errors.append(None)
                successful += 1
            except ReencryptionError as e:
                if stop_on_error:
                    raise
                results.append(None)
                errors.append(str(e))
                failed += 1

        return BulkReencryptionResult(
            total=len(ciphertexts),
            successful=successful,
            failed=failed,
            results=results,
            errors=errors,
        )

    async def rotate_key(
        self,
        db: AsyncSession,
        ciphertext: bytes,
        context_name: str,
        identity: Identity,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> ReencryptionResult:
        """Re-encrypt with the latest key version.

        Used after key rotation to migrate data to new key.

        Args:
            db: Database session
            ciphertext: Encrypted data
            context_name: Encryption context
            identity: Identity performing the operation
            ip_address: Client IP for audit
            user_agent: Client user agent for audit

        Returns:
            ReencryptionResult with new ciphertext
        """
        return await self.reencrypt(
            db=db,
            ciphertext=ciphertext,
            source_context=context_name,
            identity=identity,
            target_context=context_name,  # Same context, new key version
            ip_address=ip_address,
            user_agent=user_agent,
        )

    def _extract_metadata(self, ciphertext: bytes) -> dict:
        """Extract metadata from ciphertext header.

        The ciphertext format is: header_len (2 bytes) | header_json | iv | ciphertext | tag

        Returns:
            Dictionary with algorithm, mode, key_version, etc.
        """
        try:
            if len(ciphertext) < 2:
                return {}

            header_len = int.from_bytes(ciphertext[:2], "big")
            if len(ciphertext) < 2 + header_len:
                return {}

            import json
            header_json = ciphertext[2:2 + header_len]
            header = json.loads(header_json)

            return {
                "algorithm": header.get("alg", "unknown"),
                "mode": header.get("mode", "unknown"),
                "key_version": header.get("kv", 1),
                "key_bits": header.get("kb", 256),
            }
        except Exception:
            return {}


# Singleton instance
reencrypt_engine = ReencryptionEngine()
