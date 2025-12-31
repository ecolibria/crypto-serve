"""Key derivation and management.

Supports variable key sizes for different algorithm families:
- AES-128: 16 bytes
- AES-192: 24 bytes
- AES-256: 32 bytes (default)
- XTS: 64 bytes (two 256-bit keys)
"""

import secrets
import hashlib
from datetime import datetime

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models import Key, KeyStatus

settings = get_settings()

# Standard key sizes in bytes
KEY_SIZE_128 = 16
KEY_SIZE_192 = 24
KEY_SIZE_256 = 32
KEY_SIZE_XTS = 64  # XTS uses two 256-bit keys


class KeyManager:
    """Manages encryption key derivation and rotation."""

    def __init__(self):
        self.master_key = settings.cryptoserve_master_key.encode()

    def derive_key(
        self,
        context: str,
        version: int = 1,
        key_size: int = KEY_SIZE_256,
    ) -> bytes:
        """Derive a key for a context using HKDF.

        Uses a configurable salt from settings to prevent precomputation attacks.
        The salt should be unique per deployment.

        Args:
            context: Context name for key derivation
            version: Key version number
            key_size: Key size in bytes (16, 24, 32, or 64)

        Returns:
            Derived key material of specified size
        """
        # Include key size in info for proper key separation
        # This ensures different key sizes produce different keys
        info = f"{context}:{version}:{key_size}".encode()

        # Use configurable salt from settings (unique per deployment)
        salt = settings.hkdf_salt.encode()

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=key_size,
            salt=salt,
            info=info,
        )

        return hkdf.derive(self.master_key)

    async def get_or_create_key(
        self,
        db: AsyncSession,
        context: str,
        key_size: int = KEY_SIZE_256,
    ) -> tuple[bytes, str]:
        """Get current key for context, creating if needed.

        Args:
            db: Database session
            context: Context name
            key_size: Key size in bytes (default 32 for AES-256)

        Returns:
            Tuple of (key_material, key_id)
        """
        # Find active key for context
        result = await db.execute(
            select(Key)
            .where(Key.context == context)
            .where(Key.status == KeyStatus.ACTIVE)
            .order_by(Key.version.desc())
        )
        key_record = result.scalar_one_or_none()

        if not key_record:
            # Create new key record
            key_id = f"key_{context}_{secrets.token_hex(4)}"
            key_record = Key(
                id=key_id,
                context=context,
                version=1,
                status=KeyStatus.ACTIVE,
            )
            db.add(key_record)
            await db.commit()
            await db.refresh(key_record)

        # Derive actual key material with specified size
        key = self.derive_key(context, key_record.version, key_size)

        return key, key_record.id

    async def get_key_by_id(
        self,
        db: AsyncSession,
        key_id: str,
        key_size: int = KEY_SIZE_256,
    ) -> bytes | None:
        """Get key by its ID (for decryption).

        Args:
            db: Database session
            key_id: Key identifier
            key_size: Key size in bytes (must match encryption key size)

        Returns:
            Key material or None if not found
        """
        result = await db.execute(select(Key).where(Key.id == key_id))
        key_record = result.scalar_one_or_none()

        if not key_record:
            return None

        return self.derive_key(key_record.context, key_record.version, key_size)

    async def rotate_key(
        self,
        db: AsyncSession,
        context: str,
        key_size: int = KEY_SIZE_256,
    ) -> tuple[bytes, str]:
        """Rotate key by creating new version.

        Args:
            db: Database session
            context: Context name
            key_size: Key size in bytes for new key

        Returns:
            Tuple of (new_key_material, new_key_id)
        """
        # Mark current key as rotated
        result = await db.execute(
            select(Key)
            .where(Key.context == context)
            .where(Key.status == KeyStatus.ACTIVE)
        )
        current_key = result.scalar_one_or_none()

        new_version = 1
        if current_key:
            current_key.status = KeyStatus.ROTATED
            new_version = current_key.version + 1

        # Create new key
        key_id = f"key_{context}_{secrets.token_hex(4)}"
        new_key = Key(
            id=key_id,
            context=context,
            version=new_version,
            status=KeyStatus.ACTIVE,
        )
        db.add(new_key)
        await db.commit()

        key = self.derive_key(context, new_version, key_size)
        return key, key_id


# Singleton instance
key_manager = KeyManager()
