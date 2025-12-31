"""Crypto operations API routes."""

import base64
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Identity
from app.core.crypto_engine import (
    crypto_engine,
    ContextNotFoundError,
    AuthorizationError,
    DecryptionError,
)
from app.core.identity_manager import identity_manager
from app.schemas.context import AlgorithmOverride, CipherMode

router = APIRouter(prefix="/v1/crypto", tags=["crypto"])
security = HTTPBearer()


class EncryptRequest(BaseModel):
    """Encryption request schema."""
    plaintext: str  # Base64 encoded
    context: str
    algorithm_override: AlgorithmOverride | None = Field(
        default=None,
        description="Optional: Override automatic algorithm selection"
    )


class AlgorithmInfo(BaseModel):
    """Information about the algorithm used."""
    name: str
    mode: str
    key_bits: int
    description: str | None = None


class EncryptResponse(BaseModel):
    """Encryption response schema."""
    ciphertext: str  # Base64 encoded
    algorithm: AlgorithmInfo | None = Field(
        default=None,
        description="Algorithm used for encryption"
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Any warnings about the encryption (e.g., deprecation)"
    )


class DecryptRequest(BaseModel):
    """Decryption request schema."""
    ciphertext: str  # Base64 encoded
    context: str


class DecryptResponse(BaseModel):
    """Decryption response schema."""
    plaintext: str  # Base64 encoded


async def get_sdk_identity(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Identity:
    """Get identity from SDK token."""
    token = credentials.credentials

    identity = await identity_manager.get_identity_by_token(db, token)

    if not identity:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired identity token",
        )

    return identity


@router.post("/encrypt", response_model=EncryptResponse)
async def encrypt(
    request: Request,
    data: EncryptRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Encrypt data.

    Encrypts the provided plaintext using the specified context's algorithm.
    Optionally accepts an algorithm_override to explicitly select cipher,
    mode, and key size.
    """
    try:
        plaintext = base64.b64decode(data.plaintext)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 plaintext",
        )

    try:
        result = await crypto_engine.encrypt(
            db=db,
            plaintext=plaintext,
            context_name=data.context,
            identity=identity,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            algorithm_override=data.algorithm_override,
        )
    except ContextNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except AuthorizationError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )

    # Build algorithm info for response
    algorithm_info = AlgorithmInfo(
        name=result.algorithm,
        mode=result.mode.value if hasattr(result.mode, 'value') else str(result.mode),
        key_bits=result.key_bits,
        description=result.description,
    )

    return EncryptResponse(
        ciphertext=base64.b64encode(result.ciphertext).decode("ascii"),
        algorithm=algorithm_info,
        warnings=result.warnings,
    )


@router.post("/decrypt", response_model=DecryptResponse)
async def decrypt(
    request: Request,
    data: DecryptRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Decrypt data."""
    try:
        ciphertext = base64.b64decode(data.ciphertext)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 ciphertext",
        )

    try:
        plaintext = await crypto_engine.decrypt(
            db=db,
            packed_ciphertext=ciphertext,
            context_name=data.context,
            identity=identity,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
    except ContextNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except AuthorizationError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except DecryptionError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    return DecryptResponse(
        plaintext=base64.b64encode(plaintext).decode("ascii"),
    )
