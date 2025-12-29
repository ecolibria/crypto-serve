"""Crypto operations API routes."""

import base64
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
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

router = APIRouter(prefix="/v1/crypto", tags=["crypto"])
security = HTTPBearer()


class EncryptRequest(BaseModel):
    """Encryption request schema."""
    plaintext: str  # Base64 encoded
    context: str


class EncryptResponse(BaseModel):
    """Encryption response schema."""
    ciphertext: str  # Base64 encoded


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
    """Encrypt data."""
    try:
        plaintext = base64.b64decode(data.plaintext)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 plaintext",
        )

    try:
        ciphertext = await crypto_engine.encrypt(
            db=db,
            plaintext=plaintext,
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

    return EncryptResponse(
        ciphertext=base64.b64encode(ciphertext).decode("ascii"),
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
