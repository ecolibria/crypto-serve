"""Identity API routes."""

from typing import Annotated
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.auth.jwt import get_current_user
from app.models import User, Identity, IdentityType, IdentityStatus
from app.core.identity_manager import identity_manager
from app.config import get_settings

settings = get_settings()
router = APIRouter(prefix="/api/identities", tags=["identities"])


class IdentityCreate(BaseModel):
    """Identity creation schema."""
    name: str
    type: IdentityType = IdentityType.DEVELOPER
    team: str
    environment: str = "development"
    allowed_contexts: list[str]
    expires_in_days: int = 90


class IdentityResponse(BaseModel):
    """Identity response schema."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    type: IdentityType
    name: str
    team: str
    environment: str
    allowed_contexts: list[str]
    status: IdentityStatus
    created_at: datetime
    expires_at: datetime
    last_used_at: datetime | None


class IdentityCreateResponse(BaseModel):
    """Response when creating a new identity."""
    identity: IdentityResponse
    token: str
    sdk_download_url: str


@router.get("", response_model=list[IdentityResponse])
async def list_identities(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """List all identities for the current user."""
    result = await db.execute(
        select(Identity)
        .where(Identity.user_id == user.id)
        .order_by(Identity.created_at.desc())
    )
    identities = result.scalars().all()
    return identities


@router.post("", response_model=IdentityCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_identity(
    data: IdentityCreate,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Create a new identity."""
    identity, token = await identity_manager.create_identity(
        db=db,
        user=user,
        name=data.name,
        identity_type=data.type,
        team=data.team,
        environment=data.environment,
        allowed_contexts=data.allowed_contexts,
        expires_in_days=data.expires_in_days,
    )

    sdk_download_url = f"{settings.backend_url}/sdk/download/{token}/python"

    return IdentityCreateResponse(
        identity=identity,
        token=token,
        sdk_download_url=sdk_download_url,
    )


@router.get("/{identity_id}", response_model=IdentityResponse)
async def get_identity(
    identity_id: str,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get a specific identity."""
    result = await db.execute(
        select(Identity)
        .where(Identity.id == identity_id)
        .where(Identity.user_id == user.id)
    )
    identity = result.scalar_one_or_none()

    if not identity:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Identity not found: {identity_id}",
        )

    return identity


@router.delete("/{identity_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_identity(
    identity_id: str,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Revoke an identity."""
    success = await identity_manager.revoke_identity(db, identity_id, user)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Identity not found: {identity_id}",
        )
