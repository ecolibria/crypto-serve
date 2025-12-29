"""Context API routes."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.auth.jwt import get_current_user
from app.models import User, Context

router = APIRouter(prefix="/api/contexts", tags=["contexts"])


class ContextResponse(BaseModel):
    """Context response schema."""
    name: str
    display_name: str
    description: str
    data_examples: list[str] | None
    compliance_tags: list[str] | None
    algorithm: str

    class Config:
        from_attributes = True


class ContextCreate(BaseModel):
    """Context creation schema."""
    name: str
    display_name: str
    description: str
    data_examples: list[str] | None = None
    compliance_tags: list[str] | None = None
    algorithm: str = "AES-256-GCM"


@router.get("", response_model=list[ContextResponse])
async def list_contexts(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """List all available contexts."""
    result = await db.execute(select(Context).order_by(Context.name))
    contexts = result.scalars().all()
    return contexts


@router.get("/{name}", response_model=ContextResponse)
async def get_context(
    name: str,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get a specific context."""
    result = await db.execute(select(Context).where(Context.name == name))
    context = result.scalar_one_or_none()

    if not context:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Context not found: {name}",
        )

    return context


@router.post("", response_model=ContextResponse, status_code=status.HTTP_201_CREATED)
async def create_context(
    data: ContextCreate,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Create a new context."""
    # Check if context already exists
    result = await db.execute(select(Context).where(Context.name == data.name))
    existing = result.scalar_one_or_none()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Context already exists: {data.name}",
        )

    context = Context(
        name=data.name,
        display_name=data.display_name,
        description=data.description,
        data_examples=data.data_examples,
        compliance_tags=data.compliance_tags,
        algorithm=data.algorithm,
    )

    db.add(context)
    await db.commit()
    await db.refresh(context)

    return context
