"""SDK download API routes."""

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_session_maker
from app.models import Identity
from app.core.identity_manager import identity_manager
from app.sdk_generator.generator import sdk_generator

router = APIRouter(prefix="/sdk", tags=["sdk"])


@router.get("/download/{token}/python")
async def download_python_sdk(token: str):
    """Download personalized Python SDK."""
    async with get_session_maker()() as db:
        # Validate token and get identity
        identity = await identity_manager.get_identity_by_token(db, token)

        if not identity:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Invalid or expired token",
            )

        # Generate SDK
        try:
            wheel_path = sdk_generator.generate_python_sdk(identity, token)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to generate SDK: {str(e)}",
            )

        return FileResponse(
            path=wheel_path,
            filename=wheel_path.name,
            media_type="application/octet-stream",
        )


@router.get("/info/{token}")
async def get_sdk_info(token: str):
    """Get identity info for a token (for SDK refresh)."""
    async with get_session_maker()() as db:
        identity = await identity_manager.get_identity_by_token(db, token)

        if not identity:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Invalid or expired token",
            )

        return {
            "identity_id": identity.id,
            "name": identity.name,
            "team": identity.team,
            "environment": identity.environment,
            "allowed_contexts": identity.allowed_contexts,
            "expires_at": identity.expires_at.isoformat(),
        }
