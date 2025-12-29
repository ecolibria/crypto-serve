"""User API routes."""

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.auth.jwt import get_current_user
from app.models import User

router = APIRouter(prefix="/api/users", tags=["users"])


class UserResponse(BaseModel):
    """User response schema."""
    id: str
    github_username: str
    email: str | None
    avatar_url: str | None
    is_admin: bool = False

    class Config:
        from_attributes = True


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    user: Annotated[User, Depends(get_current_user)],
):
    """Get current authenticated user."""
    return user
