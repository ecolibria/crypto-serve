"""Teams API routes.

Provides endpoints for team management:
- List user's teams
- List all teams (admin)
- Create team (admin)
"""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.auth.jwt import get_current_user
from app.models import User, Team, TeamSource
from app.core.team_service import team_service

router = APIRouter(prefix="/api/v1/teams", tags=["teams"])


# ============================================================================
# Request/Response Models
# ============================================================================


class TeamResponse(BaseModel):
    """Team response schema."""
    id: str
    name: str
    display_name: str | None
    description: str | None
    source: str
    member_count: int
    created_at: datetime

    class Config:
        from_attributes = True


class TeamCreate(BaseModel):
    """Team creation schema (admin only)."""
    name: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9-]*[a-z0-9]$")
    display_name: str | None = Field(None, max_length=256)
    description: str | None = Field(None, max_length=1024)


class UserTeamsResponse(BaseModel):
    """User's teams response."""
    teams: list[TeamResponse]
    can_create_for_any_team: bool  # True for admins


# ============================================================================
# Helper Functions
# ============================================================================


def team_to_response(team: Team, member_count: int = 0) -> TeamResponse:
    """Convert Team model to response."""
    return TeamResponse(
        id=team.id,
        name=team.name,
        display_name=team.display_name,
        description=team.description,
        source=team.source,
        member_count=member_count,
        created_at=team.created_at,
    )


# ============================================================================
# Endpoints
# ============================================================================


@router.get("/me", response_model=UserTeamsResponse)
async def get_my_teams(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get current user's teams.

    Returns the list of teams the user belongs to and whether they can
    create apps for any team (admins only).
    """
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    # Reload user with teams eagerly loaded
    result = await db.execute(
        select(User)
        .options(selectinload(User.teams))
        .where(User.id == user.id)
    )
    user_with_teams = result.scalar_one()

    return UserTeamsResponse(
        teams=[team_to_response(t) for t in user_with_teams.teams],
        can_create_for_any_team=user.is_admin,
    )


@router.get("", response_model=list[TeamResponse])
async def list_all_teams(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """List all teams (admin only).

    Returns all teams in the tenant.
    """
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required to list all teams",
        )

    teams = await team_service.get_all_teams(db, user.tenant_id)
    return [team_to_response(t) for t in teams]


@router.post("", response_model=TeamResponse, status_code=status.HTTP_201_CREATED)
async def create_team(
    data: TeamCreate,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Create a new team (admin only).

    Creates a team that can be assigned to applications.
    Team names must be lowercase alphanumeric with hyphens.
    """
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required to create teams",
        )

    team = await team_service.get_or_create_team(
        db=db,
        tenant_id=user.tenant_id,
        name=data.name,
        source=TeamSource.ADMIN,
        display_name=data.display_name,
    )

    if data.description:
        team.description = data.description

    await db.commit()
    await db.refresh(team)

    return team_to_response(team)


@router.post("/{team_name}/members/{username}", status_code=status.HTTP_204_NO_CONTENT)
async def add_team_member(
    team_name: str,
    username: str,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Add a user to a team (admin only).

    Allows admins to manually add users to teams.
    """
    from sqlalchemy import select

    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required to manage team members",
        )

    # Find the team
    from app.models import Team
    result = await db.execute(
        select(Team).where(
            Team.tenant_id == user.tenant_id,
            Team.name == team_name.lower()
        )
    )
    team = result.scalar_one_or_none()
    if not team:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Team not found: {team_name}",
        )

    # Find the user to add
    result = await db.execute(
        select(User).where(
            User.tenant_id == user.tenant_id,
            User.github_username == username
        )
    )
    target_user = result.scalar_one_or_none()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User not found: {username}",
        )

    # Add to team if not already a member
    if team not in target_user.teams:
        target_user.teams.append(team)
        await db.commit()
