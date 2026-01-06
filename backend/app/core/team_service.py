"""Team service for OIDC-based team validation.

Manages teams extracted from OIDC claims and validates team membership
when creating applications.
"""

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Team, TeamSource, User


class TeamService:
    """Service for managing teams and team membership."""

    async def get_or_create_team(
        self,
        db: AsyncSession,
        tenant_id: str,
        name: str,
        source: TeamSource = TeamSource.OIDC,
        display_name: str | None = None,
        external_id: str | None = None,
    ) -> Team:
        """Get or create a team by name within a tenant.

        Args:
            db: Database session
            tenant_id: Tenant ID for isolation
            name: Team name (normalized to lowercase)
            source: Source of team (oidc, github, admin, dev)
            display_name: Human-readable name
            external_id: External ID from provider

        Returns:
            The existing or newly created team
        """
        # Normalize team name
        normalized_name = name.lower().strip()

        # Check if team exists
        result = await db.execute(select(Team).where(Team.tenant_id == tenant_id, Team.name == normalized_name))
        team = result.scalar_one_or_none()

        if team:
            # Update external_id if provided and not set
            if external_id and not team.external_id:
                team.external_id = external_id
                team.updated_at = datetime.now(timezone.utc)
            return team

        # Create new team
        team = Team(
            tenant_id=tenant_id,
            name=normalized_name,
            display_name=display_name or name,
            source=source.value if isinstance(source, TeamSource) else source,
            external_id=external_id,
        )
        db.add(team)
        await db.flush()  # Get the ID without committing
        return team

    async def sync_user_teams(
        self,
        db: AsyncSession,
        user: User,
        team_names: list[str],
        source: TeamSource = TeamSource.OIDC,
    ) -> list[Team]:
        """Sync user's team memberships from OIDC claims.

        This replaces the user's teams from this source with the new list.
        Teams from other sources (admin, dev) are preserved.

        Args:
            db: Database session
            user: User to update teams for
            team_names: List of team names from OIDC claims
            source: Source of teams (oidc, github)

        Returns:
            List of teams the user is now a member of
        """
        if not team_names:
            return []

        # Get or create teams
        teams = []
        for name in team_names:
            team = await self.get_or_create_team(
                db=db,
                tenant_id=user.tenant_id,
                name=name,
                source=source,
            )
            teams.append(team)

        # Update user's teams (additive - don't remove existing teams)
        existing_team_ids = {t.id for t in user.teams}
        for team in teams:
            if team.id not in existing_team_ids:
                user.teams.append(team)

        return teams

    async def get_user_teams(
        self,
        db: AsyncSession,
        user: User,
    ) -> list[Team]:
        """Get all teams a user belongs to.

        Args:
            db: Database session
            user: User to get teams for

        Returns:
            List of teams
        """
        from sqlalchemy.orm import selectinload
        from app.models import User as UserModel

        # Reload user with teams eagerly loaded
        result = await db.execute(
            select(UserModel).options(selectinload(UserModel.teams)).where(UserModel.id == user.id)
        )
        user_with_teams = result.scalar_one_or_none()
        if not user_with_teams:
            return []
        return list(user_with_teams.teams)

    async def get_user_team_names(
        self,
        db: AsyncSession,
        user: User,
    ) -> list[str]:
        """Get team names for a user.

        Args:
            db: Database session
            user: User to get team names for

        Returns:
            List of team names
        """
        teams = await self.get_user_teams(db, user)
        return [t.name for t in teams]

    async def user_belongs_to_team(
        self,
        db: AsyncSession,
        user: User,
        team_name: str,
    ) -> bool:
        """Check if a user belongs to a specific team.

        Args:
            db: Database session
            user: User to check
            team_name: Team name to check membership for

        Returns:
            True if user belongs to the team
        """
        normalized_name = team_name.lower().strip()
        teams = await self.get_user_teams(db, user)
        return any(t.name == normalized_name for t in teams)

    async def validate_team_for_app_creation(
        self,
        db: AsyncSession,
        user: User,
        team_name: str,
    ) -> tuple[bool, str | None]:
        """Validate that a user can create an app for a team.

        Admins can create apps for any team.
        Regular users can only create apps for teams they belong to.

        Args:
            db: Database session
            user: User creating the app
            team_name: Team name for the app

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Admins can create apps for any team
        if user.is_admin:
            return True, None

        # Check team membership
        if await self.user_belongs_to_team(db, user, team_name):
            return True, None

        # Get user's teams for error message
        user_teams = await self.get_user_team_names(db, user)
        if user_teams:
            return False, (f"You are not a member of team '{team_name}'. " f"Your teams: {', '.join(user_teams)}")
        else:
            return False, (
                "You are not a member of any team. "
                "Teams are synced from your identity provider (GitHub organizations, OIDC groups)."
            )

    async def get_or_create_dev_team(
        self,
        db: AsyncSession,
        tenant_id: str,
    ) -> Team:
        """Get or create the development mode team.

        Args:
            db: Database session
            tenant_id: Tenant ID

        Returns:
            The dev team
        """
        return await self.get_or_create_team(
            db=db,
            tenant_id=tenant_id,
            name="dev",
            source=TeamSource.DEV,
            display_name="Development Team",
        )

    async def get_all_teams(
        self,
        db: AsyncSession,
        tenant_id: str,
    ) -> list[Team]:
        """Get all teams for a tenant.

        Args:
            db: Database session
            tenant_id: Tenant ID

        Returns:
            List of all teams
        """
        result = await db.execute(select(Team).where(Team.tenant_id == tenant_id).order_by(Team.name))
        return list(result.scalars().all())


# Singleton instance
team_service = TeamService()
