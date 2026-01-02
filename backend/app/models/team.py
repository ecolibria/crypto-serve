"""Team model for OIDC-based team validation.

Teams are extracted from OIDC claims (groups, organizations) and used to
validate that users can only create applications for teams they belong to.
"""

from datetime import datetime, timezone
from uuid import uuid4
from enum import Enum

from sqlalchemy import String, DateTime, ForeignKey, Table, Column, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base, GUID


class TeamSource(str, Enum):
    """Source of team definition."""
    OIDC = "oidc"  # Extracted from OIDC claims
    GITHUB = "github"  # GitHub organization
    ADMIN = "admin"  # Created by admin
    DEV = "dev"  # Dev mode default team


# Association table for many-to-many user-team relationship
user_teams = Table(
    "user_teams",
    Base.metadata,
    Column("user_id", GUID(), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("team_id", GUID(), ForeignKey("teams.id", ondelete="CASCADE"), primary_key=True),
    Column("joined_at", DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)),
)


class Team(Base):
    """Team for access control and audit.

    Teams are synchronized from OIDC providers (GitHub orgs, Azure AD groups, etc.)
    and used to validate that users can only create apps for teams they belong to.
    """

    __tablename__ = "teams"

    id: Mapped[str] = mapped_column(
        GUID(),
        primary_key=True,
        default=lambda: str(uuid4())
    )

    # Tenant isolation
    tenant_id: Mapped[str] = mapped_column(
        GUID(),
        ForeignKey("tenants.id"),
        nullable=False,
        index=True
    )

    # Team identification
    name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    display_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    # Source tracking
    source: Mapped[TeamSource] = mapped_column(
        String(16),
        default=TeamSource.OIDC.value,
        nullable=False
    )
    external_id: Mapped[str | None] = mapped_column(
        String(256),
        nullable=True,
        doc="External ID from provider (e.g., GitHub org ID)"
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="teams")
    users: Mapped[list["User"]] = relationship(
        "User",
        secondary=user_teams,
        back_populates="teams",
        lazy="selectin"
    )

    # Unique constraint: team name must be unique within tenant
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_team_tenant_name"),
    )

    def __repr__(self) -> str:
        return f"<Team {self.name}>"
