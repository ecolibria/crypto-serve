"""Context model for crypto policy definitions."""

from datetime import datetime

from sqlalchemy import String, DateTime, Text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Context(Base):
    """Cryptographic context with policy and metadata."""

    __tablename__ = "contexts"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    data_examples: Mapped[list[str] | None] = mapped_column(
        ARRAY(String),
        nullable=True
    )
    compliance_tags: Mapped[list[str] | None] = mapped_column(
        ARRAY(String),
        nullable=True
    )
    algorithm: Mapped[str] = mapped_column(
        String(32),
        default="AES-256-GCM"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow
    )

    def __repr__(self) -> str:
        return f"<Context {self.name}>"
