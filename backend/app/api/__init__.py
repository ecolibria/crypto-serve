"""API routes."""

from app.api.identities import router as identities_router
from app.api.contexts import router as contexts_router
from app.api.crypto import router as crypto_router
from app.api.users import router as users_router
from app.api.audit import router as audit_router
from app.api.policies import router as policies_router

__all__ = [
    "identities_router",
    "contexts_router",
    "crypto_router",
    "users_router",
    "audit_router",
    "policies_router",
]
