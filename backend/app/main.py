"""CryptoServe Backend - Main FastAPI Application."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from app.config import get_settings
from app.database import init_db, close_db, get_session_maker
from app.auth import github_oauth_router
from app.api import (
    identities_router,
    contexts_router,
    crypto_router,
    users_router,
    audit_router,
)
from app.api.sdk import router as sdk_router
from app.api.admin import router as admin_router
from app.models import Context

settings = get_settings()


async def seed_default_contexts():
    """Seed default contexts if they don't exist."""
    default_contexts = [
        {
            "name": "user-pii",
            "display_name": "User Personal Data",
            "description": "Personally identifiable information that can identify an individual",
            "data_examples": ["email", "phone", "SSN", "address", "date of birth", "full name"],
            "compliance_tags": ["GDPR", "CCPA"],
            "algorithm": "AES-256-GCM",
        },
        {
            "name": "payment-data",
            "display_name": "Payment & Financial",
            "description": "Payment card data and financial account information",
            "data_examples": ["credit card number", "bank account", "CVV", "billing address"],
            "compliance_tags": ["PCI-DSS"],
            "algorithm": "AES-256-GCM",
        },
        {
            "name": "session-tokens",
            "display_name": "Session & Auth Tokens",
            "description": "Temporary authentication and session data",
            "data_examples": ["JWT tokens", "session IDs", "refresh tokens", "API keys"],
            "compliance_tags": [],
            "algorithm": "AES-256-GCM",
        },
        {
            "name": "health-data",
            "display_name": "Health Information",
            "description": "Protected health information and medical records",
            "data_examples": ["diagnosis", "prescriptions", "medical history", "insurance ID"],
            "compliance_tags": ["HIPAA"],
            "algorithm": "AES-256-GCM",
        },
        {
            "name": "general",
            "display_name": "General Purpose",
            "description": "General purpose encryption for miscellaneous sensitive data",
            "data_examples": ["internal IDs", "configuration secrets", "API responses"],
            "compliance_tags": [],
            "algorithm": "AES-256-GCM",
        },
    ]

    async with get_session_maker()() as db:
        for ctx_data in default_contexts:
            result = await db.execute(
                select(Context).where(Context.name == ctx_data["name"])
            )
            existing = result.scalar_one_or_none()

            if not existing:
                context = Context(**ctx_data)
                db.add(context)

        await db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup
    await init_db()
    await seed_default_contexts()
    yield
    # Shutdown
    await close_db()


app = FastAPI(
    title="CryptoServe",
    description="Cryptographic operations server with personalized SDK distribution",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_url],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(github_oauth_router)
app.include_router(users_router)
app.include_router(identities_router)
app.include_router(contexts_router)
app.include_router(crypto_router)
app.include_router(audit_router)
app.include_router(sdk_router)
app.include_router(admin_router)


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": "CryptoServe",
        "version": "0.1.0",
        "docs": "/docs",
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}
