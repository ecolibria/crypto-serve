"""GitHub OAuth authentication."""

from datetime import datetime

import httpx
from fastapi import APIRouter, HTTPException, status, Depends, Response
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.models import User
from app.auth.jwt import create_access_token

settings = get_settings()
router = APIRouter(prefix="/auth", tags=["auth"])

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"
GITHUB_EMAILS_URL = "https://api.github.com/user/emails"


@router.get("/dev-login")
async def dev_login(db: AsyncSession = Depends(get_db)):
    """Development mode login - bypasses OAuth for testing."""
    if not settings.dev_mode:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Dev login only available in dev mode",
        )

    # Find or create dev user
    dev_github_id = 1
    result = await db.execute(select(User).where(User.github_id == dev_github_id))
    user = result.scalar_one_or_none()

    if not user:
        user = User(
            github_id=dev_github_id,
            github_username="devuser",
            email="dev@localhost",
            avatar_url=None,
            last_login_at=datetime.utcnow(),
            is_admin=True,  # Dev user is admin in dev mode
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
    else:
        user.last_login_at = datetime.utcnow()
        # Ensure dev user always has admin in dev mode
        if not user.is_admin:
            user.is_admin = True
        await db.commit()

    # Create JWT token
    jwt_token = create_access_token(user.id, user.github_username)

    # Redirect to frontend with token in cookie
    response = RedirectResponse(
        url=f"{settings.frontend_url}/dashboard",
        status_code=status.HTTP_302_FOUND,
    )
    response.set_cookie(
        key="access_token",
        value=jwt_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=settings.jwt_expiration_days * 24 * 60 * 60,
    )
    return response


@router.get("/status")
async def auth_status():
    """Check auth configuration status."""
    return {
        "devMode": settings.dev_mode,
        "githubConfigured": bool(settings.github_client_id),
    }


@router.get("/github")
async def github_login():
    """Redirect to GitHub OAuth authorization."""
    if not settings.github_client_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GitHub OAuth not configured",
        )

    params = {
        "client_id": settings.github_client_id,
        "redirect_uri": f"{settings.backend_url}/auth/github/callback",
        "scope": "read:user user:email",
    }
    query = "&".join(f"{k}={v}" for k, v in params.items())
    return RedirectResponse(f"{GITHUB_AUTHORIZE_URL}?{query}")


@router.get("/github/callback")
async def github_callback(
    code: str,
    db: AsyncSession = Depends(get_db),
):
    """Handle GitHub OAuth callback."""
    if not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing authorization code",
        )

    # Exchange code for access token
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            GITHUB_TOKEN_URL,
            data={
                "client_id": settings.github_client_id,
                "client_secret": settings.github_client_secret,
                "code": code,
            },
            headers={"Accept": "application/json"},
        )

        if token_response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to exchange code for token",
            )

        token_data = token_response.json()
        access_token = token_data.get("access_token")

        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No access token in response",
            )

        # Get user info
        user_response = await client.get(
            GITHUB_USER_URL,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
        )

        if user_response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to get user info",
            )

        github_user = user_response.json()

        # Get primary email
        email = github_user.get("email")
        if not email:
            emails_response = await client.get(
                GITHUB_EMAILS_URL,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )
            if emails_response.status_code == 200:
                emails = emails_response.json()
                primary_email = next(
                    (e for e in emails if e.get("primary")),
                    None
                )
                if primary_email:
                    email = primary_email.get("email")

    # Find or create user
    github_id = github_user["id"]
    result = await db.execute(select(User).where(User.github_id == github_id))
    user = result.scalar_one_or_none()

    if user:
        # Update existing user
        user.github_username = github_user["login"]
        user.email = email
        user.avatar_url = github_user.get("avatar_url")
        user.last_login_at = datetime.utcnow()
    else:
        # Create new user
        user = User(
            github_id=github_id,
            github_username=github_user["login"],
            email=email,
            avatar_url=github_user.get("avatar_url"),
            last_login_at=datetime.utcnow(),
        )
        db.add(user)

    await db.commit()
    await db.refresh(user)

    # Create JWT token
    jwt_token = create_access_token(user.id, user.github_username)

    # Redirect to frontend with token in cookie
    response = RedirectResponse(
        url=f"{settings.frontend_url}/dashboard",
        status_code=status.HTTP_302_FOUND,
    )
    response.set_cookie(
        key="access_token",
        value=jwt_token,
        httponly=True,
        secure=False,  # Set to True in production with HTTPS
        samesite="lax",
        max_age=settings.jwt_expiration_days * 24 * 60 * 60,
    )
    return response


@router.post("/logout")
async def logout(response: Response):
    """Log out by clearing the session cookie."""
    response.delete_cookie("access_token")
    return {"message": "Logged out"}


@router.get("/me")
async def get_me(user: User = Depends(get_db)):
    """Get current user info."""
    from app.auth.jwt import get_current_user
    # This is a placeholder - actual implementation uses dependency
    pass


# Export router
github_oauth_router = router
