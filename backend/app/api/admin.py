"""Admin API routes for enterprise dashboard."""

from datetime import datetime, timedelta
from typing import Annotated, Optional
import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select, func, desc, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.database import get_db
from app.auth.jwt import get_current_user
from app.models import User, Identity, IdentityStatus, Context, AuditLog, Key

router = APIRouter(prefix="/api/admin", tags=["admin"])


# --- Pydantic Schemas ---

class AdminDashboardStats(BaseModel):
    """Aggregate statistics for admin dashboard."""
    total_users: int
    new_users_today: int
    total_identities: int
    active_identities: int
    expiring_soon: int  # Within 7 days
    total_operations: int
    operations_today: int
    operations_yesterday: int
    successful_operations: int
    failed_operations: int
    avg_latency_ms: float
    total_data_bytes: int
    contexts_count: int


class UserSummary(BaseModel):
    """User summary for admin listing."""
    id: str
    github_username: str
    email: Optional[str]
    avatar_url: Optional[str]
    created_at: datetime
    last_login_at: Optional[datetime]
    is_admin: bool
    identity_count: int
    operation_count: int


class IdentitySummary(BaseModel):
    """Identity summary for admin listing."""
    id: str
    name: str
    team: str
    environment: str
    type: str
    status: str
    allowed_contexts: list[str]
    created_at: datetime
    expires_at: datetime
    last_used_at: Optional[datetime]
    user_id: str
    user_name: str
    operation_count: int


class ContextStats(BaseModel):
    """Context with usage statistics."""
    name: str
    display_name: str
    description: str
    algorithm: str
    compliance_tags: list[str]
    data_examples: list[str]
    created_at: datetime
    operation_count: int
    identity_count: int
    last_key_rotation: Optional[datetime]
    key_version: int


class TrendDataPoint(BaseModel):
    """Single data point for trend charts."""
    date: str
    encrypt_count: int
    decrypt_count: int
    success_count: int
    failed_count: int


class TeamUsage(BaseModel):
    """Team usage statistics."""
    team: str
    operation_count: int
    identity_count: int


class HealthStatus(BaseModel):
    """System health status."""
    database: str
    encryption_service: str
    expiring_identities: int
    failed_operations_last_hour: int
    avg_latency_last_hour: float


# --- Auth Dependency ---

async def require_admin(
    user: Annotated[User, Depends(get_current_user)]
) -> User:
    """Verify user has admin privileges."""
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return user


# --- Admin Dashboard ---

@router.get("/dashboard", response_model=AdminDashboardStats)
async def get_admin_dashboard(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get aggregate statistics for admin dashboard."""
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    yesterday_start = today_start - timedelta(days=1)
    week_from_now = now + timedelta(days=7)

    # User stats
    total_users = await db.scalar(select(func.count(User.id)))
    new_users_today = await db.scalar(
        select(func.count(User.id)).where(User.created_at >= today_start)
    )

    # Identity stats
    total_identities = await db.scalar(select(func.count(Identity.id)))
    active_identities = await db.scalar(
        select(func.count(Identity.id)).where(
            and_(
                Identity.status == IdentityStatus.ACTIVE,
                Identity.expires_at > now
            )
        )
    )
    expiring_soon = await db.scalar(
        select(func.count(Identity.id)).where(
            and_(
                Identity.status == IdentityStatus.ACTIVE,
                Identity.expires_at > now,
                Identity.expires_at <= week_from_now
            )
        )
    )

    # Operations stats
    total_operations = await db.scalar(select(func.count(AuditLog.id)))
    operations_today = await db.scalar(
        select(func.count(AuditLog.id)).where(AuditLog.timestamp >= today_start)
    )
    operations_yesterday = await db.scalar(
        select(func.count(AuditLog.id)).where(
            and_(
                AuditLog.timestamp >= yesterday_start,
                AuditLog.timestamp < today_start
            )
        )
    )
    successful_operations = await db.scalar(
        select(func.count(AuditLog.id)).where(AuditLog.success == True)
    )
    failed_operations = await db.scalar(
        select(func.count(AuditLog.id)).where(AuditLog.success == False)
    )

    # Average latency
    avg_latency = await db.scalar(
        select(func.avg(AuditLog.latency_ms)).where(AuditLog.latency_ms.isnot(None))
    )

    # Total data processed
    total_input = await db.scalar(
        select(func.sum(AuditLog.input_size_bytes)).where(AuditLog.input_size_bytes.isnot(None))
    ) or 0
    total_output = await db.scalar(
        select(func.sum(AuditLog.output_size_bytes)).where(AuditLog.output_size_bytes.isnot(None))
    ) or 0

    # Context count
    contexts_count = await db.scalar(select(func.count(Context.name)))

    return AdminDashboardStats(
        total_users=total_users or 0,
        new_users_today=new_users_today or 0,
        total_identities=total_identities or 0,
        active_identities=active_identities or 0,
        expiring_soon=expiring_soon or 0,
        total_operations=total_operations or 0,
        operations_today=operations_today or 0,
        operations_yesterday=operations_yesterday or 0,
        successful_operations=successful_operations or 0,
        failed_operations=failed_operations or 0,
        avg_latency_ms=round(avg_latency or 0, 2),
        total_data_bytes=total_input + total_output,
        contexts_count=contexts_count or 0,
    )


# --- User Management ---

@router.get("/users", response_model=list[UserSummary])
async def list_all_users(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
    search: Optional[str] = Query(None, description="Search by username or email"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """List all users with statistics."""
    query = select(User).order_by(desc(User.created_at))

    if search:
        query = query.where(
            or_(
                User.github_username.ilike(f"%{search}%"),
                User.email.ilike(f"%{search}%")
            )
        )

    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    users = result.scalars().all()

    summaries = []
    for user in users:
        # Count identities
        identity_count = await db.scalar(
            select(func.count(Identity.id)).where(Identity.user_id == user.id)
        )
        # Count operations
        identity_ids_result = await db.execute(
            select(Identity.id).where(Identity.user_id == user.id)
        )
        identity_ids = [r[0] for r in identity_ids_result.fetchall()]

        operation_count = 0
        if identity_ids:
            operation_count = await db.scalar(
                select(func.count(AuditLog.id)).where(
                    AuditLog.identity_id.in_(identity_ids)
                )
            ) or 0

        summaries.append(UserSummary(
            id=user.id,
            github_username=user.github_username,
            email=user.email,
            avatar_url=user.avatar_url,
            created_at=user.created_at,
            last_login_at=user.last_login_at,
            is_admin=user.is_admin,
            identity_count=identity_count or 0,
            operation_count=operation_count,
        ))

    return summaries


@router.get("/users/{user_id}")
async def get_user_details(
    user_id: str,
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get detailed user information."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Get user's identities
    identities_result = await db.execute(
        select(Identity).where(Identity.user_id == user_id).order_by(desc(Identity.created_at))
    )
    identities = identities_result.scalars().all()

    return {
        "user": {
            "id": user.id,
            "github_username": user.github_username,
            "email": user.email,
            "avatar_url": user.avatar_url,
            "created_at": user.created_at.isoformat(),
            "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
            "is_admin": user.is_admin,
        },
        "identities": [
            {
                "id": i.id,
                "name": i.name,
                "team": i.team,
                "environment": i.environment,
                "type": i.type.value,
                "status": i.status.value,
                "allowed_contexts": i.allowed_contexts,
                "created_at": i.created_at.isoformat(),
                "expires_at": i.expires_at.isoformat(),
            }
            for i in identities
        ],
    }


# --- Identity Management ---

@router.get("/identities", response_model=list[IdentitySummary])
async def list_all_identities(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
    search: Optional[str] = Query(None, description="Search by name, team, or ID"),
    status_filter: Optional[str] = Query(None, alias="status"),
    team: Optional[str] = Query(None),
    environment: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """List all identities across all users."""
    query = select(Identity, User).join(User).order_by(desc(Identity.created_at))

    if search:
        query = query.where(
            or_(
                Identity.name.ilike(f"%{search}%"),
                Identity.team.ilike(f"%{search}%"),
                Identity.id.ilike(f"%{search}%")
            )
        )

    if status_filter:
        try:
            status_enum = IdentityStatus(status_filter)
            query = query.where(Identity.status == status_enum)
        except ValueError:
            pass

    if team:
        query = query.where(Identity.team == team)

    if environment:
        query = query.where(Identity.environment == environment)

    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    rows = result.fetchall()

    summaries = []
    for identity, user in rows:
        # Count operations for this identity
        operation_count = await db.scalar(
            select(func.count(AuditLog.id)).where(AuditLog.identity_id == identity.id)
        ) or 0

        summaries.append(IdentitySummary(
            id=identity.id,
            name=identity.name,
            team=identity.team,
            environment=identity.environment,
            type=identity.type.value,
            status=identity.status.value,
            allowed_contexts=identity.allowed_contexts,
            created_at=identity.created_at,
            expires_at=identity.expires_at,
            last_used_at=identity.last_used_at,
            user_id=user.id,
            user_name=user.github_username,
            operation_count=operation_count,
        ))

    return summaries


@router.delete("/identities/{identity_id}")
async def admin_revoke_identity(
    identity_id: str,
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Admin revoke an identity."""
    result = await db.execute(select(Identity).where(Identity.id == identity_id))
    identity = result.scalar_one_or_none()

    if not identity:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Identity not found",
        )

    identity.status = IdentityStatus.REVOKED
    await db.commit()

    return {"message": f"Identity {identity_id} revoked"}


# --- Global Audit ---

@router.get("/audit/global")
async def get_global_audit_logs(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
    identity_id: Optional[str] = Query(None),
    context: Optional[str] = Query(None),
    operation: Optional[str] = Query(None),
    success: Optional[bool] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Get global audit logs with filtering."""
    query = select(AuditLog).order_by(desc(AuditLog.timestamp))

    if identity_id:
        query = query.where(AuditLog.identity_id == identity_id)
    if context:
        query = query.where(AuditLog.context == context)
    if operation:
        query = query.where(AuditLog.operation == operation)
    if success is not None:
        query = query.where(AuditLog.success == success)
    if start_date:
        query = query.where(AuditLog.timestamp >= start_date)
    if end_date:
        query = query.where(AuditLog.timestamp <= end_date)

    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    logs = result.scalars().all()

    return [
        {
            "id": log.id,
            "timestamp": log.timestamp.isoformat(),
            "operation": log.operation,
            "context": log.context,
            "success": log.success,
            "error_message": log.error_message,
            "identity_id": log.identity_id,
            "identity_name": log.identity_name,
            "team": log.team,
            "input_size_bytes": log.input_size_bytes,
            "output_size_bytes": log.output_size_bytes,
            "latency_ms": log.latency_ms,
            "ip_address": log.ip_address,
        }
        for log in logs
    ]


@router.get("/audit/export")
async def export_audit_logs(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
    format: str = Query("csv", regex="^(csv|json)$"),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    limit: int = Query(10000, ge=1, le=100000),
):
    """Export audit logs as CSV or JSON."""
    query = select(AuditLog).order_by(desc(AuditLog.timestamp))

    if start_date:
        query = query.where(AuditLog.timestamp >= start_date)
    if end_date:
        query = query.where(AuditLog.timestamp <= end_date)

    query = query.limit(limit)
    result = await db.execute(query)
    logs = result.scalars().all()

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "timestamp", "operation", "context", "success", "error_message",
            "identity_id", "identity_name", "team", "input_size_bytes",
            "output_size_bytes", "latency_ms", "ip_address"
        ])
        for log in logs:
            writer.writerow([
                log.timestamp.isoformat(),
                log.operation,
                log.context,
                log.success,
                log.error_message or "",
                log.identity_id,
                log.identity_name or "",
                log.team or "",
                log.input_size_bytes or "",
                log.output_size_bytes or "",
                log.latency_ms or "",
                log.ip_address or "",
            ])

        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=audit_logs.csv"}
        )
    else:
        import json
        data = [
            {
                "timestamp": log.timestamp.isoformat(),
                "operation": log.operation,
                "context": log.context,
                "success": log.success,
                "error_message": log.error_message,
                "identity_id": log.identity_id,
                "identity_name": log.identity_name,
                "team": log.team,
                "input_size_bytes": log.input_size_bytes,
                "output_size_bytes": log.output_size_bytes,
                "latency_ms": log.latency_ms,
                "ip_address": log.ip_address,
            }
            for log in logs
        ]
        return StreamingResponse(
            iter([json.dumps(data, indent=2)]),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=audit_logs.json"}
        )


# --- Context Management ---

@router.get("/contexts", response_model=list[ContextStats])
async def get_contexts_with_stats(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get all contexts with usage statistics."""
    result = await db.execute(select(Context))
    contexts = result.scalars().all()

    stats = []
    for ctx in contexts:
        # Count operations
        operation_count = await db.scalar(
            select(func.count(AuditLog.id)).where(AuditLog.context == ctx.name)
        ) or 0

        # Count identities that have access
        # This requires checking the allowed_contexts array
        identity_count = await db.scalar(
            select(func.count(Identity.id)).where(
                Identity.allowed_contexts.contains([ctx.name])
            )
        ) or 0

        # Get latest key info
        key_result = await db.execute(
            select(Key).where(Key.context == ctx.name).order_by(desc(Key.version)).limit(1)
        )
        latest_key = key_result.scalar_one_or_none()

        stats.append(ContextStats(
            name=ctx.name,
            display_name=ctx.display_name,
            description=ctx.description,
            algorithm=ctx.algorithm,
            compliance_tags=ctx.compliance_tags or [],
            data_examples=ctx.data_examples or [],
            created_at=ctx.created_at,
            operation_count=operation_count,
            identity_count=identity_count,
            last_key_rotation=latest_key.created_at if latest_key else None,
            key_version=latest_key.version if latest_key else 0,
        ))

    return stats


@router.post("/contexts/{context_name}/rotate-key")
async def rotate_context_key(
    context_name: str,
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Trigger key rotation for a context."""
    # Verify context exists
    result = await db.execute(select(Context).where(Context.name == context_name))
    context = result.scalar_one_or_none()

    if not context:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Context not found",
        )

    # Get current key version
    key_result = await db.execute(
        select(Key).where(Key.context == context_name).order_by(desc(Key.version)).limit(1)
    )
    current_key = key_result.scalar_one_or_none()
    new_version = (current_key.version + 1) if current_key else 1

    # Create new key (actual key material is generated by KeyManager)
    from app.core.key_manager import key_manager
    new_key = await key_manager.rotate_key(db, context_name)

    return {
        "message": f"Key rotated for context {context_name}",
        "new_version": new_key.version,
    }


# --- Analytics ---

@router.get("/analytics/trends", response_model=list[TrendDataPoint])
async def get_operation_trends(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
    days: int = Query(30, ge=1, le=365),
):
    """Get operation trends over time."""
    now = datetime.utcnow()
    start_date = now - timedelta(days=days)

    trends = []
    current_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)

    while current_date <= now:
        next_date = current_date + timedelta(days=1)

        # Get counts for this day
        encrypt_count = await db.scalar(
            select(func.count(AuditLog.id)).where(
                and_(
                    AuditLog.timestamp >= current_date,
                    AuditLog.timestamp < next_date,
                    AuditLog.operation == "encrypt"
                )
            )
        ) or 0

        decrypt_count = await db.scalar(
            select(func.count(AuditLog.id)).where(
                and_(
                    AuditLog.timestamp >= current_date,
                    AuditLog.timestamp < next_date,
                    AuditLog.operation == "decrypt"
                )
            )
        ) or 0

        success_count = await db.scalar(
            select(func.count(AuditLog.id)).where(
                and_(
                    AuditLog.timestamp >= current_date,
                    AuditLog.timestamp < next_date,
                    AuditLog.success == True
                )
            )
        ) or 0

        failed_count = await db.scalar(
            select(func.count(AuditLog.id)).where(
                and_(
                    AuditLog.timestamp >= current_date,
                    AuditLog.timestamp < next_date,
                    AuditLog.success == False
                )
            )
        ) or 0

        trends.append(TrendDataPoint(
            date=current_date.strftime("%Y-%m-%d"),
            encrypt_count=encrypt_count,
            decrypt_count=decrypt_count,
            success_count=success_count,
            failed_count=failed_count,
        ))

        current_date = next_date

    return trends


@router.get("/analytics/teams", response_model=list[TeamUsage])
async def get_team_usage(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = Query(10, ge=1, le=50),
):
    """Get usage statistics by team."""
    # Get teams from identities
    teams_result = await db.execute(
        select(Identity.team, func.count(Identity.id).label("identity_count"))
        .group_by(Identity.team)
        .order_by(desc("identity_count"))
        .limit(limit)
    )
    teams = teams_result.fetchall()

    usage = []
    for team_name, identity_count in teams:
        # Get operation count for this team
        operation_count = await db.scalar(
            select(func.count(AuditLog.id)).where(AuditLog.team == team_name)
        ) or 0

        usage.append(TeamUsage(
            team=team_name,
            operation_count=operation_count,
            identity_count=identity_count,
        ))

    return usage


# --- Health ---

@router.get("/health", response_model=HealthStatus)
async def get_system_health(
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get system health status."""
    now = datetime.utcnow()
    hour_ago = now - timedelta(hours=1)
    week_from_now = now + timedelta(days=7)

    # Check database
    try:
        await db.execute(select(func.count(User.id)))
        db_status = "healthy"
    except Exception:
        db_status = "unhealthy"

    # Expiring identities
    expiring = await db.scalar(
        select(func.count(Identity.id)).where(
            and_(
                Identity.status == IdentityStatus.ACTIVE,
                Identity.expires_at > now,
                Identity.expires_at <= week_from_now
            )
        )
    ) or 0

    # Failed operations last hour
    failed_last_hour = await db.scalar(
        select(func.count(AuditLog.id)).where(
            and_(
                AuditLog.timestamp >= hour_ago,
                AuditLog.success == False
            )
        )
    ) or 0

    # Average latency last hour
    avg_latency = await db.scalar(
        select(func.avg(AuditLog.latency_ms)).where(
            and_(
                AuditLog.timestamp >= hour_ago,
                AuditLog.latency_ms.isnot(None)
            )
        )
    ) or 0

    return HealthStatus(
        database=db_status,
        encryption_service="healthy",  # Could add actual check
        expiring_identities=expiring,
        failed_operations_last_hour=failed_last_hour,
        avg_latency_last_hour=round(avg_latency, 2),
    )
