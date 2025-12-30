"""Policy Management API routes.

Provides CRUD operations for cryptographic policies and policy evaluation testing.
"""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.auth.jwt import get_current_user
from app.models import User, Policy, PolicyViolationLog
from app.schemas.policy import (
    PolicyCreate,
    PolicyUpdate,
    PolicyResponse,
    PolicyListResponse,
    EvaluationRequest,
    EvaluationResponse,
    PolicyEvaluationResult,
    ViolationLogResponse,
    ViolationSummary,
)
from app.core.policy_engine import (
    PolicyEngine,
    EvaluationContext,
    PolicySeverity as EnginePolicySeverity,
    Policy as EnginePolicy,
)
from app.core.crypto_registry import crypto_registry

router = APIRouter(prefix="/api/policies", tags=["policies"])


# =============================================================================
# Helper Functions
# =============================================================================

def db_policy_to_engine_policy(db_policy: Policy) -> EnginePolicy:
    """Convert a database Policy to a PolicyEngine Policy."""
    return EnginePolicy(
        name=db_policy.name,
        description=db_policy.description or "",
        rule=db_policy.rule,
        severity=EnginePolicySeverity(db_policy.severity),
        message=db_policy.message,
        enabled=db_policy.enabled,
        contexts=db_policy.contexts or [],
        operations=db_policy.operations or [],
    )


def build_test_context(req: EvaluationRequest, algo_info: dict) -> EvaluationContext:
    """Build an EvaluationContext for testing from a request."""
    # Determine audit level based on sensitivity and frameworks
    audit_level = "standard"
    if req.sensitivity == "critical" or "HIPAA" in req.frameworks or "PCI-DSS" in req.frameworks:
        audit_level = "full"
    elif req.sensitivity == "high":
        audit_level = "detailed"
    elif req.sensitivity == "low":
        audit_level = "minimal"

    return EvaluationContext(
        algorithm={
            "name": algo_info["name"],
            "key_bits": algo_info["key_bits"],
            "quantum_resistant": algo_info["quantum_resistant"],
            "hardware_acceleration": algo_info.get("hardware_acceleration", False),
        },
        context={
            "name": req.context_name,
            "sensitivity": req.sensitivity,
            "pii": req.pii,
            "phi": req.phi,
            "pci": req.pci,
            "frameworks": req.frameworks,
            "protection_lifetime_years": req.protection_lifetime_years,
            "audit_level": audit_level,
            "frequency": "medium",
        },
        identity={
            "team": req.team,
        },
        operation=req.operation,
    )


# =============================================================================
# CRUD Endpoints
# =============================================================================

@router.get("", response_model=list[PolicyListResponse])
async def list_policies(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    enabled_only: bool = Query(False, description="Only return enabled policies"),
    severity: str | None = Query(None, description="Filter by severity (block, warn, info)"),
):
    """List all policies with optional filtering."""
    query = select(Policy).order_by(Policy.name)

    if enabled_only:
        query = query.where(Policy.enabled == True)

    if severity:
        query = query.where(Policy.severity == severity)

    result = await db.execute(query)
    policies = result.scalars().all()
    return policies


@router.post("", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(
    data: PolicyCreate,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Create a new policy.

    The rule syntax supports:
    - Comparisons: ==, !=, >, >=, <, <=
    - Membership: in, not in, contains
    - Boolean: and, or, not
    - Parentheses for grouping
    - Dot notation: algorithm.key_bits, context.sensitivity, etc.

    Example rules:
    - "algorithm.key_bits >= 256"
    - "context.sensitivity != 'critical' or algorithm.quantum_resistant == true"
    - "'HIPAA' not in context.frameworks or algorithm.key_bits >= 256"
    """
    # Check if policy already exists
    result = await db.execute(select(Policy).where(Policy.name == data.name))
    existing = result.scalar_one_or_none()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Policy already exists: {data.name}",
        )

    # Validate the rule syntax by testing it
    try:
        engine = PolicyEngine()
        test_policy = EnginePolicy(
            name="test",
            description="",
            rule=data.rule,
            severity=EnginePolicySeverity.INFO,
            message="test",
        )
        engine.add_policy(test_policy)

        # Try to evaluate with a dummy context
        test_context = EvaluationContext(
            algorithm={"name": "AES-256-GCM", "key_bits": 256, "quantum_resistant": False},
            context={"name": "test", "sensitivity": "medium", "pii": False, "frameworks": []},
            identity={"team": "test"},
            operation="encrypt",
        )
        engine.evaluate(test_context, raise_on_block=False)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid rule syntax: {e}",
        )

    # Validate operations
    valid_operations = ["encrypt", "decrypt"]
    for op in data.operations:
        if op not in valid_operations:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid operation '{op}'. Must be one of: {valid_operations}",
            )

    policy = Policy(
        name=data.name,
        description=data.description,
        rule=data.rule,
        severity=data.severity.value,
        message=data.message,
        enabled=data.enabled,
        contexts=data.contexts if data.contexts else None,
        operations=data.operations if data.operations else None,
        policy_metadata=data.policy_metadata,
        created_by=user.username,
    )

    db.add(policy)
    await db.commit()
    await db.refresh(policy)

    return policy


@router.get("/{name}", response_model=PolicyResponse)
async def get_policy(
    name: str,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get a specific policy by name."""
    result = await db.execute(select(Policy).where(Policy.name == name))
    policy = result.scalar_one_or_none()

    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy not found: {name}",
        )

    return policy


@router.put("/{name}", response_model=PolicyResponse)
async def update_policy(
    name: str,
    data: PolicyUpdate,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Update an existing policy (partial update)."""
    result = await db.execute(select(Policy).where(Policy.name == name))
    policy = result.scalar_one_or_none()

    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy not found: {name}",
        )

    # If rule is being updated, validate it
    if data.rule is not None:
        try:
            engine = PolicyEngine()
            test_policy = EnginePolicy(
                name="test",
                description="",
                rule=data.rule,
                severity=EnginePolicySeverity.INFO,
                message="test",
            )
            engine.add_policy(test_policy)
            test_context = EvaluationContext(
                algorithm={"name": "AES-256-GCM", "key_bits": 256, "quantum_resistant": False},
                context={"name": "test", "sensitivity": "medium", "pii": False, "frameworks": []},
                identity={"team": "test"},
                operation="encrypt",
            )
            engine.evaluate(test_context, raise_on_block=False)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid rule syntax: {e}",
            )

    # Update fields that were provided
    if data.description is not None:
        policy.description = data.description
    if data.rule is not None:
        policy.rule = data.rule
    if data.severity is not None:
        policy.severity = data.severity.value
    if data.message is not None:
        policy.message = data.message
    if data.enabled is not None:
        policy.enabled = data.enabled
    if data.contexts is not None:
        policy.contexts = data.contexts if data.contexts else None
    if data.operations is not None:
        policy.operations = data.operations if data.operations else None
    if data.policy_metadata is not None:
        policy.policy_metadata = data.policy_metadata

    policy.updated_at = datetime.utcnow()

    await db.commit()
    await db.refresh(policy)

    return policy


@router.delete("/{name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(
    name: str,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Delete a policy."""
    result = await db.execute(select(Policy).where(Policy.name == name))
    policy = result.scalar_one_or_none()

    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy not found: {name}",
        )

    await db.delete(policy)
    await db.commit()


@router.post("/{name}/toggle", response_model=PolicyResponse)
async def toggle_policy(
    name: str,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Toggle a policy's enabled status."""
    result = await db.execute(select(Policy).where(Policy.name == name))
    policy = result.scalar_one_or_none()

    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy not found: {name}",
        )

    policy.enabled = not policy.enabled
    policy.updated_at = datetime.utcnow()

    await db.commit()
    await db.refresh(policy)

    return policy


# =============================================================================
# Policy Evaluation (Testing)
# =============================================================================

@router.post("/evaluate", response_model=EvaluationResponse)
async def evaluate_policies(
    data: EvaluationRequest,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    include_defaults: bool = Query(True, description="Include default policies in evaluation"),
):
    """Evaluate policies against a test context.

    This endpoint is useful for testing how policies will behave
    before deploying them to production.
    """
    # Look up algorithm
    algo = crypto_registry.get(data.algorithm)
    if not algo:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown algorithm: {data.algorithm}. Use GET /api/algorithms for available options.",
        )

    algo_info = {
        "name": algo.name,
        "key_bits": algo.security_bits,
        "quantum_resistant": algo.quantum_resistant,
        "hardware_acceleration": algo.hardware_acceleration,
    }

    # Build evaluation context
    eval_context = build_test_context(data, algo_info)

    # Load policies
    engine = PolicyEngine()

    if include_defaults:
        engine.load_default_policies()

    # Load custom policies from database
    result = await db.execute(select(Policy).where(Policy.enabled == True))
    db_policies = result.scalars().all()
    for db_policy in db_policies:
        engine.add_policy(db_policy_to_engine_policy(db_policy))

    # Evaluate
    results = engine.evaluate(eval_context, raise_on_block=False)

    # Collect results
    blocking = 0
    warnings = 0
    infos = 0
    eval_results = []

    for r in results:
        eval_results.append(PolicyEvaluationResult(
            policy_name=r.policy_name,
            passed=r.passed,
            severity=r.severity.value,
            message=r.message if not r.passed else "",
            rule=r.details.get("rule", ""),
        ))

        if not r.passed:
            if r.severity == EnginePolicySeverity.BLOCK:
                blocking += 1
            elif r.severity == EnginePolicySeverity.WARN:
                warnings += 1
            else:
                infos += 1

    return EvaluationResponse(
        algorithm=data.algorithm,
        context=data.context_name,
        allowed=(blocking == 0),
        blocking_violations=blocking,
        warning_violations=warnings,
        info_violations=infos,
        results=eval_results,
    )


# =============================================================================
# Violation Logs
# =============================================================================

@router.get("/violations/logs", response_model=list[ViolationLogResponse])
async def list_violation_logs(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = Query(100, le=1000, description="Maximum number of logs to return"),
    offset: int = Query(0, description="Number of logs to skip"),
    policy_name: str | None = Query(None, description="Filter by policy name"),
    context_name: str | None = Query(None, description="Filter by context name"),
    blocked_only: bool = Query(False, description="Only return blocked violations"),
):
    """Get policy violation logs."""
    query = select(PolicyViolationLog).order_by(desc(PolicyViolationLog.timestamp))

    if policy_name:
        query = query.where(PolicyViolationLog.policy_name == policy_name)
    if context_name:
        query = query.where(PolicyViolationLog.context_name == context_name)
    if blocked_only:
        query = query.where(PolicyViolationLog.blocked == True)

    query = query.offset(offset).limit(limit)

    result = await db.execute(query)
    logs = result.scalars().all()
    return logs


@router.get("/violations/summary", response_model=ViolationSummary)
async def get_violation_summary(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    days: int = Query(7, le=90, description="Number of days to summarize"),
):
    """Get a summary of policy violations."""
    from datetime import timedelta

    cutoff = datetime.utcnow() - timedelta(days=days)

    # Get all violations in the time period
    result = await db.execute(
        select(PolicyViolationLog).where(PolicyViolationLog.timestamp >= cutoff)
    )
    violations = result.scalars().all()

    total = len(violations)
    blocked = sum(1 for v in violations if v.blocked)
    warnings = sum(1 for v in violations if v.severity == "warn" and not v.blocked)
    infos = sum(1 for v in violations if v.severity == "info")

    # Group by policy
    by_policy: dict[str, int] = {}
    for v in violations:
        by_policy[v.policy_name] = by_policy.get(v.policy_name, 0) + 1

    # Group by context
    by_context: dict[str, int] = {}
    for v in violations:
        by_context[v.context_name] = by_context.get(v.context_name, 0) + 1

    # Group by team
    by_team: dict[str, int] = {}
    for v in violations:
        team = v.team or "unknown"
        by_team[team] = by_team.get(team, 0) + 1

    return ViolationSummary(
        total_violations=total,
        blocked_count=blocked,
        warning_count=warnings,
        info_count=infos,
        by_policy=by_policy,
        by_context=by_context,
        by_team=by_team,
    )


# =============================================================================
# Bulk Operations
# =============================================================================

@router.post("/seed-defaults", status_code=status.HTTP_201_CREATED)
async def seed_default_policies(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Seed the default policies to the database.

    This copies the hardcoded default policies into the database
    so they can be customized. Existing policies with the same name
    will not be overwritten.
    """
    engine = PolicyEngine()
    engine.load_default_policies()

    created = []
    skipped = []

    for policy in engine.policies:
        # Check if already exists
        result = await db.execute(select(Policy).where(Policy.name == policy.name))
        existing = result.scalar_one_or_none()

        if existing:
            skipped.append(policy.name)
            continue

        db_policy = Policy(
            name=policy.name,
            description=policy.description,
            rule=policy.rule,
            severity=policy.severity.value,
            message=policy.message,
            enabled=policy.enabled,
            contexts=policy.contexts if policy.contexts else None,
            operations=policy.operations if policy.operations else None,
            created_by=user.username,
        )
        db.add(db_policy)
        created.append(policy.name)

    await db.commit()

    return {
        "message": f"Seeded {len(created)} policies, skipped {len(skipped)} existing",
        "created": created,
        "skipped": skipped,
    }
