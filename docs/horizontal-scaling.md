# Horizontal Scaling Guide

This guide explains how to deploy CryptoServe across multiple instances for high availability and throughput.

## Architecture Overview

```
                    ┌─────────────┐
                    │   Clients   │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │    Nginx    │
                    │ Load Balancer│
                    └──────┬──────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
    ┌─────▼─────┐    ┌─────▼─────┐    ┌─────▼─────┐
    │ Backend 1 │    │ Backend 2 │    │ Backend N │
    └─────┬─────┘    └─────┬─────┘    └─────┬─────┘
          │                │                │
          └────────────────┼────────────────┘
                           │
              ┌────────────┴────────────┐
              │                         │
        ┌─────▼─────┐             ┌─────▼─────┐
        │ PostgreSQL│             │   Redis   │
        │ (Primary) │             │ (Cache)   │
        └───────────┘             └───────────┘
```

## Prerequisites

- Docker and Docker Compose
- PostgreSQL 14+ (shared database)
- Redis 7+ (for distributed rate limiting)

## Quick Start

```bash
# Start with 3 backend instances
docker compose -f docker-compose.scale.yml up --scale backend=3

# Scale up to 5 instances
docker compose -f docker-compose.scale.yml up --scale backend=5 -d
```

## Configuration

### Required Environment Variables

All instances must share these values:

```bash
# Database (all instances connect to same DB)
DATABASE_URL=postgresql+asyncpg://user:pass@db-host:5432/cryptoserve

# Redis (required for distributed rate limiting)
REDIS_URL=redis://redis-host:6379/0

# Security (MUST be identical across all instances)
CRYPTOSERVE_MASTER_KEY=<64-char-hex-key>
JWT_SECRET_KEY=<strong-random-secret>
HKDF_SALT=<unique-deployment-salt>
```

### Database Connection Pool

Configure per-instance connection limits:

```bash
DB_POOL_SIZE=10       # Base connections per instance
DB_MAX_OVERFLOW=20    # Extra connections under load
DB_POOL_RECYCLE=3600  # Recycle after 1 hour (cloud DB timeout)
```

**Formula**: Total DB connections = `N instances × (pool_size + max_overflow)`

Example: 5 instances × 30 connections = 150 max connections

### Rate Limiting

Rate limits are enforced across all instances via Redis:

| Limit Type | Default | Description |
|------------|---------|-------------|
| Per-IP | 200/min | Protects against single-source abuse |
| Per-Identity | 100/min | Fair usage per authenticated user |
| Per-Context | 500/min | Context-specific limits |

Configure via admin API:
```bash
PUT /api/admin/rate-limits/context/sensitive-data
{
  "requests_per_minute": 50,
  "burst_size": 10,
  "enabled": true
}
```

## Health Checks

Use these endpoints for load balancer configuration:

| Endpoint | Purpose | Response Time | Use For |
|----------|---------|---------------|---------|
| `/health/live` | Liveness | <10ms | K8s liveness probe |
| `/health/ready` | Readiness | <100ms | K8s readiness probe |
| `/health/deep` | Full diagnostic | <500ms | Debugging |

### Kubernetes Probe Example

```yaml
livenessProbe:
  httpGet:
    path: /health/live
    port: 8003
  initialDelaySeconds: 10
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /health/ready
    port: 8003
  initialDelaySeconds: 5
  periodSeconds: 5
  failureThreshold: 3
```

## Graceful Shutdown

CryptoServe handles SIGTERM gracefully:

1. Stop accepting new connections
2. Complete in-flight requests (30s timeout)
3. Close database connections
4. Exit cleanly

Configure timeout via uvicorn:
```bash
uvicorn app.main:app --timeout-graceful-shutdown 30
```

## Nginx Load Balancer

The included `nginx.scale.conf` provides:

- **Least-connections** load balancing (optimal for varying request times)
- **Connection keepalive** to reduce overhead
- **Health check proxying** for external LBs
- **Rate limit header passthrough**

## Scaling Recommendations

### Instance Sizing

| Load Level | Instances | Memory/Instance | DB Pool Size |
|------------|-----------|-----------------|--------------|
| Light (<100 RPS) | 2 | 256MB | 5 |
| Medium (<1000 RPS) | 3-5 | 512MB | 10 |
| Heavy (<5000 RPS) | 5-10 | 1GB | 15 |
| Enterprise (>5000 RPS) | 10+ | 2GB | 20 |

### Database Sizing

```
max_connections = (instances × pool_size × 1.5) + 50 (admin headroom)
```

For 10 instances with pool_size=10:
```
max_connections = (10 × 10 × 1.5) + 50 = 200
```

### Redis Sizing

Rate limiting uses minimal memory (~100 bytes per active limit bucket):
- 10,000 active identities: ~1MB
- 100,000 active identities: ~10MB

Recommended: 128MB minimum, 512MB for production.

## Monitoring

### Key Metrics

| Metric | Source | Alert Threshold |
|--------|--------|-----------------|
| Request latency P95 | Nginx logs | >200ms |
| DB connection pool usage | `/health/deep` | >80% |
| Rate limit violations | Audit logs | >100/min |
| Error rate | Application logs | >1% |

### Structured Logging

All instances log with instance ID for tracing:
```json
{
  "timestamp": "2025-01-01T12:00:00Z",
  "level": "info",
  "message": "Request completed",
  "instance_id": "backend-3",
  "request_id": "abc-123",
  "latency_ms": 45
}
```

## Troubleshooting

### Rate Limits Not Shared

**Symptom**: Each instance enforces separate rate limits.

**Cause**: Redis not configured.

**Fix**: Set `REDIS_URL` environment variable.

### Connection Pool Exhaustion

**Symptom**: "connection pool exhausted" errors.

**Fix**:
1. Increase `DB_MAX_OVERFLOW`
2. Reduce instance count
3. Increase PostgreSQL `max_connections`

### Inconsistent Encryption

**Symptom**: Decrypt fails for data encrypted by different instance.

**Cause**: Different `CRYPTOSERVE_MASTER_KEY` values.

**Fix**: Ensure all instances use identical master key.

## Security Considerations

1. **Shared secrets**: All instances MUST use identical:
   - `CRYPTOSERVE_MASTER_KEY`
   - `JWT_SECRET_KEY`
   - `HKDF_SALT`

2. **Network isolation**: Backend instances should only be accessible via load balancer.

3. **Database access**: Use separate credentials per environment, not shared across prod/staging.

4. **Redis security**: Enable AUTH if Redis is network-accessible.
