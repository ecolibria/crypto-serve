# Production Deployment Guide

This guide covers deploying CryptoServe in production environments.

## Pre-Deployment Checklist

- [ ] Generate secure master key (32+ bytes)
- [ ] Configure KMS integration
- [ ] Set up PostgreSQL (not SQLite)
- [ ] Configure TLS termination
- [ ] Set up monitoring and alerting
- [ ] Configure log aggregation
- [ ] Review security settings
- [ ] Test disaster recovery

---

## Infrastructure

### Docker Compose (Simple)

```yaml
version: '3.8'
services:
  backend:
    image: cryptoserve/backend:latest
    environment:
      - DATABASE_URL=postgresql+asyncpg://user:pass@db:5432/cryptoserve
      - KMS_PROVIDER=aws
      - AWS_KMS_KEY_ID=arn:aws:kms:...
      - FIPS_MODE=enabled
    deploy:
      replicas: 3

  db:
    image: postgres:15
    volumes:
      - postgres_data:/var/lib/postgresql/data

  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./certs:/etc/ssl/certs
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cryptoserve
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: backend
        image: cryptoserve/backend:latest
        envFrom:
        - secretRef:
            name: cryptoserve-secrets
        resources:
          limits:
            cpu: "2"
            memory: "2Gi"
```

---

## KMS Integration

### AWS KMS

```bash
# Environment variables
KMS_PROVIDER=aws
AWS_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789:key/abc123
AWS_REGION=us-east-1
```

### Google Cloud KMS

```bash
KMS_PROVIDER=gcp
GCP_KMS_KEY_ID=projects/myproject/locations/global/keyRings/myring/cryptoKeys/mykey
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
```

---

## Security Configuration

### TLS

Always use TLS in production:

```nginx
server {
    listen 443 ssl http2;
    ssl_certificate /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
}
```

### FIPS Mode

Enable for regulated environments:

```bash
FIPS_MODE=enabled
```

### Rate Limiting

```bash
RATE_LIMIT_ENABLED=true
RATE_LIMIT_PER_MINUTE=1000
```

---

## Monitoring

### Prometheus Metrics

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'cryptoserve'
    static_configs:
      - targets: ['cryptoserve:8001']
    metrics_path: '/api/admin/metrics'
```

### Key Metrics

| Metric | Alert Threshold |
|--------|-----------------|
| `cryptoserve_error_rate` | > 1% |
| `cryptoserve_latency_p99` | > 100ms |
| `cryptoserve_active_connections` | > 80% capacity |

---

## Backup & Recovery

### Database Backup

```bash
# Daily backup
pg_dump cryptoserve > backup-$(date +%Y%m%d).sql
```

### Key Recovery

Document KMS key recovery procedures. Test annually.

---

## Scaling

### Horizontal Scaling

The API is stateless. Scale replicas based on load:

```yaml
autoscaling:
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilization: 70
```

### Database Connection Pooling

Use pgbouncer for high-concurrency:

```ini
[pgbouncer]
pool_mode = transaction
max_client_conn = 1000
default_pool_size = 20
```
