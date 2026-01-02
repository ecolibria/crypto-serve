# Policies API

Manage and evaluate cryptographic policies.

## List Policies

Get all policies for the current tenant.

```
GET /api/policies
```

### Response

```json
{
  "policies": [
    {
      "id": "pol_abc123",
      "name": "require-256-bit",
      "description": "Require 256-bit keys for all contexts",
      "type": "algorithm",
      "rule": {
        "min_key_bits": 256
      },
      "severity": "block",
      "enabled": true,
      "applies_to": ["*"]
    }
  ]
}
```

---

## Get Policy

Get details for a specific policy.

```
GET /api/policies/{id}
```

### Response

```json
{
  "id": "pol_abc123",
  "name": "require-256-bit",
  "description": "Require 256-bit keys for all contexts",
  "type": "algorithm",
  "rule": {
    "min_key_bits": 256,
    "blocked_algorithms": ["AES-128-*", "DES", "3DES"]
  },
  "severity": "block",
  "enabled": true,
  "applies_to": ["*"],
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-15T10:00:00Z"
}
```

---

## Create Policy

Create a new policy.

```
POST /api/policies
```

### Request

```json
{
  "name": "hipaa-encryption",
  "description": "HIPAA encryption requirements",
  "type": "compliance",
  "rule": {
    "require_algorithms": ["AES-256-GCM"],
    "require_audit": true,
    "min_key_bits": 256
  },
  "severity": "block",
  "enabled": true,
  "applies_to": ["health-data"]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Policy name |
| `description` | string | No | Description |
| `type` | string | Yes | `algorithm`, `compliance`, `custom` |
| `rule` | object | Yes | Policy rule definition |
| `severity` | string | Yes | `info`, `warn`, `block` |
| `enabled` | bool | No | Default: true |
| `applies_to` | array | No | Context names or `["*"]` for all |

### Response

```json
{
  "id": "pol_def456",
  "name": "hipaa-encryption",
  "type": "compliance",
  "created_at": "2024-01-15T10:00:00Z"
}
```

---

## Update Policy

Update an existing policy.

```
PUT /api/policies/{id}
```

### Request

```json
{
  "description": "Updated HIPAA requirements",
  "rule": {
    "require_algorithms": ["AES-256-GCM", "AES-256-GCM+ML-KEM-768"],
    "require_audit": true
  },
  "severity": "block"
}
```

---

## Delete Policy

Delete a policy.

```
DELETE /api/policies/{id}
```

---

## Enable/Disable Policy

```
POST /api/policies/{id}/enable
POST /api/policies/{id}/disable
```

---

## Get Default Policies

Get the built-in default policies.

```
GET /api/policies/defaults
```

### Response

```json
{
  "policies": [
    {
      "name": "block-deprecated",
      "description": "Block deprecated algorithms",
      "rule": {
        "blocked_algorithms": ["DES", "3DES", "RC4", "MD5"]
      },
      "severity": "block",
      "builtin": true
    },
    {
      "name": "warn-non-fips",
      "description": "Warn on non-FIPS algorithms in FIPS mode",
      "rule": {
        "condition": "fips_mode == 'preferred'"
      },
      "severity": "warn",
      "builtin": true
    }
  ]
}
```

---

## Evaluate Policy

Test policy evaluation without performing an operation.

```
POST /api/policies/evaluate
```

### Request

```json
{
  "context": "user-pii",
  "algorithm": "AES-128-GCM",
  "operation": "encrypt"
}
```

### Response (Violation)

```json
{
  "allowed": false,
  "violations": [
    {
      "policy": "require-256-bit",
      "severity": "block",
      "message": "Algorithm AES-128-GCM does not meet minimum key size (256 bits)"
    }
  ],
  "warnings": []
}
```

### Response (Allowed with Warnings)

```json
{
  "allowed": true,
  "violations": [],
  "warnings": [
    {
      "policy": "quantum-readiness",
      "severity": "warn",
      "message": "Consider using hybrid PQC for long-term data protection"
    }
  ]
}
```

---

## Simulate Policy

Test a new policy against historical operations.

```
POST /api/policies/simulate
```

### Request

```json
{
  "policy": {
    "name": "test-policy",
    "type": "algorithm",
    "rule": {
      "min_key_bits": 256,
      "blocked_algorithms": ["ChaCha20-*"]
    },
    "severity": "block"
  },
  "sample_size": 1000,
  "time_range": {
    "start": "2024-01-01T00:00:00Z",
    "end": "2024-01-15T00:00:00Z"
  }
}
```

### Response

```json
{
  "total_operations": 1000,
  "would_block": 23,
  "would_warn": 0,
  "would_allow": 977,
  "block_rate": 0.023,
  "affected_contexts": ["legacy-context"],
  "sample_violations": [
    {
      "timestamp": "2024-01-14T15:30:00Z",
      "context": "legacy-context",
      "algorithm": "AES-128-GCM",
      "reason": "Key size 128 < 256"
    }
  ]
}
```

---

## Policy Rules Reference

### Algorithm Policy Rules

```json
{
  "min_key_bits": 256,
  "max_key_bits": 512,
  "allowed_algorithms": ["AES-256-GCM", "AES-256-CBC"],
  "blocked_algorithms": ["DES", "3DES", "RC4"],
  "require_aead": true,
  "require_quantum_resistant": false
}
```

### Compliance Policy Rules

```json
{
  "require_algorithms": ["AES-256-GCM"],
  "require_audit": true,
  "require_key_rotation_days": 365,
  "require_access_logging": true
}
```

### Custom Policy Rules

```json
{
  "expression": "context.sensitivity == 'critical' && !algorithm.quantum_resistant",
  "message": "Critical data should use quantum-resistant encryption"
}
```

---

## Policy Audit

Get policy evaluation history.

```
GET /api/policies/audit
```

### Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `policy_id` | string | Filter by policy |
| `result` | string | `allowed`, `blocked`, `warned` |
| `context` | string | Filter by context |
| `limit` | int | Max results |

### Response

```json
{
  "evaluations": [
    {
      "timestamp": "2024-01-15T15:30:00Z",
      "policy": "require-256-bit",
      "context": "legacy-context",
      "algorithm": "AES-128-GCM",
      "result": "blocked",
      "identity_id": "id_abc123"
    }
  ]
}
```
