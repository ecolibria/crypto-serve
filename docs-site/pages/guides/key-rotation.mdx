# Key Rotation Guide

This guide covers key rotation strategies and implementation.

## Why Rotate Keys?

Key rotation limits the impact of key compromise and meets compliance requirements:

- **Compliance**: PCI-DSS, HIPAA, and SOC 2 require periodic rotation
- **Security**: Limits exposure window if a key is compromised
- **Cryptographic hygiene**: Reduces data encrypted under single key

---

## Rotation Strategies

### Automatic Rotation

CryptoServe supports automatic key rotation:

```bash
# Enable automatic rotation (environment)
KEY_ROTATION_ENABLED=true
KEY_ROTATION_INTERVAL_DAYS=90
```

```python
# Configure via API
from cryptoserve import admin

admin.configure_rotation(
    context="user-pii",
    interval_days=90,
    auto_reencrypt=False  # Keep old ciphertext valid
)
```

### Manual Rotation

Rotate keys on-demand:

```python
from cryptoserve import admin

# Rotate a specific context's key
result = admin.rotate_key(context="user-pii")
print(f"New key version: {result.new_version}")
print(f"Old versions retained: {result.old_versions}")
```

---

## Re-encryption Options

### Lazy Re-encryption (Recommended)

Data is re-encrypted on next access:

```python
# Enable lazy re-encryption
admin.configure_rotation(
    context="user-pii",
    reencrypt_strategy="lazy"
)

# Old ciphertext still decrypts
decrypted = crypto.decrypt(old_ciphertext)  # Works!

# New encryptions use new key
new_ciphertext = crypto.encrypt(data)  # Uses latest key
```

**Advantages:**
- No downtime
- No bulk processing
- Gradual migration

### Bulk Re-encryption

Re-encrypt all data immediately:

```python
# Trigger bulk re-encryption (use with caution)
job = admin.bulk_reencrypt(
    context="user-pii",
    batch_size=1000,
    parallel_workers=4
)

# Monitor progress
while not job.complete:
    print(f"Progress: {job.progress}%")
    time.sleep(10)
```

**Use when:**
- Compliance requires immediate rotation
- Decommissioning old key material
- Key compromise suspected

---

## Key Version Management

### Viewing Key Versions

```python
# List all versions for a context
versions = admin.list_key_versions(context="user-pii")

for v in versions:
    print(f"Version {v.version}: created={v.created_at}, status={v.status}")
```

Output:
```
Version 3: created=2024-01-15, status=active
Version 2: created=2023-10-01, status=decrypt-only
Version 1: created=2023-07-01, status=decrypt-only
```

### Key Version States

| State | Encrypt | Decrypt | Description |
|-------|---------|---------|-------------|
| `active` | Yes | Yes | Current key for new encryptions |
| `decrypt-only` | No | Yes | Old key, can still decrypt |
| `disabled` | No | No | Scheduled for deletion |
| `destroyed` | No | No | Permanently removed |

### Retiring Old Versions

```python
# Mark old version as disabled
admin.disable_key_version(context="user-pii", version=1)

# Permanently destroy (irreversible!)
admin.destroy_key_version(
    context="user-pii",
    version=1,
    confirm="DESTROY-VERSION-1"
)
```

---

## KMS Integration

### AWS KMS Rotation

When using AWS KMS, leverage native rotation:

```python
# AWS KMS handles rotation internally
admin.configure_rotation(
    context="user-pii",
    kms_rotation=True,  # Use KMS automatic rotation
    kms_rotation_days=365
)
```

### Envelope Encryption Rotation

Rotate the Data Encryption Key (DEK) while keeping the Key Encryption Key (KEK):

```python
# Rotate DEK only (fast, no KMS calls for re-encryption)
admin.rotate_key(
    context="user-pii",
    rotate_dek_only=True
)
```

---

## Rotation Monitoring

### Events

Subscribe to rotation events:

```python
from cryptoserve import events

@events.on("key.rotated")
def handle_rotation(event):
    print(f"Key rotated: {event.context}")
    print(f"New version: {event.new_version}")
    # Trigger re-encryption jobs, alerts, etc.

@events.on("key.version_disabled")
def handle_disabled(event):
    # Log for audit
    audit_log.info(f"Key version {event.version} disabled")
```

### Metrics

Monitor rotation health:

```python
# Get rotation metrics
metrics = admin.get_rotation_metrics(context="user-pii")

print(f"Current version: {metrics.current_version}")
print(f"Ciphertext on old versions: {metrics.old_version_count}")
print(f"Days since last rotation: {metrics.days_since_rotation}")
```

---

## Best Practices

### Rotation Schedule

| Data Type | Recommended Interval |
|-----------|---------------------|
| User PII | 90 days |
| Payment data | 90 days |
| Session tokens | 30 days |
| Long-term archives | 365 days |

### Pre-Rotation Checklist

- [ ] Verify all applications can handle key versions
- [ ] Test rotation in staging environment
- [ ] Ensure monitoring is configured
- [ ] Have rollback plan ready
- [ ] Notify dependent teams

### Post-Rotation Verification

```python
# Verify rotation success
def verify_rotation(context):
    # 1. Check new version is active
    versions = admin.list_key_versions(context)
    assert versions[0].status == "active"

    # 2. Test encrypt/decrypt with new key
    test_data = b"rotation test"
    encrypted = crypto.encrypt(test_data, context=context)
    decrypted = crypto.decrypt(encrypted)
    assert decrypted == test_data

    # 3. Verify old ciphertext still decrypts
    # (Use a known test ciphertext from before rotation)

    print(f"Rotation verified for {context}")
```

---

## Emergency Rotation

If key compromise is suspected:

```python
# Emergency rotation - immediately disable old key
admin.emergency_rotate(
    context="user-pii",
    disable_old_immediately=True,
    reason="Suspected compromise - incident #12345"
)

# This will:
# 1. Create new key version
# 2. Immediately disable all old versions
# 3. Trigger alerts to security team
# 4. Log to audit trail
```

**Warning**: Emergency rotation may cause decryption failures for data encrypted with old keys. Only use when security risk outweighs availability.
