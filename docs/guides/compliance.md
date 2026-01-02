# Compliance Guide

Configure CryptoServe to meet regulatory requirements for HIPAA, PCI-DSS, GDPR, and SOC 2.

## Compliance Overview

CryptoServe provides built-in support for major compliance frameworks:

| Framework | Key Requirements | CryptoServe Features |
|-----------|-----------------|---------------------|
| **HIPAA** | PHI encryption, audit logs, access controls | Context isolation, full audit trail |
| **PCI-DSS** | Strong cryptography, key management | AES-256-GCM, HSM integration |
| **GDPR** | Data protection, right to erasure | Encryption, crypto-shredding |
| **SOC 2** | Security controls, monitoring | Comprehensive logging, metrics |

---

## HIPAA Compliance

### Requirements

The HIPAA Security Rule requires:

- Encryption of PHI at rest and in transit
- Access controls and audit trails
- Regular risk assessments

### Configuration

```bash
# Environment variables for HIPAA
HIPAA_MODE=enabled
AUDIT_LOGGING=full
PHI_CONTEXT=health-data
ACCESS_LOGGING=true
```

```python
# Create HIPAA-compliant context
from cryptoserve import admin

admin.create_context(
    name="health-data",
    algorithm="AES-256-GCM",
    key_rotation_days=90,
    audit_level="full",
    access_control="strict",
    compliance_tags=["HIPAA", "PHI"]
)
```

### Audit Trail

All PHI access is logged:

```python
# Query audit logs
logs = admin.query_audit_logs(
    context="health-data",
    start_date="2024-01-01",
    end_date="2024-01-31"
)

for entry in logs:
    print(f"{entry.timestamp} | {entry.operation} | {entry.identity} | {entry.resource}")
```

### Access Controls

Implement minimum necessary access:

```python
# Restrict access to specific identities
admin.create_policy(
    name="hipaa-phi-access",
    context="health-data",
    allowed_identities=["healthcare-app", "billing-service"],
    denied_operations=["export", "bulk-decrypt"],
    require_audit=True
)
```

---

## PCI-DSS Compliance

### Requirements

PCI-DSS requires:

- Strong cryptography (AES-128 minimum)
- Secure key management
- Key rotation at least annually
- Dual control for key operations

### Configuration

```bash
# Environment variables for PCI-DSS
PCI_DSS_MODE=enabled
PAYMENT_CONTEXT=payment-data
KEY_ROTATION_DAYS=365
DUAL_CONTROL=enabled
```

```python
# Create PCI-compliant context
admin.create_context(
    name="payment-data",
    algorithm="AES-256-GCM",
    key_rotation_days=365,
    kms_provider="aws",  # Use HSM-backed KMS
    dual_control=True,
    compliance_tags=["PCI-DSS", "Level-1"]
)
```

### Cardholder Data

Encrypt PANs and sensitive authentication data:

```python
# Encrypt card data
card_data = {
    "pan": "4111111111111111",
    "expiry": "12/25",
    "cvv": "123"  # Never store CVV!
}

# Only encrypt what you must store
encrypted_pan = crypto.encrypt_string(
    card_data["pan"],
    context="payment-data",
    associated_data=b"card_storage"
)

# Store encrypted PAN, never CVV
```

### Key Custodians

Implement split knowledge:

```python
# Require two custodians for key operations
admin.configure_dual_control(
    context="payment-data",
    operations=["rotate", "export", "destroy"],
    required_approvers=2,
    custodians=["custodian-1", "custodian-2", "custodian-3"]
)

# Key rotation requires approval
rotation_request = admin.request_key_rotation(
    context="payment-data",
    requested_by="custodian-1"
)

# Second custodian approves
admin.approve_operation(
    request_id=rotation_request.id,
    approved_by="custodian-2"
)
```

---

## GDPR Compliance

### Requirements

GDPR requires:

- Data protection by design
- Right to erasure (Article 17)
- Data portability
- Breach notification

### Configuration

```bash
# Environment variables for GDPR
GDPR_MODE=enabled
USER_DATA_CONTEXT=user-pii
DATA_RETENTION_ENABLED=true
CRYPTO_SHRED_ENABLED=true
```

### Right to Erasure (Crypto-Shredding)

Delete user data by destroying their encryption key:

```python
# Each user has their own derived key
user_id = "user-12345"

# Encrypt user data with user-specific key derivation
encrypted = crypto.encrypt_string(
    "user sensitive data",
    context="user-pii",
    key_derivation_id=user_id  # Derives unique key for this user
)

# When user requests deletion - crypto-shred
admin.crypto_shred(
    context="user-pii",
    key_derivation_id=user_id
)

# All user's data is now permanently unrecoverable
# No need to find/delete individual records
```

### Data Subject Access Request (DSAR)

Export user data:

```python
# Export all data for a user
export = admin.export_user_data(
    key_derivation_id=user_id,
    format="json",
    include_metadata=True
)

# Returns decrypted data for portability
```

### Breach Notification

Configure breach detection:

```python
# Monitor for anomalies
admin.configure_breach_detection(
    alert_on_bulk_decrypt=True,
    bulk_threshold=1000,
    alert_on_failed_decrypts=True,
    failed_threshold=100,
    notification_email="security@company.com"
)
```

---

## SOC 2 Compliance

### Requirements

SOC 2 Trust Service Criteria:

- Security
- Availability
- Processing Integrity
- Confidentiality
- Privacy

### Configuration

```bash
# Environment variables for SOC 2
SOC2_MODE=enabled
COMPREHENSIVE_LOGGING=true
METRICS_ENABLED=true
CHANGE_MANAGEMENT=enabled
```

### Security Controls

```python
# Implement SOC 2 security controls
admin.configure_security_controls(
    # Access controls
    require_authentication=True,
    session_timeout_minutes=30,
    mfa_required=True,

    # Encryption
    encryption_at_rest=True,
    encryption_in_transit=True,
    minimum_key_length=256,

    # Monitoring
    security_logging=True,
    anomaly_detection=True,
    alert_integration="pagerduty"
)
```

### Change Management

Track configuration changes:

```python
# All admin operations require change tickets
admin.configure_change_management(
    require_ticket=True,
    ticket_pattern=r"^(CHANGE|INC)-\d+$",
    approval_required=True
)

# Operations include ticket reference
admin.rotate_key(
    context="user-pii",
    change_ticket="CHANGE-12345"
)
```

### Evidence Collection

Generate compliance reports:

```python
# Generate SOC 2 evidence report
report = admin.generate_compliance_report(
    framework="SOC2",
    period_start="2024-01-01",
    period_end="2024-03-31",
    controls=["CC6.1", "CC6.7", "CC7.1"]  # Specific controls
)

# Export for auditors
report.export_pdf("soc2-evidence-q1-2024.pdf")
```

---

## FIPS 140-2 Mode

For government and regulated environments:

```bash
# Enable FIPS mode
FIPS_MODE=enabled
```

```python
# Verify FIPS compliance
status = admin.get_fips_status()

print(f"FIPS mode: {status.enabled}")
print(f"FIPS module: {status.module_name}")
print(f"Module version: {status.module_version}")
print(f"Validation level: {status.validation_level}")  # Level 1, 2, or 3
```

FIPS mode enforces:

- FIPS-approved algorithms only
- FIPS-validated cryptographic module
- Self-tests on startup
- Zeroization of keys

---

## Compliance Reports

### Automated Reports

```python
# Schedule compliance reports
admin.schedule_compliance_report(
    frameworks=["HIPAA", "PCI-DSS", "SOC2"],
    frequency="monthly",
    recipients=["compliance@company.com"],
    include_evidence=True
)
```

### On-Demand Assessment

```python
# Run compliance assessment
assessment = admin.run_compliance_assessment(
    framework="PCI-DSS"
)

print(f"Overall score: {assessment.score}%")
print(f"Controls passed: {assessment.passed}/{assessment.total}")

for finding in assessment.findings:
    print(f"- {finding.control}: {finding.status} - {finding.description}")
```

---

## Best Practices

1. **Defense in depth**: Don't rely solely on encryption
2. **Regular audits**: Review access logs and configurations
3. **Key management**: Use HSM-backed KMS in production
4. **Incident response**: Have a plan for key compromise
5. **Documentation**: Maintain evidence for auditors
6. **Training**: Ensure team understands compliance requirements
