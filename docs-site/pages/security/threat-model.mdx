# Threat Model

This document describes CryptoServe's security assumptions, threat landscape, and mitigations.

## Trust Model

### Trusted Components

| Component | Trust Level | Rationale |
|-----------|-------------|-----------|
| Platform Operator | Full | Has access to master key |
| Server Infrastructure | Full | OS, database, network |
| Cryptographic Libraries | Full | cryptography (OpenSSL), liboqs |
| KMS (Production) | Full | HSM-backed key storage |

### Untrusted Components

| Component | Trust Level | Rationale |
|-----------|-------------|-----------|
| Client Applications | Untrusted | May be compromised |
| Network | Untrusted | TLS required |
| End Users | Untrusted | Authenticate all requests |
| Stored Data | Untrusted | Encrypted at rest |

---

## Threat Analysis

### T1: Master Key Compromise

**Description**: Attacker obtains the master key material.

**Impact**: Complete compromise of all encrypted data.

**Likelihood**: Low (with proper controls)

**Mitigations**:

- Production: Store master key in HSM (AWS KMS, etc.)
- Environment variable only for development
- Key rotation capability
- Audit logging of all key operations
- Access controls and monitoring

### T2: Database Compromise

**Description**: Attacker gains read access to the database.

**Impact**: Access to ciphertext, metadata, audit logs.

**Likelihood**: Medium

**Mitigations**:

- DEKs are derived, not stored (development mode)
- PQC private keys encrypted at rest
- Refresh tokens stored as SHA-256 hashes
- Database encryption at rest (recommended)
- Network isolation

**What attacker CANNOT do**:

- Decrypt data (no key material in database)
- Forge tokens (private keys encrypted)

### T3: Network Interception

**Description**: Man-in-the-middle attack on API traffic.

**Impact**: Token theft, data interception.

**Likelihood**: Medium (without TLS)

**Mitigations**:

- TLS 1.2+ required for all connections
- Certificate validation
- HSTS headers
- Token binding (future)

### T4: Nonce Reuse (AES-GCM)

**Description**: Same nonce used twice with the same key.

**Impact**: Loss of authenticity, potential plaintext recovery.

**Likelihood**: Very low

**Mitigations**:

- Nonces generated via `os.urandom()` (96-bit random)
- Birthday bound: ~2^48 encryptions before 50% collision
- Key rotation after ~2^32 operations (configurable)
- Audit logging enables detection

**Analysis**: With 96-bit random nonces and key rotation at 2^32 messages, collision probability is negligible (~2^-32).

### T5: Timing Attacks

**Description**: Side-channel attack based on operation timing.

**Impact**: Key recovery, authentication bypass.

**Likelihood**: Low

**Mitigations**:

- `hmac.compare_digest()` for MAC comparisons
- `secrets.compare_digest()` for token verification
- Ed25519 (deterministic signatures, no timing on nonce)
- Library-level protections (OpenSSL, liboqs)

### T6: Ciphertext Malleability

**Description**: Attacker modifies ciphertext to produce valid plaintext.

**Impact**: Data integrity violation.

**Likelihood**: Low (with AEAD)

**Mitigations**:

- AEAD modes (GCM, CCM, ChaCha20-Poly1305)
- Encrypt-then-MAC for CBC mode
- Key commitment prevents partition attacks

### T7: Multi-Key Attack (Invisible Salamanders)

**Description**: Single ciphertext decrypts to different plaintexts under different keys.

**Impact**: Message confusion, integrity violation.

**Likelihood**: Low

**Mitigations**:

- Key commitment stored in ciphertext header
- Verified during decryption
- Based on HMAC-SHA256 of key material

**Reference**: Albertini et al., "How to Abuse and Fix Authenticated Encryption Without Key Commitment" (2020)

### T8: Algorithm Downgrade

**Description**: Attacker forces use of weaker algorithm.

**Impact**: Reduced security guarantees.

**Likelihood**: Low

**Mitigations**:

- Algorithm policy enforcement per context
- Policy modes: warn, enforce
- Algorithm stored in authenticated ciphertext header
- Cannot modify without detection

### T9: Token Theft

**Description**: JWT access token stolen from client.

**Impact**: Unauthorized API access until expiration.

**Likelihood**: Medium

**Mitigations**:

- Short token lifetime (1 hour)
- Scope limited to specific contexts
- Audit logging of all operations
- Token revocation capability
- Refresh tokens stored as hashes (server-side)

### T10: Quantum Computer Attacks (Future)

**Description**: Quantum computer breaks classical public-key crypto.

**Impact**: Decryption of data encrypted with classical algorithms.

**Timeline**: 10-15 years (estimated)

**Mitigations**:

- Hybrid PQC modes available (ML-KEM + AES-GCM)
- Algorithm agility enables migration
- Context-based quantum threat configuration
- "Harvest now, decrypt later" addressed

---

## Out of Scope

The following threats are explicitly NOT protected against:

### Compromised Client Application

If an application using the SDK is compromised, it has legitimate access to decrypt its authorized data. CryptoServe cannot prevent this.

**Rationale**: The client needs plaintext to function. Protecting against a compromised client requires endpoint security, not encryption.

### Side-Channel Attacks on Server

We rely on library implementations (OpenSSL, liboqs) for side-channel resistance. Advanced attacks (power analysis, EM emanations) require physical access.

**Rationale**: Defense requires hardware-level controls beyond software scope.

### Memory Forensics

Keys exist in server memory during operations. A memory dump could expose key material.

**Mitigations**: SecureBytes helper (best-effort zeroization)

**Rationale**: Complete protection requires hardware security modules for all operations.

### Malicious Platform Operator

The platform operator has access to the master key and can decrypt any data.

**Rationale**: This is inherent to any encryption-as-a-service model. For zero-trust requirements, use client-side encryption.

### Denial of Service

Rate limiting provides basic protection, but determined attackers can still degrade service.

**Rationale**: Full DoS protection requires network-level controls (CDN, WAF) beyond CryptoServe's scope.

---

## Security Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                         Trust Boundary                           │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                 CryptoServe Server                        │   │
│  │                                                           │   │
│  │  • Master Key (in memory)                                 │   │
│  │  • DEKs (derived per request)                             │   │
│  │  • Private signing keys (encrypted at rest)               │   │
│  │                                                           │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ TLS-protected network
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Untrusted Zone                              │
│                                                                  │
│  • Network traffic (encrypted in transit)                        │
│  • Client applications (authenticated, authorized)               │
│  • Stored ciphertext (encrypted at rest)                         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Assumptions

For CryptoServe's security guarantees to hold:

1. **Master key is protected**: Stored in HSM/KMS in production
2. **TLS is properly configured**: Valid certificates, modern ciphers
3. **Server is not compromised**: OS, network, and application secure
4. **Cryptographic libraries are correct**: OpenSSL, liboqs without bugs
5. **Random number generation is working**: OS CSPRNG is seeded

---

## Incident Response

In case of suspected security incident:

1. **Isolate**: Disconnect affected systems
2. **Assess**: Determine scope of compromise
3. **Rotate**: Rotate master key if potentially exposed
4. **Audit**: Review audit logs for unauthorized access
5. **Notify**: Inform affected users per compliance requirements
6. **Remediate**: Fix vulnerability, deploy patches
7. **Review**: Post-incident analysis and improvements
