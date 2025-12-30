# CryptoServe CI/CD Integration

**Test Before You Trust** - Comprehensive tools for validating cryptographic policies at every stage of development, from pre-commit hooks to production deployment.

## The Innovation

Unlike traditional crypto libraries that fail silently or crash at runtime, CryptoServe lets you:

1. **Catch issues before commit** - Pre-commit hooks block deprecated algorithms
2. **Simulate policy changes** - See exactly what would break before deploying
3. **Analyze blast radius** - Understand how many operations would be affected
4. **Run shadow mode** - Test new policies against production traffic without blocking
5. **Compare policy versions** - Diff current vs proposed policies side-by-side

This is game-changing - you get **confidence before deployment**.

---

## Quick Start

### Option 1: GitHub Actions (Recommended)

Copy the workflow to your repo:

```bash
mkdir -p .github/workflows
cp crypto-policy-check.yml .github/workflows/
```

Every PR will now be checked for cryptographic policy violations.

### Option 2: Pre-Commit Hook (Developer Machine)

Install the hook:

```bash
cp ci/pre-commit-hook.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Now deprecated algorithms and hardcoded secrets are caught before code leaves your machine.

### Option 3: Standalone Script (Any CI)

```bash
./ci/check-crypto-policies.sh --algorithm AES-256-GCM --context user-pii
```

Works with Jenkins, CircleCI, Azure DevOps, Buildkite, or any CI system.

---

## Tools Reference

### 1. Policy CLI (`cryptoserve-policy`)

The main command-line interface for policy validation.

```bash
# Validate policy YAML files
cryptoserve-policy validate policies/my-policy.yaml

# Check algorithm against policies
cryptoserve-policy check --algorithm AES-256-GCM --context user-pii --pii

# List algorithms
cryptoserve-policy list algorithms
cryptoserve-policy list deprecated
cryptoserve-policy list quantum

# Simulate algorithm resolution
cryptoserve-policy simulate --context payment-data --pci
```

**Output Formats:**
- `--format text` - Colored terminal output (default)
- `--format json` - Machine-readable JSON
- `--format github` - GitHub Actions annotations

**Exit Codes:**
- `0` - All checks passed
- `1` - Policy violations found (blocking)
- `2` - File/parse error
- `3` - Invalid arguments

### 2. Policy Simulator (`policy-simulator.py`)

The game-changing tool for testing policies before deployment.

```bash
# Simulate policy against all test scenarios
python ci/policy-simulator.py simulate --policy new-policy.yaml

# Analyze impact - see exactly what would break
python ci/policy-simulator.py impact --policy strict-crypto.yaml

# Compare current vs proposed policies
python ci/policy-simulator.py diff --current v1.yaml --proposed v2.yaml

# Shadow mode - replay historical operations
python ci/policy-simulator.py shadow --policy new-policy.yaml --hours 24
```

**Sample Impact Analysis Output:**

```
============================================================
IMPACT ANALYSIS: require-quantum-resistant
============================================================

Total test scenarios: 1,200

Projected Impact:
  Would BLOCK: 340 operations (28.3%)
  Would WARN:  0 operations (0.0%)
  Would PASS:  860 operations (71.7%)

Affected Contexts: quantum-ready, payment-data, health-data
Affected Teams: platform, security, payments
Affected Algorithms: AES-256-GCM, ChaCha20-Poly1305

Recommendations:
  - MODERATE IMPACT: This policy would block 28.3% of operations.
    Review affected contexts before enabling.
  - TIP: Consider deploying in shadow mode first to validate impact
    with real production traffic.
```

### 3. Pre-Commit Hook

Catches issues before code is committed:

```bash
# Install
ln -sf ../../ci/pre-commit-hook.sh .git/hooks/pre-commit

# What it checks:
# 1. Deprecated algorithms (DES, 3DES, MD5, SHA1, RC4, ECB mode)
# 2. Hardcoded secrets (base64/hex encoded keys)
# 3. Policy YAML syntax
# 4. Direct crypto API usage (should use CryptoServe SDK)
```

### 4. CI Scripts

**`check-crypto-policies.sh`** - Universal CI script

```bash
# Basic usage
./ci/check-crypto-policies.sh

# With options
./ci/check-crypto-policies.sh \
  --mode cli \
  --algorithm AES-256-GCM \
  --context user-pii:critical:pii:GDPR,CCPA \
  --context payment-data:critical:pci:PCI-DSS \
  --strict \
  --output junit
```

**Output formats:** `text`, `json`, `junit`

---

## GitHub Actions Workflow

The included workflow (`.github/workflows/crypto-policy-check.yml`) provides:

### Job 1: Policy Check (CLI)
Validates all your contexts against policies using the CLI tool.

### Job 2: Policy Check (API)
Validates against your running CryptoServe instance (optional).

### Job 3: Crypto Usage Scan
Scans source code for:
- Deprecated algorithm usage
- Hardcoded cryptographic keys
- Direct crypto API calls (should use SDK)

### Configuration

Set these secrets in your GitHub repo:

| Secret | Description |
|--------|-------------|
| `CRYPTOSERVE_API_URL` | URL of your CryptoServe instance |
| `CRYPTOSERVE_API_KEY` | API key for authentication |

Set these variables:

| Variable | Description |
|----------|-------------|
| `USE_API_CHECK` | Set to `true` to enable API-based checking |

---

## GitLab CI Integration

Include in your `.gitlab-ci.yml`:

```yaml
include:
  - project: 'your-org/crypto-serve'
    ref: main
    file: '/ci/gitlab-ci-policy.yml'
```

Or copy individual jobs to your pipeline.

---

## Policy File Format

Policies are defined in YAML:

```yaml
- name: my-policy-name
  description: Human readable description
  rule: algorithm.key_bits >= 256
  severity: block  # block, warn, info
  message: Error message when rule fails
  enabled: true
  contexts: []     # Empty = applies to all
  operations: []   # Empty = applies to all
```

### Rule Syntax

Rules support:

| Operator | Example |
|----------|---------|
| Comparison | `algorithm.key_bits >= 256` |
| Equality | `context.sensitivity == 'critical'` |
| Membership | `'HIPAA' in context.frameworks` |
| Negation | `algorithm.name not in ['DES', '3DES']` |
| Boolean | `condition1 and condition2` |
| Grouping | `(a or b) and c` |

### Available Variables

**`algorithm.*`**
- `name` - Algorithm name (e.g., "AES-256-GCM")
- `key_bits` - Key size in bits
- `quantum_resistant` - Boolean
- `hardware_acceleration` - Boolean

**`context.*`**
- `name` - Context name
- `sensitivity` - "low", "medium", "high", "critical"
- `pii` - Boolean (contains PII)
- `phi` - Boolean (contains PHI)
- `pci` - Boolean (contains payment card data)
- `frameworks` - List of compliance frameworks
- `protection_lifetime_years` - Integer
- `audit_level` - "minimal", "standard", "detailed", "full"

**`identity.*`**
- `team` - Team name
- `name` - Identity name

**`operation`**
- "encrypt" or "decrypt"

---

## Best Practices

### 1. Start with Warnings

Don't block immediately. Use `severity: warn` first to understand impact:

```yaml
- name: new-requirement
  severity: warn  # Start here
  # Later change to: severity: block
```

### 2. Use Impact Analysis

Before enabling any blocking policy:

```bash
python ci/policy-simulator.py impact --policy new-policy.yaml
```

### 3. Deploy in Stages

1. **Development** - `severity: info` (logging only)
2. **Staging** - `severity: warn` (alerts but doesn't block)
3. **Production** - `severity: block` (enforced)

### 4. Run Shadow Mode

Test new policies against production traffic without blocking:

```bash
# Replay last 24 hours of operations
python ci/policy-simulator.py shadow --policy new-policy.yaml --hours 24
```

### 5. Version Your Policies

Keep policies in version control and use diff analysis:

```bash
python ci/policy-simulator.py diff \
  --current policies/v1.0.yaml \
  --proposed policies/v1.1.yaml
```

---

## Troubleshooting

### "Policy not found"

Ensure the policy name matches exactly (case-sensitive).

### "Rule evaluation error"

Check rule syntax. Common issues:
- Unbalanced parentheses
- Missing quotes around strings
- Using `=` instead of `==`

### "CLI tool not found"

Set the path:
```bash
export CRYPTOSERVE_CLI_PATH=/path/to/cryptoserve-policy
```

### CI is slow

Use caching:
```yaml
- uses: actions/cache@v4
  with:
    path: ~/.cache/pip
    key: cryptoserve-${{ hashFiles('requirements.txt') }}
```

---

## Support

- Issues: https://github.com/your-org/crypto-serve/issues
- Docs: https://docs.cryptoserve.io/ci-cd
- Slack: #cryptoserve-support
