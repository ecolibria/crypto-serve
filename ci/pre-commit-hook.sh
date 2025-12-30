#!/usr/bin/env bash
#
# CryptoServe Pre-Commit Hook
#
# Catches cryptographic policy violations before code is even committed.
# This is the first line of defense - issues are caught immediately on
# the developer's machine, not in CI 30 minutes later.
#
# Installation:
#   cp ci/pre-commit-hook.sh .git/hooks/pre-commit
#   chmod +x .git/hooks/pre-commit
#
# Or with a symlink:
#   ln -sf ../../ci/pre-commit-hook.sh .git/hooks/pre-commit

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}CryptoServe Pre-Commit Check${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Get list of staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [[ -z "$STAGED_FILES" ]]; then
    echo "No files staged for commit."
    exit 0
fi

ERRORS=0
WARNINGS=0

# =============================================================================
# Check 1: Scan for deprecated algorithms in code
# =============================================================================

echo -e "\n${CYAN}[1/4]${NC} Scanning for deprecated algorithms..."

DEPRECATED_PATTERNS=(
    "DES"
    "3DES"
    "TripleDES"
    "MD5"
    "SHA1[^0-9]"  # SHA1 but not SHA128, SHA192, etc.
    "RC4"
    "RC2"
    "Blowfish"
    "ECB"         # ECB mode is almost always wrong
)

for file in $STAGED_FILES; do
    # Only check source files
    if [[ "$file" =~ \.(py|js|ts|java|go|rs|c|cpp|h|hpp)$ ]]; then
        for pattern in "${DEPRECATED_PATTERNS[@]}"; do
            if grep -n -E "(encrypt|cipher|algorithm|mode|hash).*$pattern|$pattern.*(encrypt|cipher|mode)" "$file" 2>/dev/null | grep -v "test\|mock\|example\|deprecated\|legacy\|#.*$pattern" > /dev/null; then
                echo -e "  ${RED}✗${NC} $file: Deprecated algorithm pattern '$pattern' found"
                grep -n -E "(encrypt|cipher|algorithm|mode|hash).*$pattern|$pattern.*(encrypt|mode)" "$file" 2>/dev/null | head -3 | sed 's/^/    /'
                ((ERRORS++))
            fi
        done
    fi
done

if [[ $ERRORS -eq 0 ]]; then
    echo -e "  ${GREEN}✓${NC} No deprecated algorithms found"
fi

# =============================================================================
# Check 2: Scan for hardcoded secrets
# =============================================================================

echo -e "\n${CYAN}[2/4]${NC} Scanning for potential hardcoded secrets..."

SECRET_PATTERNS=(
    # Base64-encoded keys (32+ chars suggests 256-bit key)
    '["\x27][A-Za-z0-9+/]{32,}={0,2}["\x27]'
    # Hex-encoded keys
    '["\x27][0-9a-fA-F]{32,}["\x27]'
    # Common secret variable patterns
    '(secret|key|password|token|api_key)\s*[:=]\s*["\x27][^"\x27]{16,}["\x27]'
)

for file in $STAGED_FILES; do
    if [[ "$file" =~ \.(py|js|ts|java|go|env|yaml|yml|json)$ ]]; then
        for pattern in "${SECRET_PATTERNS[@]}"; do
            matches=$(grep -n -E "$pattern" "$file" 2>/dev/null | grep -v "test\|mock\|example\|placeholder\|xxx\|your-" || true)
            if [[ -n "$matches" ]]; then
                echo -e "  ${YELLOW}⚠${NC} $file: Potential hardcoded secret"
                echo "$matches" | head -3 | sed 's/^/    /'
                ((WARNINGS++))
            fi
        done
    fi
done

if [[ $WARNINGS -eq 0 ]]; then
    echo -e "  ${GREEN}✓${NC} No obvious hardcoded secrets found"
fi

# =============================================================================
# Check 3: Validate policy YAML files if changed
# =============================================================================

echo -e "\n${CYAN}[3/4]${NC} Validating policy files..."

POLICY_FILES=$(echo "$STAGED_FILES" | grep -E "policies?/.*\.ya?ml$" || true)

if [[ -n "$POLICY_FILES" ]]; then
    CLI_PATH="${CRYPTOSERVE_CLI_PATH:-cryptoserve-policy}"

    if command -v "$CLI_PATH" &> /dev/null; then
        for file in $POLICY_FILES; do
            if ! "$CLI_PATH" validate "$file" > /dev/null 2>&1; then
                echo -e "  ${RED}✗${NC} $file: Invalid policy syntax"
                "$CLI_PATH" validate "$file" 2>&1 | sed 's/^/    /'
                ((ERRORS++))
            else
                echo -e "  ${GREEN}✓${NC} $file: Valid"
            fi
        done
    else
        echo -e "  ${YELLOW}⚠${NC} CLI tool not found, skipping policy validation"
        echo "    Install or set CRYPTOSERVE_CLI_PATH to enable"
    fi
else
    echo -e "  ${GREEN}✓${NC} No policy files changed"
fi

# =============================================================================
# Check 4: Ensure encryption contexts are used correctly
# =============================================================================

echo -e "\n${CYAN}[4/4]${NC} Checking encryption context usage..."

# Look for raw encryption calls without context
RAW_CRYPTO_PATTERNS=(
    'AESGCM\('
    'Fernet\('
    'AES\.new\('
    'createCipheriv\('
    'crypto\.createCipher'
    'Cipher\.getInstance\('
)

for file in $STAGED_FILES; do
    if [[ "$file" =~ \.(py|js|ts|java)$ ]]; then
        for pattern in "${RAW_CRYPTO_PATTERNS[@]}"; do
            if grep -n "$pattern" "$file" 2>/dev/null | grep -v "test\|mock\|cryptoserve" > /dev/null; then
                echo -e "  ${YELLOW}⚠${NC} $file: Direct crypto API usage detected"
                echo "    Consider using CryptoServe SDK for policy enforcement"
                grep -n "$pattern" "$file" 2>/dev/null | head -2 | sed 's/^/    /'
                ((WARNINGS++))
            fi
        done
    fi
done

if [[ $WARNINGS -eq 0 ]]; then
    echo -e "  ${GREEN}✓${NC} No direct crypto API calls found"
fi

# =============================================================================
# Summary
# =============================================================================

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ $ERRORS -gt 0 ]]; then
    echo -e "${RED}Pre-commit check failed!${NC}"
    echo -e "  $ERRORS error(s), $WARNINGS warning(s)"
    echo ""
    echo "Fix the errors above before committing."
    echo "To bypass (not recommended): git commit --no-verify"
    exit 1
elif [[ $WARNINGS -gt 0 ]]; then
    echo -e "${YELLOW}Pre-commit check passed with warnings${NC}"
    echo -e "  $WARNINGS warning(s)"
    echo ""
    echo "Consider addressing the warnings above."
    exit 0
else
    echo -e "${GREEN}All pre-commit checks passed!${NC}"
    exit 0
fi
