#!/usr/bin/env bash
#
# CryptoServe Policy Check Script
#
# A standalone script for validating cryptographic policies in any CI/CD system.
# Can use either the CLI tool (local) or the API (remote).
#
# Usage:
#   ./check-crypto-policies.sh [options]
#
# Options:
#   --mode cli|api          Use CLI tool or API (default: cli)
#   --api-url URL           CryptoServe API URL (for API mode)
#   --api-key KEY           API key for authentication
#   --config FILE           Path to check configuration file
#   --context NAME          Context to check (can be repeated)
#   --algorithm ALGO        Algorithm to check (default: AES-256-GCM)
#   --strict                Fail on warnings too (default: fail on blocks only)
#   --output FORMAT         Output format: text, json, junit (default: text)
#   --help                  Show this help message
#
# Environment Variables:
#   CRYPTOSERVE_API_URL     API URL (alternative to --api-url)
#   CRYPTOSERVE_API_KEY     API key (alternative to --api-key)
#   CRYPTOSERVE_CLI_PATH    Path to cryptoserve-policy CLI
#
# Exit Codes:
#   0 - All checks passed
#   1 - Policy violations found
#   2 - Configuration error
#   3 - Network/API error

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

MODE="cli"
API_URL="${CRYPTOSERVE_API_URL:-}"
API_KEY="${CRYPTOSERVE_API_KEY:-}"
CLI_PATH="${CRYPTOSERVE_CLI_PATH:-cryptoserve-policy}"
CONFIG_FILE=""
CONTEXTS=()
ALGORITHM="AES-256-GCM"
STRICT=false
OUTPUT_FORMAT="text"
VERBOSE=false

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Disable colors if not a terminal
if [[ ! -t 1 ]]; then
    RED='' GREEN='' YELLOW='' BLUE='' NC=''
fi

# =============================================================================
# Helper Functions
# =============================================================================

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[PASS]${NC} $*"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[FAIL]${NC} $*"; }
log_debug() { [[ "$VERBOSE" == "true" ]] && echo -e "[DEBUG] $*" || true; }

show_help() {
    grep '^#' "$0" | grep -v '#!/' | sed 's/^# \?//'
    exit 0
}

check_dependencies() {
    if [[ "$MODE" == "cli" ]]; then
        if ! command -v "$CLI_PATH" &> /dev/null; then
            log_error "CLI tool not found: $CLI_PATH"
            log_info "Set CRYPTOSERVE_CLI_PATH or install the CLI tool"
            exit 2
        fi
    else
        if ! command -v curl &> /dev/null; then
            log_error "curl is required for API mode"
            exit 2
        fi
        if ! command -v jq &> /dev/null; then
            log_warning "jq not found, JSON parsing will be limited"
        fi
    fi
}

# =============================================================================
# Parse Arguments
# =============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        --mode)
            MODE="$2"
            shift 2
            ;;
        --api-url)
            API_URL="$2"
            shift 2
            ;;
        --api-key)
            API_KEY="$2"
            shift 2
            ;;
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --context)
            CONTEXTS+=("$2")
            shift 2
            ;;
        --algorithm)
            ALGORITHM="$2"
            shift 2
            ;;
        --strict)
            STRICT=true
            shift
            ;;
        --output)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --help|-h)
            show_help
            ;;
        *)
            log_error "Unknown option: $1"
            exit 2
            ;;
    esac
done

# =============================================================================
# Default Contexts Configuration
# =============================================================================

# If no contexts specified, use defaults
if [[ ${#CONTEXTS[@]} -eq 0 ]]; then
    CONTEXTS=(
        "user-pii:critical:pii:GDPR,CCPA"
        "payment-data:critical:pci:PCI-DSS"
        "health-data:critical:phi:HIPAA"
        "session-tokens:medium::"
        "general:medium::"
    )
fi

# =============================================================================
# Check Functions
# =============================================================================

check_context_cli() {
    local context="$1"
    local sensitivity="${2:-medium}"
    local flags="${3:-}"
    local frameworks="${4:-}"

    local args=("--format" "json" "check")
    args+=("--algorithm" "$ALGORITHM")
    args+=("--context" "$context")
    args+=("--sensitivity" "$sensitivity")

    [[ "$flags" == *"pii"* ]] && args+=("--pii")
    [[ "$flags" == *"phi"* ]] && args+=("--pii")  # CLI uses --pii for PHI too
    [[ "$flags" == *"pci"* ]] && args+=("--frameworks" "PCI-DSS")
    [[ -n "$frameworks" ]] && args+=("--frameworks" "$frameworks")

    log_debug "Running: $CLI_PATH ${args[*]}"

    local result
    result=$("$CLI_PATH" "${args[@]}" 2>&1) || true

    echo "$result"
}

check_context_api() {
    local context="$1"
    local sensitivity="${2:-medium}"
    local flags="${3:-}"
    local frameworks="${4:-}"

    # Build JSON payload
    local pii="false" phi="false" pci="false"
    [[ "$flags" == *"pii"* ]] && pii="true"
    [[ "$flags" == *"phi"* ]] && phi="true"
    [[ "$flags" == *"pci"* ]] && pci="true"

    # Convert comma-separated frameworks to JSON array
    local fw_json="[]"
    if [[ -n "$frameworks" ]]; then
        fw_json=$(echo "$frameworks" | tr ',' '\n' | sed 's/^/"/;s/$/"/' | tr '\n' ',' | sed 's/,$//' | sed 's/^/[/;s/$/]/')
    fi

    local payload
    payload=$(cat <<EOF
{
    "algorithm": "$ALGORITHM",
    "context_name": "$context",
    "sensitivity": "$sensitivity",
    "pii": $pii,
    "phi": $phi,
    "pci": $pci,
    "frameworks": $fw_json
}
EOF
)

    log_debug "Payload: $payload"

    local result
    result=$(curl -s -X POST \
        "${API_URL}/api/policies/evaluate" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${API_KEY}" \
        -d "$payload" 2>&1)

    echo "$result"
}

# =============================================================================
# Output Formatters
# =============================================================================

output_junit_header() {
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo '<testsuites name="CryptoServe Policy Checks">'
}

output_junit_footer() {
    echo '</testsuites>'
}

output_junit_test() {
    local name="$1"
    local passed="$2"
    local message="${3:-}"

    echo "  <testsuite name=\"$name\" tests=\"1\">"
    if [[ "$passed" == "true" ]]; then
        echo "    <testcase name=\"policy-check\" classname=\"$name\"/>"
    else
        echo "    <testcase name=\"policy-check\" classname=\"$name\">"
        echo "      <failure message=\"Policy violation\">$message</failure>"
        echo "    </testcase>"
    fi
    echo "  </testsuite>"
}

# =============================================================================
# Main Execution
# =============================================================================

main() {
    log_info "CryptoServe Policy Check"
    log_info "Mode: $MODE | Algorithm: $ALGORITHM | Contexts: ${#CONTEXTS[@]}"

    check_dependencies

    if [[ "$MODE" == "api" ]]; then
        if [[ -z "$API_URL" || -z "$API_KEY" ]]; then
            log_error "API mode requires --api-url and --api-key (or environment variables)"
            exit 2
        fi
    fi

    local total=0
    local passed=0
    local warnings=0
    local failed=0
    local results=()

    [[ "$OUTPUT_FORMAT" == "junit" ]] && output_junit_header

    for ctx_config in "${CONTEXTS[@]}"; do
        # Parse context config: name:sensitivity:flags:frameworks
        IFS=':' read -r ctx sensitivity flags frameworks <<< "$ctx_config"
        sensitivity="${sensitivity:-medium}"

        log_info "Checking context: $ctx"
        ((total++))

        local result
        if [[ "$MODE" == "cli" ]]; then
            result=$(check_context_cli "$ctx" "$sensitivity" "$flags" "$frameworks")
        else
            result=$(check_context_api "$ctx" "$sensitivity" "$flags" "$frameworks")
        fi

        log_debug "Result: $result"

        # Parse result
        local success
        if command -v jq &> /dev/null; then
            success=$(echo "$result" | jq -r '.success // .allowed // "unknown"')
        else
            # Fallback: grep for success/allowed
            if echo "$result" | grep -q '"success":\s*true\|"allowed":\s*true'; then
                success="true"
            else
                success="false"
            fi
        fi

        local message=""
        if command -v jq &> /dev/null; then
            message=$(echo "$result" | jq -r '.message // .details[0].message // ""' 2>/dev/null || echo "")
        fi

        if [[ "$success" == "true" ]]; then
            # Check for warnings
            local warn_count=0
            if command -v jq &> /dev/null; then
                warn_count=$(echo "$result" | jq -r '.warning_violations // 0' 2>/dev/null || echo "0")
            fi

            if [[ "$warn_count" -gt 0 ]]; then
                log_warning "$ctx: Passed with $warn_count warning(s)"
                ((warnings++))
                if [[ "$STRICT" == "true" ]]; then
                    ((failed++))
                else
                    ((passed++))
                fi
            else
                log_success "$ctx: All policies passed"
                ((passed++))
            fi
            [[ "$OUTPUT_FORMAT" == "junit" ]] && output_junit_test "$ctx" "true"
        else
            log_error "$ctx: Policy violation - $message"
            ((failed++))
            [[ "$OUTPUT_FORMAT" == "junit" ]] && output_junit_test "$ctx" "false" "$message"
        fi

        results+=("$result")
    done

    [[ "$OUTPUT_FORMAT" == "junit" ]] && output_junit_footer

    # Summary
    echo ""
    log_info "========================================="
    log_info "Summary: $passed passed, $warnings warnings, $failed failed (of $total)"
    log_info "========================================="

    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        echo "{"
        echo "  \"total\": $total,"
        echo "  \"passed\": $passed,"
        echo "  \"warnings\": $warnings,"
        echo "  \"failed\": $failed,"
        echo "  \"strict\": $STRICT"
        echo "}"
    fi

    if [[ $failed -gt 0 ]]; then
        log_error "Policy checks failed!"
        exit 1
    fi

    log_success "All policy checks passed!"
    exit 0
}

main
