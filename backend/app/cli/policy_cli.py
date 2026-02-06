#!/usr/bin/env python3
"""CryptoServe Policy Validation CLI.

A command-line tool for validating cryptographic policies and checking
algorithm compliance. Designed for both interactive use and CI/CD integration.

Usage:
    cryptoserve-policy validate policy.yaml
    cryptoserve-policy check --algorithm AES-256-GCM --context user-pii
    cryptoserve-policy list algorithms --quantum-resistant
    cryptoserve-policy list deprecated

Exit Codes:
    0 - Success / All checks passed
    1 - Validation failed / Policy violations found
    2 - File not found or parse error
    3 - Invalid arguments
"""

import argparse
import json
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import yaml

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.core.crypto_registry import (
    crypto_registry,
    AlgorithmType,
    SecurityStatus,
    get_deprecated_algorithms,
)
from app.core.policy_engine import (
    Policy,
    PolicyEngine,
    PolicySeverity,
    EvaluationContext,
)
from app.schemas.context import ContextConfig

# =============================================================================
# Terminal Colors (for non-CI output)
# =============================================================================


class Colors:
    """ANSI color codes for terminal output."""

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls):
        """Disable colors (for CI/CD or piped output)."""
        cls.RED = ""
        cls.GREEN = ""
        cls.YELLOW = ""
        cls.BLUE = ""
        cls.MAGENTA = ""
        cls.CYAN = ""
        cls.WHITE = ""
        cls.BOLD = ""
        cls.RESET = ""


def colored(text: str, color: str) -> str:
    """Apply color to text."""
    return f"{color}{text}{Colors.RESET}"


def status_icon(passed: bool) -> str:
    """Return a status icon."""
    if passed:
        return colored("✓", Colors.GREEN)
    return colored("✗", Colors.RED)


def severity_color(severity: str) -> str:
    """Get color for severity level."""
    if severity == "block":
        return Colors.RED
    elif severity == "warn":
        return Colors.YELLOW
    return Colors.CYAN


# =============================================================================
# Output Formatters
# =============================================================================


@dataclass
class ValidationResult:
    """Result of a validation operation."""

    success: bool
    message: str
    details: list[dict] = None

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "message": self.message,
            "details": self.details or [],
        }


class OutputFormat(str, Enum):
    """Output format options."""

    TEXT = "text"
    JSON = "json"
    GITHUB = "github"  # GitHub Actions annotations


def output_result(result: ValidationResult, format: OutputFormat) -> None:
    """Output result in the specified format."""
    if format == OutputFormat.JSON:
        print(json.dumps(result.to_dict(), indent=2))
    elif format == OutputFormat.GITHUB:
        # GitHub Actions workflow commands
        if not result.success:
            for detail in result.details or []:
                level = "error" if detail.get("severity") == "block" else "warning"
                msg = detail.get("message", result.message)
                file = detail.get("file", "")
                line = detail.get("line", 1)
                print(f"::{level} file={file},line={line}::{msg}")
        else:
            print(f"::notice::{result.message}")
    else:
        # Text format
        icon = status_icon(result.success)
        print(f"{icon} {result.message}")
        if result.details:
            for detail in result.details:
                severity = detail.get("severity", "info")
                color = severity_color(severity)
                msg = detail.get("message", "")
                print(f"  {colored('→', color)} {msg}")


# =============================================================================
# Command: validate
# =============================================================================


def cmd_validate(args) -> int:
    """Validate policy YAML files."""
    file_path = Path(args.file)

    if not file_path.exists():
        result = ValidationResult(
            success=False,
            message=f"File not found: {file_path}",
        )
        output_result(result, args.format)
        return 2

    try:
        with open(file_path) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        result = ValidationResult(
            success=False,
            message=f"YAML parse error: {e}",
        )
        output_result(result, args.format)
        return 2

    # Validate policy structure
    errors = []
    warnings = []

    # Handle single policy or list of policies
    policies = data if isinstance(data, list) else [data]

    for i, policy_data in enumerate(policies):
        policy_errors = validate_policy_structure(policy_data, i)
        errors.extend(policy_errors)

        # Check for deprecated algorithms in rules
        rule = policy_data.get("rule", "")
        deprecated_check = check_deprecated_in_rule(rule)
        if deprecated_check:
            warnings.append(
                {
                    "severity": "warn",
                    "message": deprecated_check,
                    "policy": policy_data.get("name", f"policy_{i}"),
                }
            )

    if errors:
        result = ValidationResult(
            success=False,
            message=f"Policy validation failed with {len(errors)} error(s)",
            details=errors,
        )
        output_result(result, args.format)
        return 1

    # Success with optional warnings
    details = warnings if warnings else None
    result = ValidationResult(
        success=True,
        message=f"Validated {len(policies)} policy/policies in {file_path.name}",
        details=details,
    )
    output_result(result, args.format)
    return 0


def validate_policy_structure(policy: dict, index: int) -> list[dict]:
    """Validate a single policy structure."""
    errors = []
    name = policy.get("name", f"policy_{index}")

    # Required fields
    required = ["name", "rule", "message"]
    for field in required:
        if field not in policy:
            errors.append(
                {
                    "severity": "block",
                    "message": f"Policy '{name}': missing required field '{field}'",
                    "policy": name,
                }
            )

    # Validate severity if present
    if "severity" in policy:
        valid_severities = ["block", "warn", "info"]
        if policy["severity"] not in valid_severities:
            errors.append(
                {
                    "severity": "block",
                    "message": f"Policy '{name}': invalid severity '{policy['severity']}' (must be one of {valid_severities})",
                    "policy": name,
                }
            )

    # Validate rule syntax (basic check)
    rule = policy.get("rule", "")
    rule_error = validate_rule_syntax(rule)
    if rule_error:
        errors.append(
            {
                "severity": "block",
                "message": f"Policy '{name}': {rule_error}",
                "policy": name,
            }
        )

    return errors


def validate_rule_syntax(rule: str) -> str | None:
    """Basic validation of rule syntax."""
    if not rule.strip():
        return "rule cannot be empty"

    # Check for balanced parentheses
    if rule.count("(") != rule.count(")"):
        return "unbalanced parentheses in rule"

    # Check for valid comparison operators
    valid_operators = ["==", "!=", ">=", "<=", ">", "<", " in ", " not in ", " contains "]
    has_operator = any(op in rule for op in valid_operators)

    # Rules can be simple boolean expressions or comparisons
    if not has_operator and " and " not in rule and " or " not in rule:
        # Could be a simple variable reference - that's ok
        pass

    return None


def check_deprecated_in_rule(rule: str) -> str | None:
    """Check if rule references deprecated algorithms."""
    deprecated = get_deprecated_algorithms()
    for algo in deprecated:
        if algo.name in rule or algo.name.lower() in rule.lower():
            return f"Rule references deprecated algorithm '{algo.name}' - consider using '{algo.replacement}'"
    return None


# =============================================================================
# Command: check
# =============================================================================


def cmd_check(args) -> int:
    """Check if an algorithm/context combination passes policies."""
    algorithm = args.algorithm
    context_name = args.context or "general"
    sensitivity = args.sensitivity or "medium"

    # Look up algorithm
    algo = crypto_registry.get(algorithm)
    if not algo:
        result = ValidationResult(
            success=False,
            message=f"Unknown algorithm: {algorithm}",
            details=[
                {
                    "severity": "block",
                    "message": f"Algorithm '{algorithm}' not found in registry. Use 'list algorithms' to see available options.",
                }
            ],
        )
        output_result(result, args.format)
        return 1

    # Build evaluation context with smart defaults
    # This mirrors what the real system does with context configuration
    frameworks = args.frameworks.split(",") if args.frameworks else []

    # Determine audit level based on sensitivity and frameworks
    audit_level = "standard"
    if sensitivity == "critical" or "HIPAA" in frameworks or "PCI-DSS" in frameworks:
        audit_level = "full"
    elif sensitivity == "high":
        audit_level = "detailed"
    elif sensitivity == "low":
        audit_level = "minimal"

    eval_context = EvaluationContext(
        algorithm={
            "name": algo.name,
            "key_bits": algo.security_bits,
            "quantum_resistant": algo.quantum_resistant,
            "hardware_acceleration": algo.hardware_acceleration,
        },
        context={
            "name": context_name,
            "sensitivity": sensitivity,
            "pii": args.pii,
            "phi": "HIPAA" in frameworks,  # Protected Health Information
            "pci": "PCI-DSS" in frameworks,
            "frameworks": frameworks,
            "protection_lifetime_years": args.lifetime or 5,
            "audit_level": audit_level,
            "frequency": "medium",
        },
        identity={
            "team": args.team or "unknown",
        },
        operation=args.operation or "encrypt",
    )

    # Load and evaluate policies
    engine = PolicyEngine()
    engine.load_default_policies()

    # Also load custom policies if provided
    if args.policy_file:
        custom_policies = load_policies_from_file(args.policy_file)
        engine.add_policies(custom_policies)

    results = engine.evaluate(eval_context, raise_on_block=False)

    # Collect violations
    violations = [r for r in results if not r.passed]
    blocking = [v for v in violations if v.severity == PolicySeverity.BLOCK]
    warnings = [v for v in violations if v.severity == PolicySeverity.WARN]

    details = []
    for v in violations:
        details.append(
            {
                "severity": v.severity.value,
                "message": f"[{v.policy_name}] {v.message}",
                "policy": v.policy_name,
            }
        )

    if blocking:
        result = ValidationResult(
            success=False,
            message=f"Algorithm '{algo.name}' BLOCKED for context '{context_name}' ({len(blocking)} violation(s))",
            details=details,
        )
        output_result(result, args.format)
        return 1
    elif warnings:
        result = ValidationResult(
            success=True,
            message=f"Algorithm '{algo.name}' ALLOWED for context '{context_name}' with {len(warnings)} warning(s)",
            details=details,
        )
        output_result(result, args.format)
        return 0
    else:
        result = ValidationResult(
            success=True,
            message=f"Algorithm '{algo.name}' ALLOWED for context '{context_name}' - all policies passed",
        )
        output_result(result, args.format)
        return 0


def load_policies_from_file(file_path: str) -> list[Policy]:
    """Load policies from a YAML file."""
    policies = []
    with open(file_path) as f:
        data = yaml.safe_load(f)

    policy_list = data if isinstance(data, list) else [data]
    for p in policy_list:
        policies.append(
            Policy(
                name=p["name"],
                description=p.get("description", ""),
                rule=p["rule"],
                severity=PolicySeverity(p.get("severity", "warn")),
                message=p["message"],
                enabled=p.get("enabled", True),
                contexts=p.get("contexts", []),
                operations=p.get("operations", []),
            )
        )
    return policies


# =============================================================================
# Command: list
# =============================================================================


def cmd_list(args) -> int:
    """List algorithms or policies."""
    what = args.what

    if what == "algorithms":
        return list_algorithms(args)
    elif what == "deprecated":
        return list_deprecated(args)
    elif what == "policies":
        return list_policies(args)
    elif what == "quantum":
        return list_quantum(args)
    else:
        print(f"Unknown list type: {what}")
        return 3


def list_algorithms(args) -> int:
    """List all algorithms."""
    algorithms = crypto_registry.all_algorithms()

    # Apply filters
    if args.type:
        try:
            algo_type = AlgorithmType(args.type)
            algorithms = [a for a in algorithms if a.algorithm_type == algo_type]
        except ValueError:
            print(f"Invalid algorithm type: {args.type}")
            return 3

    if args.quantum_resistant:
        algorithms = [a for a in algorithms if a.quantum_resistant]

    if args.recommended:
        algorithms = [a for a in algorithms if a.status == SecurityStatus.RECOMMENDED]

    if args.format == OutputFormat.JSON:
        data = [a.to_dict() for a in algorithms]
        print(json.dumps(data, indent=2))
    else:
        print(f"\n{colored('Cryptographic Algorithms', Colors.BOLD)} ({len(algorithms)} total)\n")
        print(f"{'Name':<30} {'Type':<20} {'Bits':>6} {'Status':<12} {'Standards'}")
        print("-" * 100)
        for algo in algorithms:
            status_color_code = {
                SecurityStatus.RECOMMENDED: Colors.GREEN,
                SecurityStatus.ACCEPTABLE: Colors.BLUE,
                SecurityStatus.LEGACY: Colors.YELLOW,
                SecurityStatus.DEPRECATED: Colors.RED,
                SecurityStatus.BROKEN: Colors.RED + Colors.BOLD,
            }.get(algo.status, Colors.WHITE)

            status = colored(algo.status.value, status_color_code)
            qr = colored("◆", Colors.MAGENTA) if algo.quantum_resistant else " "
            standards = ", ".join(algo.standards[:2]) if algo.standards else "-"

            print(
                f"{qr} {algo.name:<28} {algo.algorithm_type.value:<20} {algo.security_bits:>5}  {status:<20} {standards}"
            )

        print(f"\n{colored('◆', Colors.MAGENTA)} = Quantum-resistant")

    return 0


def list_deprecated(args) -> int:
    """List deprecated algorithms."""
    deprecated = get_deprecated_algorithms()

    if args.format == OutputFormat.JSON:
        data = [
            {
                "name": a.name,
                "status": a.status.value,
                "replacement": a.replacement,
                "vulnerabilities": a.vulnerabilities,
            }
            for a in deprecated
        ]
        print(json.dumps(data, indent=2))
    else:
        print(f"\n{colored('⚠ Deprecated/Broken Algorithms', Colors.RED + Colors.BOLD)} ({len(deprecated)} total)\n")
        print("These algorithms should NOT be used. Migrate to recommended alternatives.\n")

        for algo in deprecated:
            status = colored(algo.status.value.upper(), Colors.RED)
            print(f"{status}: {colored(algo.name, Colors.BOLD)}")
            if algo.replacement:
                print(f"  → Replace with: {colored(algo.replacement, Colors.GREEN)}")
            if algo.vulnerabilities:
                for vuln in algo.vulnerabilities[:2]:
                    print(f"  {colored('!', Colors.YELLOW)} {vuln}")
            print()

    return 0


def list_quantum(args) -> int:
    """List quantum-resistant algorithms."""
    algorithms = crypto_registry.get_quantum_resistant()

    if args.format == OutputFormat.JSON:
        data = [a.to_dict() for a in algorithms]
        print(json.dumps(data, indent=2))
    else:
        print(
            f"\n{colored('Post-Quantum Cryptography', Colors.MAGENTA + Colors.BOLD)} ({len(algorithms)} algorithms)\n"
        )
        print("NIST PQC Standards (Finalized August 2024):\n")

        # Group by family
        families = {}
        for algo in algorithms:
            family = algo.family
            if family not in families:
                families[family] = []
            families[family].append(algo)

        for family, algos in families.items():
            standards = algos[0].standards if algos else []
            standard_str = ", ".join(standards) if standards else ""
            print(f"{colored(family, Colors.BOLD)} {colored(f'({standard_str})', Colors.CYAN)}")
            for algo in algos:
                notes = algo.implementation_notes[0] if algo.implementation_notes else ""
                print(f"  • {algo.name:<25} {algo.security_bits:>3}-bit  {notes}")
            print()

    return 0


def list_policies(args) -> int:
    """List default policies."""
    engine = PolicyEngine()
    engine.load_default_policies()

    if args.format == OutputFormat.JSON:
        data = [
            {
                "name": p.name,
                "description": p.description,
                "severity": p.severity.value,
                "rule": p.rule,
                "message": p.message,
            }
            for p in engine.policies
        ]
        print(json.dumps(data, indent=2))
    else:
        print(f"\n{colored('Default Policies', Colors.BOLD)} ({len(engine.policies)} total)\n")

        for policy in engine.policies:
            severity_c = severity_color(policy.severity.value)
            severity = colored(policy.severity.value.upper(), severity_c)
            print(f"[{severity}] {colored(policy.name, Colors.BOLD)}")
            if policy.description:
                print(f"  {policy.description}")
            print(f"  Rule: {colored(policy.rule, Colors.CYAN)}")
            print(f"  Message: {policy.message}")
            print()

    return 0


# =============================================================================
# Command: simulate
# =============================================================================


def cmd_simulate(args) -> int:
    """Simulate policy evaluation for a context configuration."""
    # Load context from YAML if provided
    if args.context_file:
        context_file = Path(args.context_file)
        if not context_file.exists():
            print(f"Context file not found: {context_file}")
            return 2

        with open(context_file) as f:
            context_data = yaml.safe_load(f)
    else:
        # Build from args
        context_data = {
            "data_identity": {
                "sensitivity": args.sensitivity or "medium",
                "pii": args.pii,
            },
            "regulatory": {
                "frameworks": args.frameworks.split(",") if args.frameworks else [],
            },
            "threat_model": {
                "protection_lifetime_years": args.lifetime or 5,
            },
        }

    # Try to parse as ContextConfig
    try:
        config = ContextConfig(**context_data)
    except Exception as e:
        result = ValidationResult(
            success=False,
            message=f"Invalid context configuration: {e}",
        )
        output_result(result, args.format)
        return 1

    # Resolve algorithm
    from app.core.algorithm_resolver import AlgorithmResolver

    resolver = AlgorithmResolver(config)
    derived = resolver.resolve()

    # Show results
    if args.format == OutputFormat.JSON:
        data = {
            "resolved_algorithm": derived.resolved_algorithm,
            "minimum_security_bits": derived.minimum_security_bits,
            "quantum_resistant": derived.quantum_resistant,
            "key_rotation_days": derived.key_rotation_days,
            "audit_level": derived.audit_level,
            "hardware_acceleration": derived.hardware_acceleration,
            "rationale": derived.rationale,
        }
        print(json.dumps(data, indent=2))
    else:
        print(f"\n{colored('Algorithm Resolution', Colors.BOLD)}\n")
        print(f"  Resolved Algorithm:    {colored(derived.resolved_algorithm, Colors.GREEN + Colors.BOLD)}")
        print(f"  Minimum Security:      {derived.minimum_security_bits} bits")
        print(f"  Quantum Resistant:     {colored('Yes', Colors.MAGENTA) if derived.quantum_resistant else 'No'}")
        print(f"  Key Rotation:          Every {derived.key_rotation_days} days")
        print(f"  Audit Level:           {derived.audit_level}")
        print(f"  HW Acceleration:       {'Yes' if derived.hardware_acceleration else 'No'}")

        print(f"\n{colored('Rationale', Colors.BOLD)}")
        for reason in derived.rationale:
            print(f"  → {reason}")
        print()

    return 0


# =============================================================================
# Main Entry Point
# =============================================================================


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="cryptoserve-policy",
        description="CryptoServe Policy Validation CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Validate a policy file
  cryptoserve-policy validate policies/encryption.yaml

  # Check if AES-256-GCM is allowed for health data
  cryptoserve-policy check --algorithm AES-256-GCM --context health-data --pii

  # List all quantum-resistant algorithms
  cryptoserve-policy list algorithms --quantum-resistant

  # List deprecated algorithms that need migration
  cryptoserve-policy list deprecated

  # Simulate algorithm selection for a context
  cryptoserve-policy simulate --sensitivity critical --frameworks HIPAA --lifetime 20

  # CI/CD integration with JSON output
  cryptoserve-policy check -a AES-128-GCM -c user-pii --format json
        """,
    )

    # Global options
    parser.add_argument(
        "--format",
        "-f",
        type=OutputFormat,
        choices=list(OutputFormat),
        default=OutputFormat.TEXT,
        help="Output format (default: text)",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # validate command
    validate_parser = subparsers.add_parser("validate", help="Validate policy YAML files")
    validate_parser.add_argument("file", help="Policy YAML file to validate")

    # check command
    check_parser = subparsers.add_parser("check", help="Check algorithm/context against policies")
    check_parser.add_argument("-a", "--algorithm", required=True, help="Algorithm to check")
    check_parser.add_argument("-c", "--context", help="Context name")
    check_parser.add_argument("-s", "--sensitivity", choices=["low", "medium", "high", "critical"])
    check_parser.add_argument("--pii", action="store_true", help="Data contains PII")
    check_parser.add_argument("--frameworks", help="Compliance frameworks (comma-separated)")
    check_parser.add_argument("--lifetime", type=int, help="Protection lifetime in years")
    check_parser.add_argument("--team", help="Team name")
    check_parser.add_argument("--operation", choices=["encrypt", "decrypt"], default="encrypt")
    check_parser.add_argument("--policy-file", help="Additional policy file to load")

    # list command
    list_parser = subparsers.add_parser("list", help="List algorithms or policies")
    list_parser.add_argument("what", choices=["algorithms", "deprecated", "policies", "quantum"], help="What to list")
    list_parser.add_argument("--type", help="Filter by algorithm type")
    list_parser.add_argument("--quantum-resistant", "-q", action="store_true")
    list_parser.add_argument("--recommended", "-r", action="store_true")

    # simulate command
    simulate_parser = subparsers.add_parser("simulate", help="Simulate algorithm resolution")
    simulate_parser.add_argument("--context-file", help="Context configuration YAML file")
    simulate_parser.add_argument("-s", "--sensitivity", choices=["low", "medium", "high", "critical"])
    simulate_parser.add_argument("--pii", action="store_true", help="Data contains PII")
    simulate_parser.add_argument("--frameworks", help="Compliance frameworks (comma-separated)")
    simulate_parser.add_argument("--lifetime", type=int, help="Protection lifetime in years")

    return parser


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    # Handle no-color or piped output
    if args.no_color or not sys.stdout.isatty():
        Colors.disable()

    # Handle format as string if needed
    if isinstance(args.format, str):
        args.format = OutputFormat(args.format)

    if not args.command:
        parser.print_help()
        return 0

    # Dispatch to command handler
    if args.command == "validate":
        return cmd_validate(args)
    elif args.command == "check":
        return cmd_check(args)
    elif args.command == "list":
        return cmd_list(args)
    elif args.command == "simulate":
        return cmd_simulate(args)
    else:
        parser.print_help()
        return 3


if __name__ == "__main__":
    sys.exit(main())
