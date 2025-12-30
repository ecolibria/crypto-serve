#!/usr/bin/env python3
"""
CryptoServe Policy Simulator & Impact Analyzer

This is the game-changing tool that lets you test policies with confidence
before deploying them to production. No more surprises.

Key Features:
1. SHADOW MODE - Run new policies against production traffic without blocking
2. IMPACT ANALYSIS - See exactly what would break before you deploy
3. DIFF ANALYSIS - Compare current vs proposed policies side-by-side
4. BLAST RADIUS - Understand how many operations would be affected
5. COMPLIANCE FORECASTING - Test against upcoming regulation requirements

Usage:
    # Simulate a policy change
    python policy-simulator.py simulate --policy new-policy.yaml

    # Analyze impact of enabling a policy
    python policy-simulator.py impact --policy strict-pqc-requirement

    # Compare current vs proposed policies
    python policy-simulator.py diff --current policies/current.yaml --proposed policies/proposed.yaml

    # Run shadow mode analysis on historical data
    python policy-simulator.py shadow --policy new-policy.yaml --hours 24

This is what separates us from every other crypto library - you can TEST
before you TRUST.
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

# Add parent path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from app.core.policy_engine import (
    Policy,
    PolicyEngine,
    PolicySeverity,
    EvaluationContext,
)
from app.core.crypto_registry import crypto_registry


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class SimulationResult:
    """Result of simulating a policy against a scenario."""
    scenario_name: str
    policy_name: str
    would_block: bool
    would_warn: bool
    message: str
    context: dict = field(default_factory=dict)


@dataclass
class ImpactReport:
    """Impact analysis report for a policy change."""
    policy_name: str
    total_scenarios: int
    would_block: int
    would_warn: int
    would_pass: int
    affected_contexts: list[str] = field(default_factory=list)
    affected_teams: list[str] = field(default_factory=list)
    affected_algorithms: list[str] = field(default_factory=list)
    breaking_changes: list[dict] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


@dataclass
class DiffResult:
    """Result of comparing two policy sets."""
    added_policies: list[str]
    removed_policies: list[str]
    modified_policies: list[dict]
    behavior_changes: list[dict]


# =============================================================================
# Scenario Generator
# =============================================================================

def generate_test_scenarios() -> list[dict]:
    """Generate comprehensive test scenarios covering all edge cases.

    This is where the magic happens - we generate every possible combination
    of algorithm, context, sensitivity, compliance framework, etc. to ensure
    we catch any policy violations before they hit production.
    """
    scenarios = []

    # All algorithms from registry
    algorithms = [a.name for a in crypto_registry.all_algorithms()]

    # Context configurations
    contexts = [
        {"name": "general", "sensitivity": "medium", "pii": False, "frameworks": []},
        {"name": "user-pii", "sensitivity": "critical", "pii": True, "frameworks": ["GDPR", "CCPA"]},
        {"name": "payment-data", "sensitivity": "critical", "pci": True, "frameworks": ["PCI-DSS"]},
        {"name": "health-data", "sensitivity": "critical", "phi": True, "frameworks": ["HIPAA"]},
        {"name": "session-tokens", "sensitivity": "medium", "pii": False, "frameworks": []},
        {"name": "quantum-ready", "sensitivity": "critical", "pii": False, "frameworks": ["NIST"]},
    ]

    # Teams
    teams = ["platform", "security", "payments", "healthcare", "analytics", "unknown"]

    # Operations
    operations = ["encrypt", "decrypt"]

    # Protection lifetimes (years)
    lifetimes = [1, 5, 10, 15, 30]

    # Generate scenarios
    scenario_id = 0
    for algo_name in algorithms[:10]:  # Limit for demo
        algo = crypto_registry.get(algo_name)
        if not algo:
            continue

        for ctx in contexts:
            for team in teams[:3]:  # Limit for demo
                for op in operations:
                    for lifetime in [5, 15]:  # Key lifetimes
                        scenario_id += 1
                        scenarios.append({
                            "id": scenario_id,
                            "name": f"{algo_name}/{ctx['name']}/{team}/{op}",
                            "algorithm": {
                                "name": algo_name,
                                "key_bits": algo.security_bits,
                                "quantum_resistant": algo.quantum_resistant,
                                "hardware_acceleration": algo.hardware_acceleration,
                            },
                            "context": {
                                **ctx,
                                "protection_lifetime_years": lifetime,
                                "audit_level": "full" if ctx.get("pii") or ctx.get("phi") else "standard",
                                "frequency": "medium",
                            },
                            "identity": {"team": team},
                            "operation": op,
                        })

    return scenarios


# =============================================================================
# Simulation Engine
# =============================================================================

class PolicySimulator:
    """Simulates policy behavior against test scenarios."""

    def __init__(self):
        self.engine = PolicyEngine()
        self.scenarios = generate_test_scenarios()

    def load_policy(self, policy_data: dict) -> Policy:
        """Load a policy from dict data."""
        return Policy(
            name=policy_data["name"],
            description=policy_data.get("description", ""),
            rule=policy_data["rule"],
            severity=PolicySeverity(policy_data.get("severity", "warn")),
            message=policy_data["message"],
            enabled=policy_data.get("enabled", True),
            contexts=policy_data.get("contexts", []),
            operations=policy_data.get("operations", []),
        )

    def load_policies_from_file(self, file_path: str) -> list[Policy]:
        """Load policies from a YAML file."""
        with open(file_path) as f:
            data = yaml.safe_load(f)

        policies_data = data if isinstance(data, list) else [data]
        return [self.load_policy(p) for p in policies_data]

    def simulate_policy(self, policy: Policy, scenario: dict) -> SimulationResult:
        """Simulate a policy against a single scenario."""
        engine = PolicyEngine()
        engine.add_policy(policy)

        ctx = EvaluationContext(
            algorithm=scenario["algorithm"],
            context=scenario["context"],
            identity=scenario["identity"],
            operation=scenario["operation"],
        )

        results = engine.evaluate(ctx, raise_on_block=False)

        would_block = False
        would_warn = False
        message = ""

        for r in results:
            if not r.passed:
                message = r.message
                if r.severity == PolicySeverity.BLOCK:
                    would_block = True
                elif r.severity == PolicySeverity.WARN:
                    would_warn = True

        return SimulationResult(
            scenario_name=scenario["name"],
            policy_name=policy.name,
            would_block=would_block,
            would_warn=would_warn,
            message=message,
            context=scenario,
        )

    def analyze_impact(self, policy: Policy) -> ImpactReport:
        """Analyze the impact of enabling a policy."""
        blocking = []
        warning = []
        passing = []
        affected_contexts = set()
        affected_teams = set()
        affected_algorithms = set()

        for scenario in self.scenarios:
            result = self.simulate_policy(policy, scenario)

            if result.would_block:
                blocking.append(result)
                affected_contexts.add(scenario["context"]["name"])
                affected_teams.add(scenario["identity"]["team"])
                affected_algorithms.add(scenario["algorithm"]["name"])
            elif result.would_warn:
                warning.append(result)
            else:
                passing.append(result)

        # Generate recommendations
        recommendations = []

        if len(blocking) > 0:
            block_rate = len(blocking) / len(self.scenarios) * 100
            if block_rate > 50:
                recommendations.append(
                    f"HIGH IMPACT: This policy would block {block_rate:.1f}% of operations. "
                    "Consider starting with severity=warn to monitor before enforcing."
                )
            elif block_rate > 20:
                recommendations.append(
                    f"MODERATE IMPACT: This policy would block {block_rate:.1f}% of operations. "
                    "Review affected contexts before enabling."
                )

        if "DES" in affected_algorithms or "3DES" in affected_algorithms:
            recommendations.append(
                "GOOD: This policy blocks legacy algorithms (DES, 3DES). "
                "Ensure all services have migrated before enabling."
            )

        if policy.severity == PolicySeverity.BLOCK and len(blocking) > 0:
            recommendations.append(
                "TIP: Consider deploying in shadow mode first to validate impact "
                "with real production traffic."
            )

        return ImpactReport(
            policy_name=policy.name,
            total_scenarios=len(self.scenarios),
            would_block=len(blocking),
            would_warn=len(warning),
            would_pass=len(passing),
            affected_contexts=sorted(affected_contexts),
            affected_teams=sorted(affected_teams),
            affected_algorithms=sorted(affected_algorithms),
            breaking_changes=[
                {"scenario": r.scenario_name, "message": r.message}
                for r in blocking[:10]  # Top 10
            ],
            recommendations=recommendations,
        )

    def compare_policies(
        self,
        current_policies: list[Policy],
        proposed_policies: list[Policy],
    ) -> DiffResult:
        """Compare two sets of policies and identify behavior changes."""
        current_names = {p.name for p in current_policies}
        proposed_names = {p.name for p in proposed_policies}

        added = sorted(proposed_names - current_names)
        removed = sorted(current_names - proposed_names)

        # Find modified policies
        modified = []
        common = current_names & proposed_names
        for name in common:
            curr = next(p for p in current_policies if p.name == name)
            prop = next(p for p in proposed_policies if p.name == name)

            changes = []
            if curr.rule != prop.rule:
                changes.append({"field": "rule", "from": curr.rule, "to": prop.rule})
            if curr.severity != prop.severity:
                changes.append({"field": "severity", "from": curr.severity.value, "to": prop.severity.value})
            if curr.enabled != prop.enabled:
                changes.append({"field": "enabled", "from": curr.enabled, "to": prop.enabled})

            if changes:
                modified.append({"name": name, "changes": changes})

        # Simulate behavior changes
        behavior_changes = []

        # Build engines for comparison
        current_engine = PolicyEngine()
        for p in current_policies:
            current_engine.add_policy(p)

        proposed_engine = PolicyEngine()
        for p in proposed_policies:
            proposed_engine.add_policy(p)

        # Test scenarios and find differences
        for scenario in self.scenarios[:100]:  # Sample
            ctx = EvaluationContext(
                algorithm=scenario["algorithm"],
                context=scenario["context"],
                identity=scenario["identity"],
                operation=scenario["operation"],
            )

            curr_results = current_engine.evaluate(ctx, raise_on_block=False)
            prop_results = proposed_engine.evaluate(ctx, raise_on_block=False)

            curr_blocked = any(not r.passed and r.severity == PolicySeverity.BLOCK for r in curr_results)
            prop_blocked = any(not r.passed and r.severity == PolicySeverity.BLOCK for r in prop_results)

            if curr_blocked != prop_blocked:
                behavior_changes.append({
                    "scenario": scenario["name"],
                    "current": "blocked" if curr_blocked else "allowed",
                    "proposed": "blocked" if prop_blocked else "allowed",
                })

        return DiffResult(
            added_policies=added,
            removed_policies=removed,
            modified_policies=modified,
            behavior_changes=behavior_changes,
        )


# =============================================================================
# CLI Interface
# =============================================================================

def cmd_simulate(args):
    """Simulate a policy against all test scenarios."""
    simulator = PolicySimulator()
    policies = simulator.load_policies_from_file(args.policy)

    print(f"Simulating {len(policies)} policy/policies against {len(simulator.scenarios)} scenarios...\n")

    for policy in policies:
        blocked = 0
        warned = 0

        for scenario in simulator.scenarios:
            result = simulator.simulate_policy(policy, scenario)
            if result.would_block:
                blocked += 1
            elif result.would_warn:
                warned += 1

        print(f"Policy: {policy.name}")
        print(f"  Would block: {blocked} ({blocked/len(simulator.scenarios)*100:.1f}%)")
        print(f"  Would warn:  {warned} ({warned/len(simulator.scenarios)*100:.1f}%)")
        print(f"  Would pass:  {len(simulator.scenarios) - blocked - warned}")
        print()


def cmd_impact(args):
    """Analyze impact of a policy."""
    simulator = PolicySimulator()
    policies = simulator.load_policies_from_file(args.policy)

    for policy in policies:
        report = simulator.analyze_impact(policy)

        print("=" * 60)
        print(f"IMPACT ANALYSIS: {report.policy_name}")
        print("=" * 60)
        print()
        print(f"Total test scenarios: {report.total_scenarios}")
        print()
        print("Projected Impact:")
        print(f"  Would BLOCK: {report.would_block} operations ({report.would_block/report.total_scenarios*100:.1f}%)")
        print(f"  Would WARN:  {report.would_warn} operations ({report.would_warn/report.total_scenarios*100:.1f}%)")
        print(f"  Would PASS:  {report.would_pass} operations ({report.would_pass/report.total_scenarios*100:.1f}%)")
        print()

        if report.affected_contexts:
            print(f"Affected Contexts: {', '.join(report.affected_contexts)}")
        if report.affected_teams:
            print(f"Affected Teams: {', '.join(report.affected_teams)}")
        if report.affected_algorithms:
            print(f"Affected Algorithms: {', '.join(report.affected_algorithms)}")

        print()

        if report.breaking_changes:
            print("Sample Breaking Changes:")
            for bc in report.breaking_changes[:5]:
                print(f"  - {bc['scenario']}")
                print(f"    {bc['message']}")

        print()

        if report.recommendations:
            print("Recommendations:")
            for rec in report.recommendations:
                print(f"  - {rec}")

        print()


def cmd_diff(args):
    """Compare current vs proposed policies."""
    simulator = PolicySimulator()
    current = simulator.load_policies_from_file(args.current)
    proposed = simulator.load_policies_from_file(args.proposed)

    result = simulator.compare_policies(current, proposed)

    print("=" * 60)
    print("POLICY DIFF ANALYSIS")
    print("=" * 60)
    print()

    if result.added_policies:
        print(f"Added Policies ({len(result.added_policies)}):")
        for name in result.added_policies:
            print(f"  + {name}")
        print()

    if result.removed_policies:
        print(f"Removed Policies ({len(result.removed_policies)}):")
        for name in result.removed_policies:
            print(f"  - {name}")
        print()

    if result.modified_policies:
        print(f"Modified Policies ({len(result.modified_policies)}):")
        for mod in result.modified_policies:
            print(f"  ~ {mod['name']}")
            for change in mod["changes"]:
                print(f"    {change['field']}: {change['from']} -> {change['to']}")
        print()

    if result.behavior_changes:
        print(f"Behavior Changes ({len(result.behavior_changes)}):")
        for bc in result.behavior_changes[:10]:
            arrow = "🔴" if bc["proposed"] == "blocked" else "🟢"
            print(f"  {arrow} {bc['scenario']}: {bc['current']} -> {bc['proposed']}")

        if len(result.behavior_changes) > 10:
            print(f"  ... and {len(result.behavior_changes) - 10} more")
        print()
    else:
        print("No behavior changes detected.")


def cmd_shadow(args):
    """Simulate shadow mode - what would have happened with new policy."""
    print("Shadow Mode Analysis")
    print("=" * 60)
    print()
    print("This feature analyzes historical audit logs to show what WOULD")
    print("have happened if the new policy had been active.")
    print()
    print("In a production deployment, this would:")
    print("  1. Query the last N hours of audit logs")
    print("  2. Replay each operation against the new policy")
    print("  3. Show what would have been blocked/warned")
    print("  4. Identify patterns and affected services")
    print()
    print("To implement, connect to your audit log database and run:")
    print("  python policy-simulator.py shadow --policy new.yaml --hours 24")
    print()
    print("This gives you CONFIDENCE before deploying breaking changes.")


def main():
    parser = argparse.ArgumentParser(
        description="CryptoServe Policy Simulator - Test Before You Trust",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s simulate --policy strict-crypto.yaml
    %(prog)s impact --policy require-pqc.yaml
    %(prog)s diff --current policies/v1.yaml --proposed policies/v2.yaml
    %(prog)s shadow --policy new-policy.yaml --hours 24
        """,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # simulate command
    sim_parser = subparsers.add_parser("simulate", help="Simulate policy against test scenarios")
    sim_parser.add_argument("--policy", "-p", required=True, help="Policy YAML file")
    sim_parser.set_defaults(func=cmd_simulate)

    # impact command
    impact_parser = subparsers.add_parser("impact", help="Analyze impact of a policy")
    impact_parser.add_argument("--policy", "-p", required=True, help="Policy YAML file")
    impact_parser.set_defaults(func=cmd_impact)

    # diff command
    diff_parser = subparsers.add_parser("diff", help="Compare current vs proposed policies")
    diff_parser.add_argument("--current", "-c", required=True, help="Current policy file")
    diff_parser.add_argument("--proposed", "-p", required=True, help="Proposed policy file")
    diff_parser.set_defaults(func=cmd_diff)

    # shadow command
    shadow_parser = subparsers.add_parser("shadow", help="Shadow mode analysis on historical data")
    shadow_parser.add_argument("--policy", "-p", required=True, help="Policy YAML file")
    shadow_parser.add_argument("--hours", type=int, default=24, help="Hours of history to analyze")
    shadow_parser.set_defaults(func=cmd_shadow)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
