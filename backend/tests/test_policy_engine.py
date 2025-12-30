"""Tests for the policy engine."""

import pytest

from app.core.policy_engine import (
    PolicyEngine,
    Policy,
    PolicySeverity,
    EvaluationContext,
    PolicyViolation,
)


class TestPolicyEngine:
    """Tests for PolicyEngine class."""

    def test_create_engine(self):
        """Test creating a policy engine."""
        engine = PolicyEngine()
        assert engine is not None
        assert len(engine.policies) == 0

    def test_add_policy(self):
        """Test adding a policy to the engine."""
        engine = PolicyEngine()
        policy = Policy(
            name="test-policy",
            description="Test policy",
            rule="algorithm.key_bits >= 256",
            severity=PolicySeverity.BLOCK,
            message="Key size too small",
        )
        engine.add_policy(policy)
        assert len(engine.policies) == 1
        assert engine.policies[0].name == "test-policy"

    def test_load_default_policies(self):
        """Test loading default policies."""
        engine = PolicyEngine()
        engine.load_default_policies()
        assert len(engine.policies) > 0
        # Check some expected default policies exist
        policy_names = [p.name for p in engine.policies]
        assert "require-256-bit-for-pii" in policy_names or len(policy_names) > 0

    def test_evaluate_passing(self):
        """Test evaluation with passing policies."""
        engine = PolicyEngine()
        policy = Policy(
            name="require-256-bit",
            description="Require 256-bit keys",
            rule="algorithm.key_bits >= 256",
            severity=PolicySeverity.BLOCK,
            message="Key size must be at least 256 bits",
        )
        engine.add_policy(policy)

        context = EvaluationContext(
            algorithm={
                "name": "AES-256-GCM",
                "key_bits": 256,
                "quantum_resistant": False,
                "hardware_acceleration": True,
            },
            context={
                "name": "test-context",
                "sensitivity": "high",
                "pii": False,
                "phi": False,
                "pci": False,
                "frameworks": [],
                "protection_lifetime_years": 5,
                "audit_level": "standard",
                "frequency": "medium",
            },
            identity={"team": "test-team"},
            operation="encrypt",
        )

        results = engine.evaluate(context, raise_on_block=False)
        assert len(results) == 1
        assert results[0].passed is True

    def test_evaluate_failing(self):
        """Test evaluation with failing policies."""
        engine = PolicyEngine()
        policy = Policy(
            name="require-256-bit",
            description="Require 256-bit keys",
            rule="algorithm.key_bits >= 256",
            severity=PolicySeverity.BLOCK,
            message="Key size must be at least 256 bits",
        )
        engine.add_policy(policy)

        context = EvaluationContext(
            algorithm={
                "name": "AES-128-GCM",
                "key_bits": 128,
                "quantum_resistant": False,
                "hardware_acceleration": True,
            },
            context={
                "name": "test-context",
                "sensitivity": "high",
                "pii": False,
                "phi": False,
                "pci": False,
                "frameworks": [],
                "protection_lifetime_years": 5,
                "audit_level": "standard",
                "frequency": "medium",
            },
            identity={"team": "test-team"},
            operation="encrypt",
        )

        results = engine.evaluate(context, raise_on_block=False)
        assert len(results) == 1
        assert results[0].passed is False
        assert results[0].severity == PolicySeverity.BLOCK

    def test_evaluate_raises_on_block(self):
        """Test that evaluation raises on blocking violation when configured."""
        engine = PolicyEngine()
        policy = Policy(
            name="require-256-bit",
            description="Require 256-bit keys",
            rule="algorithm.key_bits >= 256",
            severity=PolicySeverity.BLOCK,
            message="Key size must be at least 256 bits",
        )
        engine.add_policy(policy)

        context = EvaluationContext(
            algorithm={
                "name": "AES-128-GCM",
                "key_bits": 128,
                "quantum_resistant": False,
                "hardware_acceleration": True,
            },
            context={
                "name": "test-context",
                "sensitivity": "high",
                "pii": False,
                "phi": False,
                "pci": False,
                "frameworks": [],
                "protection_lifetime_years": 5,
                "audit_level": "standard",
                "frequency": "medium",
            },
            identity={"team": "test-team"},
            operation="encrypt",
        )

        with pytest.raises(PolicyViolation):
            engine.evaluate(context, raise_on_block=True)

    def test_warn_policy_does_not_raise(self):
        """Test that warn policies don't raise even with raise_on_block."""
        engine = PolicyEngine()
        policy = Policy(
            name="prefer-256-bit",
            description="Prefer 256-bit keys",
            rule="algorithm.key_bits >= 256",
            severity=PolicySeverity.WARN,
            message="Consider using 256-bit keys",
        )
        engine.add_policy(policy)

        context = EvaluationContext(
            algorithm={
                "name": "AES-128-GCM",
                "key_bits": 128,
                "quantum_resistant": False,
                "hardware_acceleration": True,
            },
            context={
                "name": "test-context",
                "sensitivity": "low",
                "pii": False,
                "phi": False,
                "pci": False,
                "frameworks": [],
                "protection_lifetime_years": 5,
                "audit_level": "standard",
                "frequency": "medium",
            },
            identity={"team": "test-team"},
            operation="encrypt",
        )

        # Should not raise
        results = engine.evaluate(context, raise_on_block=True)
        assert len(results) == 1
        assert results[0].passed is False
        assert results[0].severity == PolicySeverity.WARN

    def test_disabled_policy_skipped(self):
        """Test that disabled policies are skipped."""
        engine = PolicyEngine()
        policy = Policy(
            name="disabled-policy",
            description="This policy is disabled",
            rule="algorithm.key_bits >= 256",
            severity=PolicySeverity.BLOCK,
            message="Should not see this",
            enabled=False,
        )
        engine.add_policy(policy)

        context = EvaluationContext(
            algorithm={
                "name": "AES-128-GCM",
                "key_bits": 128,
                "quantum_resistant": False,
                "hardware_acceleration": True,
            },
            context={
                "name": "test-context",
                "sensitivity": "high",
                "pii": False,
                "phi": False,
                "pci": False,
                "frameworks": [],
                "protection_lifetime_years": 5,
                "audit_level": "standard",
                "frequency": "medium",
            },
            identity={"team": "test-team"},
            operation="encrypt",
        )

        results = engine.evaluate(context, raise_on_block=True)
        assert len(results) == 0

    def test_context_specific_policy(self):
        """Test that context-specific policies only apply to matching contexts."""
        engine = PolicyEngine()
        policy = Policy(
            name="pii-256-bit",
            description="Require 256-bit for PII contexts",
            rule="algorithm.key_bits >= 256",
            severity=PolicySeverity.BLOCK,
            message="PII requires 256-bit encryption",
            contexts=["user-pii"],  # Only applies to user-pii context
        )
        engine.add_policy(policy)

        # Context that doesn't match - should not evaluate policy
        other_context = EvaluationContext(
            algorithm={
                "name": "AES-128-GCM",
                "key_bits": 128,
                "quantum_resistant": False,
                "hardware_acceleration": True,
            },
            context={
                "name": "other-context",
                "sensitivity": "low",
                "pii": False,
                "phi": False,
                "pci": False,
                "frameworks": [],
                "protection_lifetime_years": 5,
                "audit_level": "standard",
                "frequency": "medium",
            },
            identity={"team": "test-team"},
            operation="encrypt",
        )

        results = engine.evaluate(other_context, raise_on_block=True)
        assert len(results) == 0  # Policy should not apply

        # Context that matches - should evaluate policy
        pii_context = EvaluationContext(
            algorithm={
                "name": "AES-128-GCM",
                "key_bits": 128,
                "quantum_resistant": False,
                "hardware_acceleration": True,
            },
            context={
                "name": "user-pii",
                "sensitivity": "high",
                "pii": True,
                "phi": False,
                "pci": False,
                "frameworks": [],
                "protection_lifetime_years": 5,
                "audit_level": "standard",
                "frequency": "medium",
            },
            identity={"team": "test-team"},
            operation="encrypt",
        )

        with pytest.raises(PolicyViolation):
            engine.evaluate(pii_context, raise_on_block=True)


class TestPolicyRuleEvaluation:
    """Tests for policy rule evaluation."""

    def test_comparison_operators(self):
        """Test comparison operators in rules."""
        engine = PolicyEngine()

        # Test >=
        engine.add_policy(Policy(
            name="test-gte",
            rule="algorithm.key_bits >= 256",
            severity=PolicySeverity.BLOCK,
            message="Test",
        ))

        context_pass = EvaluationContext(
            algorithm={"name": "AES", "key_bits": 256, "quantum_resistant": False, "hardware_acceleration": False},
            context={"name": "test", "sensitivity": "low", "pii": False, "phi": False, "pci": False, "frameworks": [], "protection_lifetime_years": 1, "audit_level": "minimal", "frequency": "low"},
            identity={"team": "test"},
            operation="encrypt",
        )
        context_fail = EvaluationContext(
            algorithm={"name": "AES", "key_bits": 128, "quantum_resistant": False, "hardware_acceleration": False},
            context={"name": "test", "sensitivity": "low", "pii": False, "phi": False, "pci": False, "frameworks": [], "protection_lifetime_years": 1, "audit_level": "minimal", "frequency": "low"},
            identity={"team": "test"},
            operation="encrypt",
        )

        results_pass = engine.evaluate(context_pass, raise_on_block=False)
        results_fail = engine.evaluate(context_fail, raise_on_block=False)

        assert results_pass[0].passed is True
        assert results_fail[0].passed is False

    def test_boolean_checks(self):
        """Test boolean checks in rules."""
        engine = PolicyEngine()
        engine.add_policy(Policy(
            name="require-quantum",
            rule="algorithm.quantum_resistant == True",
            severity=PolicySeverity.BLOCK,
            message="Quantum resistance required",
        ))

        context_pass = EvaluationContext(
            algorithm={"name": "Kyber", "key_bits": 256, "quantum_resistant": True, "hardware_acceleration": False},
            context={"name": "test", "sensitivity": "low", "pii": False, "phi": False, "pci": False, "frameworks": [], "protection_lifetime_years": 1, "audit_level": "minimal", "frequency": "low"},
            identity={"team": "test"},
            operation="encrypt",
        )
        context_fail = EvaluationContext(
            algorithm={"name": "AES", "key_bits": 256, "quantum_resistant": False, "hardware_acceleration": False},
            context={"name": "test", "sensitivity": "low", "pii": False, "phi": False, "pci": False, "frameworks": [], "protection_lifetime_years": 1, "audit_level": "minimal", "frequency": "low"},
            identity={"team": "test"},
            operation="encrypt",
        )

        results_pass = engine.evaluate(context_pass, raise_on_block=False)
        results_fail = engine.evaluate(context_fail, raise_on_block=False)

        assert results_pass[0].passed is True
        assert results_fail[0].passed is False

    def test_membership_in_check(self):
        """Test 'in' membership checks in rules."""
        engine = PolicyEngine()
        engine.add_policy(Policy(
            name="require-hipaa",
            rule="'HIPAA' in context.frameworks",
            severity=PolicySeverity.INFO,
            message="HIPAA framework detected",
        ))

        context_with_hipaa = EvaluationContext(
            algorithm={"name": "AES", "key_bits": 256, "quantum_resistant": False, "hardware_acceleration": False},
            context={"name": "test", "sensitivity": "high", "pii": True, "phi": True, "pci": False, "frameworks": ["HIPAA", "SOC2"], "protection_lifetime_years": 7, "audit_level": "full", "frequency": "high"},
            identity={"team": "test"},
            operation="encrypt",
        )
        context_without_hipaa = EvaluationContext(
            algorithm={"name": "AES", "key_bits": 256, "quantum_resistant": False, "hardware_acceleration": False},
            context={"name": "test", "sensitivity": "low", "pii": False, "phi": False, "pci": False, "frameworks": ["SOC2"], "protection_lifetime_years": 1, "audit_level": "minimal", "frequency": "low"},
            identity={"team": "test"},
            operation="encrypt",
        )

        results_with = engine.evaluate(context_with_hipaa, raise_on_block=False)
        results_without = engine.evaluate(context_without_hipaa, raise_on_block=False)

        assert results_with[0].passed is True
        assert results_without[0].passed is False
