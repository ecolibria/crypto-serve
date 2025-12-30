"""Algorithm Resolution Engine.

Computes optimal cryptographic settings based on the 5-layer context model.
Takes data identity, regulatory, threat model, and access patterns as input,
and outputs derived requirements including the resolved algorithm.
"""

from app.schemas.context import (
    ContextConfig,
    DerivedRequirements,
    Sensitivity,
    Adversary,
    AccessFrequency,
)


# Algorithm registry with properties
# Uses official NIST naming: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205)
ALGORITHMS = {
    "AES-128-GCM": {
        "security_bits": 128,
        "quantum_resistant": False,
        "latency_ms": 0.1,
        "description": "AES-128 in GCM mode (FIPS 197, SP 800-38D)",
        "standards": ["FIPS 197", "NIST SP 800-38D"],
    },
    "AES-256-GCM": {
        "security_bits": 256,
        "quantum_resistant": False,
        "latency_ms": 0.15,
        "description": "AES-256 in GCM mode (FIPS 197, SP 800-38D)",
        "standards": ["FIPS 197", "NIST SP 800-38D"],
    },
    "AES-256-GCM-SIV": {
        "security_bits": 256,
        "quantum_resistant": False,
        "latency_ms": 0.2,
        "description": "AES-256 in GCM-SIV mode - nonce-misuse resistant (RFC 8452)",
        "standards": ["RFC 8452"],
    },
    "ChaCha20-Poly1305": {
        "security_bits": 256,
        "quantum_resistant": False,
        "latency_ms": 0.12,
        "description": "ChaCha20 with Poly1305 - good for non-AES-NI (RFC 8439)",
        "standards": ["RFC 8439"],
    },
    "AES-256-GCM+ML-KEM-768": {
        "security_bits": 256,
        "quantum_resistant": True,
        "latency_ms": 0.5,
        "description": "Hybrid classical + post-quantum, NIST PQC Level 3 (FIPS 203)",
        "standards": ["FIPS 197", "FIPS 203"],
    },
    "AES-256-GCM+ML-KEM-1024": {
        "security_bits": 256,
        "quantum_resistant": True,
        "latency_ms": 0.7,
        "description": "Hybrid classical + post-quantum, NIST PQC Level 5 (FIPS 203)",
        "standards": ["FIPS 197", "FIPS 203"],
    },
}

# Default algorithm when no special requirements
DEFAULT_ALGORITHM = "AES-256-GCM"

# Sensitivity to security requirements mapping
SENSITIVITY_REQUIREMENTS = {
    Sensitivity.CRITICAL: {
        "min_bits": 256,
        "audit_level": "full",
        "key_rotation_days": 30,
    },
    Sensitivity.HIGH: {
        "min_bits": 256,
        "audit_level": "detailed",
        "key_rotation_days": 90,
    },
    Sensitivity.MEDIUM: {
        "min_bits": 128,
        "audit_level": "standard",
        "key_rotation_days": 180,
    },
    Sensitivity.LOW: {
        "min_bits": 128,
        "audit_level": "minimal",
        "key_rotation_days": 365,
    },
}


class AlgorithmResolver:
    """Resolves optimal cryptographic algorithm based on context configuration."""

    def __init__(self, config: ContextConfig):
        self.config = config
        self.rationale: list[str] = []

    def resolve(self) -> DerivedRequirements:
        """Compute derived requirements from context configuration."""
        self.rationale = []

        # Step 1: Determine minimum security bits from sensitivity
        sensitivity_req = SENSITIVITY_REQUIREMENTS[self.config.data_identity.sensitivity]
        min_bits = sensitivity_req["min_bits"]
        audit_level = sensitivity_req["audit_level"]
        key_rotation_days = sensitivity_req["key_rotation_days"]

        self.rationale.append(
            f"Sensitivity '{self.config.data_identity.sensitivity.value}' requires "
            f"{min_bits}-bit encryption with {audit_level} audit"
        )

        # Step 2: Check for quantum resistance requirement
        quantum_resistant = self._needs_quantum_resistance()

        # Step 3: Adjust key rotation based on compliance
        if self.config.regulatory.frameworks:
            # PCI-DSS and HIPAA typically require more frequent rotation
            if any(f.upper() in ["PCI-DSS", "HIPAA"] for f in self.config.regulatory.frameworks):
                key_rotation_days = min(key_rotation_days, 90)
                self.rationale.append(
                    f"Compliance frameworks {self.config.regulatory.frameworks} require "
                    f"key rotation every {key_rotation_days} days max"
                )

        # Step 4: Consider adversary strength
        if Adversary.NATION_STATE in self.config.threat_model.adversaries:
            min_bits = max(min_bits, 256)
            self.rationale.append(
                "Nation-state adversary requires 256-bit minimum"
            )

        # Step 5: Determine hardware acceleration
        hw_acceleration = self._should_use_hw_acceleration()

        # Step 6: Select algorithm
        algorithm = self._select_algorithm(min_bits, quantum_resistant, hw_acceleration)

        return DerivedRequirements(
            minimum_security_bits=min_bits,
            quantum_resistant=quantum_resistant,
            key_rotation_days=key_rotation_days,
            resolved_algorithm=algorithm,
            audit_level=audit_level,
            hardware_acceleration=hw_acceleration,
            rationale=self.rationale,
        )

    def _needs_quantum_resistance(self) -> bool:
        """Determine if quantum-resistant algorithms are needed."""
        # Explicit quantum adversary
        if Adversary.QUANTUM in self.config.threat_model.adversaries:
            self.rationale.append(
                "Quantum computer in threat model requires post-quantum algorithms"
            )
            return True

        # Long protection lifetime (harvest now, decrypt later)
        if self.config.threat_model.protection_lifetime_years > 10:
            self.rationale.append(
                f"Protection lifetime of {self.config.threat_model.protection_lifetime_years} years "
                "exceeds quantum threat horizon (10 years), requiring post-quantum algorithms"
            )
            return True

        # Nation-state adversary with long-term data
        if (
            Adversary.NATION_STATE in self.config.threat_model.adversaries and
            self.config.threat_model.protection_lifetime_years > 5
        ):
            self.rationale.append(
                "Nation-state adversary with 5+ year protection requires quantum resistance"
            )
            return True

        return False

    def _should_use_hw_acceleration(self) -> bool:
        """Determine if hardware acceleration should be used."""
        # High frequency access benefits from AES-NI
        if self.config.access_patterns.frequency == AccessFrequency.HIGH:
            self.rationale.append(
                "High access frequency benefits from hardware acceleration"
            )
            return True

        # Low latency requirements need hardware acceleration
        if (
            self.config.access_patterns.latency_requirement_ms is not None and
            self.config.access_patterns.latency_requirement_ms < 10
        ):
            self.rationale.append(
                f"Latency requirement of {self.config.access_patterns.latency_requirement_ms}ms "
                "requires hardware acceleration"
            )
            return True

        # High throughput needs hardware acceleration
        if (
            self.config.access_patterns.operations_per_second is not None and
            self.config.access_patterns.operations_per_second > 1000
        ):
            self.rationale.append(
                f"Throughput of {self.config.access_patterns.operations_per_second} ops/sec "
                "requires hardware acceleration"
            )
            return True

        return False

    def _select_algorithm(
        self,
        min_bits: int,
        quantum_resistant: bool,
        hw_acceleration: bool,
    ) -> str:
        """Select the optimal algorithm based on requirements."""
        candidates = []

        for name, props in ALGORITHMS.items():
            # Filter by minimum security bits
            if props["security_bits"] < min_bits:
                continue

            # Filter by quantum resistance
            if quantum_resistant and not props["quantum_resistant"]:
                continue

            candidates.append((name, props))

        if not candidates:
            # Fallback to strongest available
            self.rationale.append(
                "No algorithm meets all requirements, using strongest available"
            )
            return "AES-256-GCM+ML-KEM-1024" if quantum_resistant else "AES-256-GCM"

        # Sort by latency (prefer faster algorithms)
        candidates.sort(key=lambda x: x[1]["latency_ms"])

        # If hardware acceleration preferred and we have AES options, prefer those
        if hw_acceleration:
            aes_candidates = [c for c in candidates if c[0].startswith("AES")]
            if aes_candidates:
                selected = aes_candidates[0][0]
                self.rationale.append(
                    f"Selected {selected} for hardware acceleration support"
                )
                return selected

        selected = candidates[0][0]
        self.rationale.append(f"Selected {selected}: {candidates[0][1]['description']}")
        return selected


def resolve_algorithm(config: ContextConfig) -> DerivedRequirements:
    """Convenience function to resolve algorithm for a context config."""
    resolver = AlgorithmResolver(config)
    return resolver.resolve()
