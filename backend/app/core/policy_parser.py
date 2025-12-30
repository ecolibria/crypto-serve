"""YAML Policy Parser for CryptoServe.

Parses context definitions and policy rules from YAML files.
Supports both single-context and multi-context files.

Example context YAML:
```yaml
name: user-pii
display_name: User Personal Data
description: Personally identifiable information

data_identity:
  category: personal_identifier
  sensitivity: critical
  pii: true
  notification_required: true
  examples:
    - Social Security Numbers
    - Email addresses

regulatory:
  frameworks:
    - GDPR
    - CCPA
  retention:
    maximum_days: 2555
    deletion_method: crypto_shred

threat_model:
  adversaries:
    - organized_crime
    - nation_state
  protection_lifetime_years: 20

access_patterns:
  frequency: high
  latency_requirement_ms: 50
```

Example policy YAML:
```yaml
policies:
  - name: minimum-encryption-strength
    rule: algorithm.key_bits >= 256
    severity: block
    message: Encryption must use 256-bit keys minimum

  - name: no-legacy-algorithms
    rule: algorithm.name not in ['DES', '3DES', 'MD5', 'SHA1']
    severity: block
    message: Legacy algorithms are prohibited
```
"""

import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, ValidationError

from app.schemas.context import (
    ContextConfig,
    ContextCreate,
    DataIdentity,
    RegulatoryMapping,
    ThreatModel,
    AccessPatterns,
    Sensitivity,
    DataCategory,
    Adversary,
    AccessFrequency,
)


class PolicyRule(BaseModel):
    """A single policy rule definition."""

    name: str = Field(description="Unique policy name")
    rule: str = Field(description="Rule expression")
    severity: str = Field(
        default="warn",
        description="Severity: block, warn, or info"
    )
    message: str = Field(description="Human-readable message when rule triggers")
    enabled: bool = Field(default=True, description="Whether this rule is active")


class PolicyFile(BaseModel):
    """Collection of policies from a YAML file."""

    policies: list[PolicyRule] = Field(default_factory=list)


class ParseError(Exception):
    """Error parsing a YAML file."""

    def __init__(self, message: str, file_path: str | None = None, line: int | None = None):
        self.file_path = file_path
        self.line = line
        super().__init__(f"{file_path}:{line}: {message}" if line else f"{file_path}: {message}")


class PolicyParser:
    """Parses YAML policy and context definitions."""

    # Mapping from YAML string values to enum values
    SENSITIVITY_MAP = {
        "critical": Sensitivity.CRITICAL,
        "high": Sensitivity.HIGH,
        "medium": Sensitivity.MEDIUM,
        "low": Sensitivity.LOW,
    }

    CATEGORY_MAP = {
        "personal_identifier": DataCategory.PERSONAL_IDENTIFIER,
        "financial": DataCategory.FINANCIAL,
        "health": DataCategory.HEALTH,
        "authentication": DataCategory.AUTHENTICATION,
        "business_confidential": DataCategory.BUSINESS_CONFIDENTIAL,
        "general": DataCategory.GENERAL,
    }

    ADVERSARY_MAP = {
        "opportunistic_attacker": Adversary.OPPORTUNISTIC,
        "opportunistic": Adversary.OPPORTUNISTIC,
        "organized_crime": Adversary.ORGANIZED_CRIME,
        "nation_state": Adversary.NATION_STATE,
        "insider_threat": Adversary.INSIDER,
        "insider": Adversary.INSIDER,
        "quantum_computer": Adversary.QUANTUM,
        "quantum": Adversary.QUANTUM,
    }

    FREQUENCY_MAP = {
        "high": AccessFrequency.HIGH,
        "medium": AccessFrequency.MEDIUM,
        "low": AccessFrequency.LOW,
        "rare": AccessFrequency.RARE,
    }

    def parse_context_file(self, file_path: str | Path) -> ContextCreate:
        """Parse a single context definition from a YAML file."""
        file_path = Path(file_path)

        if not file_path.exists():
            raise ParseError(f"File not found: {file_path}", str(file_path))

        with open(file_path) as f:
            try:
                data = yaml.safe_load(f)
            except yaml.YAMLError as e:
                raise ParseError(f"Invalid YAML: {e}", str(file_path))

        return self.parse_context_dict(data, str(file_path))

    def parse_context_yaml(self, yaml_content: str) -> ContextCreate:
        """Parse a context definition from a YAML string."""
        try:
            data = yaml.safe_load(yaml_content)
        except yaml.YAMLError as e:
            raise ParseError(f"Invalid YAML: {e}")

        return self.parse_context_dict(data)

    def parse_context_dict(self, data: dict[str, Any], source: str = "<string>") -> ContextCreate:
        """Parse a context definition from a dictionary."""
        if not isinstance(data, dict):
            raise ParseError("Context must be a dictionary", source)

        # Required fields
        if "name" not in data:
            raise ParseError("Missing required field: name", source)
        if "display_name" not in data:
            raise ParseError("Missing required field: display_name", source)
        if "description" not in data:
            raise ParseError("Missing required field: description", source)

        # Parse each layer
        data_identity = self._parse_data_identity(data.get("data_identity", {}), source)
        regulatory = self._parse_regulatory(data.get("regulatory", {}), source)
        threat_model = self._parse_threat_model(data.get("threat_model", {}), source)
        access_patterns = self._parse_access_patterns(data.get("access_patterns", {}), source)

        config = ContextConfig(
            data_identity=data_identity,
            regulatory=regulatory,
            threat_model=threat_model,
            access_patterns=access_patterns,
        )

        return ContextCreate(
            name=data["name"],
            display_name=data["display_name"],
            description=data["description"],
            config=config,
        )

    def _parse_data_identity(self, data: dict[str, Any], source: str) -> DataIdentity:
        """Parse data identity layer."""
        if not data:
            return DataIdentity()

        # Map string values to enums
        category = data.get("category", "general")
        if category in self.CATEGORY_MAP:
            category = self.CATEGORY_MAP[category]
        else:
            category = DataCategory.GENERAL

        sensitivity = data.get("sensitivity", "medium")
        if sensitivity in self.SENSITIVITY_MAP:
            sensitivity = self.SENSITIVITY_MAP[sensitivity]
        else:
            sensitivity = Sensitivity.MEDIUM

        return DataIdentity(
            category=category,
            subcategory=data.get("subcategory"),
            sensitivity=sensitivity,
            pii=data.get("pii", False),
            phi=data.get("phi", False),
            pci=data.get("pci", False),
            notification_required=data.get("notification_required", False),
            examples=data.get("examples", []),
        )

    def _parse_regulatory(self, data: dict[str, Any], source: str) -> RegulatoryMapping:
        """Parse regulatory mapping layer."""
        if not data:
            return RegulatoryMapping()

        from app.schemas.context import RetentionPolicy, DataResidency

        retention = None
        if "retention" in data:
            r = data["retention"]
            retention = RetentionPolicy(
                minimum_days=r.get("minimum_days"),
                maximum_days=r.get("maximum_days"),
                deletion_method=r.get("deletion_method", "standard"),
            )

        residency = None
        if "data_residency" in data:
            r = data["data_residency"]
            residency = DataResidency(
                allowed_regions=r.get("allowed_regions", []),
                prohibited_regions=r.get("prohibited_regions", []),
            )

        return RegulatoryMapping(
            frameworks=data.get("frameworks", []),
            data_residency=residency,
            retention=retention,
            cross_border_allowed=data.get("cross_border_allowed", True),
        )

    def _parse_threat_model(self, data: dict[str, Any], source: str) -> ThreatModel:
        """Parse threat model layer."""
        if not data:
            return ThreatModel()

        # Map adversary strings to enums
        adversaries = []
        for adv in data.get("adversaries", []):
            if adv in self.ADVERSARY_MAP:
                adversaries.append(self.ADVERSARY_MAP[adv])

        return ThreatModel(
            adversaries=adversaries if adversaries else [Adversary.OPPORTUNISTIC],
            attack_vectors=data.get("attack_vectors", []),
            protection_lifetime_years=data.get("protection_lifetime_years", 5.0),
        )

    def _parse_access_patterns(self, data: dict[str, Any], source: str) -> AccessPatterns:
        """Parse access patterns layer."""
        if not data:
            return AccessPatterns()

        frequency = data.get("frequency", "medium")
        if frequency in self.FREQUENCY_MAP:
            frequency = self.FREQUENCY_MAP[frequency]
        else:
            frequency = AccessFrequency.MEDIUM

        return AccessPatterns(
            frequency=frequency,
            operations_per_second=data.get("operations_per_second"),
            latency_requirement_ms=data.get("latency_requirement_ms"),
            batch_operations=data.get("batch_operations", False),
            search_required=data.get("search_required", False),
        )

    def parse_policies_file(self, file_path: str | Path) -> PolicyFile:
        """Parse a policy definitions file."""
        file_path = Path(file_path)

        if not file_path.exists():
            raise ParseError(f"File not found: {file_path}", str(file_path))

        with open(file_path) as f:
            try:
                data = yaml.safe_load(f)
            except yaml.YAMLError as e:
                raise ParseError(f"Invalid YAML: {e}", str(file_path))

        return self.parse_policies_dict(data, str(file_path))

    def parse_policies_yaml(self, yaml_content: str) -> PolicyFile:
        """Parse policies from a YAML string."""
        try:
            data = yaml.safe_load(yaml_content)
        except yaml.YAMLError as e:
            raise ParseError(f"Invalid YAML: {e}")

        return self.parse_policies_dict(data)

    def parse_policies_dict(self, data: dict[str, Any], source: str = "<string>") -> PolicyFile:
        """Parse policies from a dictionary."""
        if not isinstance(data, dict):
            raise ParseError("Policies file must be a dictionary", source)

        if "policies" not in data:
            raise ParseError("Missing required field: policies", source)

        policies = []
        for i, policy_data in enumerate(data["policies"]):
            try:
                policy = PolicyRule.model_validate(policy_data)
                policies.append(policy)
            except ValidationError as e:
                raise ParseError(f"Invalid policy at index {i}: {e}", source)

        return PolicyFile(policies=policies)

    def parse_multi_context_file(self, file_path: str | Path) -> list[ContextCreate]:
        """Parse multiple context definitions from a YAML file.

        The file should have a 'contexts' key with a list of context definitions.
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise ParseError(f"File not found: {file_path}", str(file_path))

        with open(file_path) as f:
            try:
                data = yaml.safe_load(f)
            except yaml.YAMLError as e:
                raise ParseError(f"Invalid YAML: {e}", str(file_path))

        if not isinstance(data, dict) or "contexts" not in data:
            raise ParseError("Multi-context file must have 'contexts' key", str(file_path))

        contexts = []
        for i, ctx_data in enumerate(data["contexts"]):
            try:
                context = self.parse_context_dict(ctx_data, f"{file_path}:contexts[{i}]")
                contexts.append(context)
            except ParseError as e:
                raise ParseError(f"Error in context {i}: {e}", str(file_path))

        return contexts


# Convenience functions
def parse_context(yaml_content: str) -> ContextCreate:
    """Parse a context from YAML string."""
    return PolicyParser().parse_context_yaml(yaml_content)


def parse_context_file(file_path: str | Path) -> ContextCreate:
    """Parse a context from a YAML file."""
    return PolicyParser().parse_context_file(file_path)


def parse_policies(yaml_content: str) -> PolicyFile:
    """Parse policies from YAML string."""
    return PolicyParser().parse_policies_yaml(yaml_content)


def parse_policies_file(file_path: str | Path) -> PolicyFile:
    """Parse policies from a YAML file."""
    return PolicyParser().parse_policies_file(file_path)
