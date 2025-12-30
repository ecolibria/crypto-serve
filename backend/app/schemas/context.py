"""Context schemas with 5-layer model.

Layers:
1. Data Identity - What is this data, and how bad if it leaks?
2. Regulatory Mapping - What rules govern this data?
3. Threat Model - What are we protecting against?
4. Access Patterns - How is this data used?
5. Derived Requirements - Computed optimal cryptography
"""

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, computed_field


class Sensitivity(str, Enum):
    """Data sensitivity levels that drive encryption strength."""
    CRITICAL = "critical"  # 256-bit, full audit
    HIGH = "high"          # 256-bit, detailed audit
    MEDIUM = "medium"      # 128-bit, standard audit
    LOW = "low"            # 128-bit, minimal audit


class DataCategory(str, Enum):
    """Categories of data for classification."""
    PERSONAL_IDENTIFIER = "personal_identifier"
    FINANCIAL = "financial"
    HEALTH = "health"
    AUTHENTICATION = "authentication"
    BUSINESS_CONFIDENTIAL = "business_confidential"
    GENERAL = "general"


class Adversary(str, Enum):
    """Types of adversaries to protect against."""
    OPPORTUNISTIC = "opportunistic_attacker"
    ORGANIZED_CRIME = "organized_crime"
    NATION_STATE = "nation_state"
    INSIDER = "insider_threat"
    QUANTUM = "quantum_computer"


class AccessFrequency(str, Enum):
    """How often the data is accessed."""
    HIGH = "high"      # > 1000 ops/sec
    MEDIUM = "medium"  # 100-1000 ops/sec
    LOW = "low"        # 10-100 ops/sec
    RARE = "rare"      # < 10 ops/sec


# =============================================================================
# Layer 1: Data Identity
# =============================================================================

class DataIdentity(BaseModel):
    """Layer 1: What is this data, and how bad if it leaks?"""

    category: DataCategory = Field(
        default=DataCategory.GENERAL,
        description="Primary data category"
    )
    subcategory: str | None = Field(
        default=None,
        description="Specific classification within category"
    )
    sensitivity: Sensitivity = Field(
        default=Sensitivity.MEDIUM,
        description="Sensitivity level - drives encryption strength"
    )
    pii: bool = Field(
        default=False,
        description="Contains personally identifiable information"
    )
    phi: bool = Field(
        default=False,
        description="Contains protected health information"
    )
    pci: bool = Field(
        default=False,
        description="Contains payment card data"
    )
    notification_required: bool = Field(
        default=False,
        description="Must notify regulators if breached"
    )
    examples: list[str] = Field(
        default_factory=list,
        description="Example data types for developer guidance"
    )


# =============================================================================
# Layer 2: Regulatory Mapping
# =============================================================================

class RetentionPolicy(BaseModel):
    """Data retention requirements."""
    minimum_days: int | None = Field(
        default=None,
        description="Minimum retention period in days"
    )
    maximum_days: int | None = Field(
        default=None,
        description="Maximum retention period in days"
    )
    deletion_method: Literal["crypto_shred", "secure_delete", "standard"] = Field(
        default="standard",
        description="How to delete data when retention expires"
    )


class DataResidency(BaseModel):
    """Geographic restrictions on data storage."""
    allowed_regions: list[str] = Field(
        default_factory=list,
        description="AWS/cloud regions where data can be stored"
    )
    prohibited_regions: list[str] = Field(
        default_factory=list,
        description="Regions where data must not be stored"
    )


class RegulatoryMapping(BaseModel):
    """Layer 2: What rules govern this data?"""

    frameworks: list[str] = Field(
        default_factory=list,
        description="Compliance frameworks (GDPR, CCPA, PCI-DSS, HIPAA, SOX)"
    )
    data_residency: DataResidency | None = Field(
        default=None,
        description="Geographic restrictions"
    )
    retention: RetentionPolicy | None = Field(
        default=None,
        description="Data retention requirements"
    )
    cross_border_allowed: bool = Field(
        default=True,
        description="Whether data can cross national borders"
    )


# =============================================================================
# Layer 3: Threat Model
# =============================================================================

class ThreatModel(BaseModel):
    """Layer 3: What are we protecting against?"""

    adversaries: list[Adversary] = Field(
        default_factory=lambda: [Adversary.OPPORTUNISTIC],
        description="Expected threat actors"
    )
    attack_vectors: list[str] = Field(
        default_factory=list,
        description="Expected attack vectors"
    )
    protection_lifetime_years: float = Field(
        default=5.0,
        ge=0,
        description="How long data must stay protected"
    )

    @computed_field
    @property
    def quantum_resistant_required(self) -> bool:
        """Quantum resistance needed if protection > 10 years or quantum adversary."""
        return (
            self.protection_lifetime_years > 10 or
            Adversary.QUANTUM in self.adversaries
        )


# =============================================================================
# Layer 4: Access Patterns
# =============================================================================

class AccessPatterns(BaseModel):
    """Layer 4: How is this data used?"""

    frequency: AccessFrequency = Field(
        default=AccessFrequency.MEDIUM,
        description="How often data is accessed"
    )
    operations_per_second: int | None = Field(
        default=None,
        ge=0,
        description="Expected throughput"
    )
    latency_requirement_ms: int | None = Field(
        default=None,
        ge=0,
        description="Maximum acceptable latency in milliseconds"
    )
    batch_operations: bool = Field(
        default=False,
        description="Whether bulk encrypt/decrypt is needed"
    )
    search_required: bool = Field(
        default=False,
        description="Whether encrypted search is needed"
    )


# =============================================================================
# Layer 5: Derived Requirements (Computed)
# =============================================================================

class DerivedRequirements(BaseModel):
    """Layer 5: Computed optimal cryptography settings.

    This layer is automatically computed based on the other 4 layers.
    Users don't configure this directly.
    """

    minimum_security_bits: int = Field(
        description="Minimum key size in bits"
    )
    quantum_resistant: bool = Field(
        description="Whether post-quantum algorithms are required"
    )
    key_rotation_days: int = Field(
        description="How often to rotate keys"
    )
    resolved_algorithm: str = Field(
        description="Final algorithm selection"
    )
    audit_level: Literal["full", "detailed", "standard", "minimal"] = Field(
        description="Level of audit logging required"
    )
    hardware_acceleration: bool = Field(
        description="Whether to use hardware acceleration"
    )
    rationale: list[str] = Field(
        default_factory=list,
        description="Explanation for algorithm selection"
    )


# =============================================================================
# Complete Context Configuration
# =============================================================================

class ContextConfig(BaseModel):
    """Complete 5-layer context configuration."""

    data_identity: DataIdentity = Field(default_factory=DataIdentity)
    regulatory: RegulatoryMapping = Field(default_factory=RegulatoryMapping)
    threat_model: ThreatModel = Field(default_factory=ThreatModel)
    access_patterns: AccessPatterns = Field(default_factory=AccessPatterns)

    # Derived requirements are computed, not stored
    # See algorithm_resolver.py for computation logic


# =============================================================================
# API Request/Response Schemas
# =============================================================================

class ContextCreate(BaseModel):
    """Schema for creating a new context."""

    name: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z][a-z0-9-]*$",
        description="Unique context identifier (lowercase, hyphens allowed)"
    )
    display_name: str = Field(
        min_length=1,
        max_length=128,
        description="Human-readable name"
    )
    description: str = Field(
        min_length=1,
        description="Detailed description of what this context protects"
    )
    config: ContextConfig = Field(
        default_factory=ContextConfig,
        description="5-layer context configuration"
    )


class ContextUpdate(BaseModel):
    """Schema for updating an existing context."""

    display_name: str | None = None
    description: str | None = None
    config: ContextConfig | None = None


class ContextResponse(BaseModel):
    """Schema for context API responses."""

    name: str
    display_name: str
    description: str
    config: ContextConfig
    derived: DerivedRequirements

    # Legacy fields for backward compatibility
    algorithm: str
    compliance_tags: list[str]
    data_examples: list[str]

    created_at: datetime
    updated_at: datetime | None = None

    class Config:
        from_attributes = True
