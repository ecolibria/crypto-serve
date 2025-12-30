"""CryptoServe CLI tools.

Available CLI tools:
- cryptoserve: Unified CLI entry point
- cryptoserve-policy: Policy validation and compliance checking
- cryptoserve-migrate: Codebase migration and crypto scanning
- cryptoserve-heal: Self-healing and remediation

Usage:
    ./cryptoserve policy check -a AES-256-GCM
    ./cryptoserve migrate scan ./src
    ./cryptoserve heal status
"""

from .policy_cli import main as policy_main
from .migrate_cli import main as migrate_main
from .heal_cli import main as heal_main

__all__ = ["policy_main", "migrate_main", "heal_main"]
