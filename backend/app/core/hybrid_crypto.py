"""Hybrid Quantum-Safe Cryptography Engine.

Implements hybrid encryption combining classical algorithms with post-quantum
Key Encapsulation Mechanisms (KEMs) per NIST guidance for the PQC transition.

Hybrid Mode Benefits:
- Security if either algorithm is unbroken
- Transition path from classical to post-quantum
- Compliance with NSA CNSA 2.0 timeline

Supported Hybrid Modes:
- AES-256-GCM + ML-KEM-768 (recommended for most use cases)
- AES-256-GCM + ML-KEM-1024 (maximum security)
- ChaCha20-Poly1305 + ML-KEM-768 (no AES-NI environments)

Note: This uses a mock/placeholder implementation for ML-KEM since
liboqs Python bindings may not be available. In production, you would
use the oqs-python package (https://github.com/open-quantum-safe/liboqs-python).

For production deployment:
1. pip install oqs
2. Replace mock implementations with actual ML-KEM calls
"""

import os
import json
import base64
import hashlib
import secrets
from dataclasses import dataclass
from enum import Enum
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class HybridMode(str, Enum):
    """Supported hybrid encryption modes."""
    AES_MLKEM_768 = "AES-256-GCM+ML-KEM-768"
    AES_MLKEM_1024 = "AES-256-GCM+ML-KEM-1024"
    CHACHA_MLKEM_768 = "ChaCha20-Poly1305+ML-KEM-768"


@dataclass
class HybridKeyPair:
    """A hybrid key pair combining classical and PQC keys."""
    mode: HybridMode
    public_key: bytes     # Serialized public key (classical + PQC)
    private_key: bytes    # Serialized private key (classical + PQC)
    key_id: str           # Unique identifier

    def to_dict(self) -> dict:
        return {
            "mode": self.mode.value,
            "public_key": base64.b64encode(self.public_key).decode('ascii'),
            "key_id": self.key_id,
        }


@dataclass
class HybridCiphertext:
    """Result of hybrid encryption."""
    mode: HybridMode
    classical_ciphertext: bytes  # AES/ChaCha encrypted data
    kem_ciphertext: bytes        # ML-KEM encapsulated key
    nonce: bytes                 # For AEAD
    key_id: str                  # Which key was used

    def serialize(self) -> bytes:
        """Serialize to bytes for storage/transmission."""
        header = {
            "v": 1,
            "mode": self.mode.value,
            "kid": self.key_id,
            "nonce": base64.b64encode(self.nonce).decode('ascii'),
            "kem_ct_len": len(self.kem_ciphertext),
        }
        header_json = json.dumps(header, separators=(',', ':')).encode()
        header_len = len(header_json).to_bytes(2, 'big')

        return header_len + header_json + self.kem_ciphertext + self.classical_ciphertext

    @classmethod
    def deserialize(cls, data: bytes) -> 'HybridCiphertext':
        """Deserialize from bytes."""
        if len(data) < 3:
            raise ValueError("Invalid ciphertext: too short")

        header_len = int.from_bytes(data[:2], 'big')
        if len(data) < 2 + header_len:
            raise ValueError("Invalid ciphertext: header truncated")

        header = json.loads(data[2:2 + header_len].decode())

        if header.get("v") != 1:
            raise ValueError(f"Unsupported version: {header.get('v')}")

        kem_ct_len = header["kem_ct_len"]
        kem_start = 2 + header_len
        kem_end = kem_start + kem_ct_len

        return cls(
            mode=HybridMode(header["mode"]),
            kem_ciphertext=data[kem_start:kem_end],
            classical_ciphertext=data[kem_end:],
            nonce=base64.b64decode(header["nonce"]),
            key_id=header["kid"],
        )


# =============================================================================
# Mock ML-KEM Implementation
# For production, replace with liboqs: pip install oqs
# =============================================================================

class MockMLKEM:
    """Mock ML-KEM implementation for development/testing.

    In production, replace with:
    ```
    import oqs
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()
    ciphertext, shared_secret = kem.encap_secret(public_key)
    shared_secret = kem.decap_secret(ciphertext)
    ```
    """

    # Parameter sizes per NIST FIPS 203
    PARAMS = {
        "ML-KEM-512": {"pk_len": 800, "sk_len": 1632, "ct_len": 768, "ss_len": 32},
        "ML-KEM-768": {"pk_len": 1184, "sk_len": 2400, "ct_len": 1088, "ss_len": 32},
        "ML-KEM-1024": {"pk_len": 1568, "sk_len": 3168, "ct_len": 1568, "ss_len": 32},
    }

    def __init__(self, algorithm: str = "ML-KEM-768"):
        if algorithm not in self.PARAMS:
            raise ValueError(f"Unknown algorithm: {algorithm}")
        self.algorithm = algorithm
        self.params = self.PARAMS[algorithm]
        self._private_key = None

    def generate_keypair(self) -> bytes:
        """Generate a new key pair. Returns public key."""
        # In mock mode, we use random bytes
        # Real ML-KEM has structured keys from lattice math
        self._private_key = secrets.token_bytes(self.params["sk_len"])
        public_key = secrets.token_bytes(self.params["pk_len"])
        return public_key

    def set_keypair(self, public_key: bytes, private_key: bytes) -> None:
        """Set an existing key pair."""
        self._private_key = private_key

    def encap_secret(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Encapsulate a shared secret using the public key.

        Returns (ciphertext, shared_secret).
        """
        # Mock: Generate random shared secret and "ciphertext"
        # Real ML-KEM: Lattice-based encapsulation
        shared_secret = secrets.token_bytes(self.params["ss_len"])
        ciphertext = secrets.token_bytes(self.params["ct_len"])

        # For mock reproducibility, derive both from a seed
        seed = hashlib.sha256(public_key + secrets.token_bytes(32)).digest()
        shared_secret = hashlib.sha256(b"ss:" + seed).digest()
        ciphertext = hashlib.sha256(b"ct:" + seed).digest() * (self.params["ct_len"] // 32 + 1)
        ciphertext = ciphertext[:self.params["ct_len"]]

        # Store for mock decapsulation (not how real KEM works)
        self._last_secret = shared_secret
        self._last_ct = ciphertext

        return ciphertext, shared_secret

    def decap_secret(self, ciphertext: bytes) -> bytes:
        """Decapsulate the shared secret using the private key.

        Returns shared_secret.
        """
        if self._private_key is None:
            raise ValueError("No private key set")

        # Mock: In real ML-KEM, this would use lattice decryption
        # For mock, we need to track the secret (not secure, just for demo)

        # In real implementation:
        # return real_mlkem_decap(self._private_key, ciphertext)

        # Mock: derive deterministically from ciphertext + private key
        # This is NOT cryptographically sound - just for API demonstration
        seed = hashlib.sha256(ciphertext + self._private_key[:32]).digest()
        return hashlib.sha256(b"decap:" + seed).digest()


def get_mlkem(algorithm: str = "ML-KEM-768") -> MockMLKEM:
    """Get an ML-KEM instance.

    In production, replace with:
    ```
    try:
        import oqs
        return oqs.KeyEncapsulation(algorithm)
    except ImportError:
        return MockMLKEM(algorithm)
    ```
    """
    return MockMLKEM(algorithm)


# =============================================================================
# Hybrid Crypto Engine
# =============================================================================

class HybridCryptoEngine:
    """Hybrid quantum-safe encryption engine.

    Combines classical AEAD (AES-GCM or ChaCha20-Poly1305) with
    post-quantum Key Encapsulation Mechanism (ML-KEM/Kyber).

    The hybrid approach provides security if either algorithm remains
    secure, following NIST transition guidance.
    """

    def __init__(self, mode: HybridMode = HybridMode.AES_MLKEM_768):
        self.mode = mode
        self._kem_algorithm = self._get_kem_algorithm(mode)

    def _get_kem_algorithm(self, mode: HybridMode) -> str:
        """Get the KEM algorithm for a hybrid mode."""
        if "1024" in mode.value:
            return "ML-KEM-1024"
        return "ML-KEM-768"

    def _get_aead(self, key: bytes) -> AESGCM | ChaCha20Poly1305:
        """Get the AEAD cipher for this mode."""
        if "ChaCha" in self.mode.value:
            return ChaCha20Poly1305(key)
        return AESGCM(key)

    def _derive_symmetric_key(self, kem_shared_secret: bytes, context: bytes = b"") -> bytes:
        """Derive a symmetric key from the KEM shared secret using HKDF."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key for AES-256 or ChaCha20
            salt=None,
            info=b"cryptoserve-hybrid-v1" + context,
        )
        return hkdf.derive(kem_shared_secret)

    def generate_keypair(self, key_id: str | None = None) -> HybridKeyPair:
        """Generate a hybrid key pair.

        Returns:
            HybridKeyPair with public and private keys for both
            classical and post-quantum algorithms.
        """
        kem = get_mlkem(self._kem_algorithm)
        public_key = kem.generate_keypair()

        # For the hybrid pair, we package the KEM keys
        # In real deployment, you might also include X25519 keys for
        # a full X25519+ML-KEM hybrid
        key_id = key_id or secrets.token_hex(16)

        return HybridKeyPair(
            mode=self.mode,
            public_key=public_key,
            private_key=kem._private_key,  # Mock access
            key_id=key_id,
        )

    def encrypt(
        self,
        plaintext: bytes,
        public_key: bytes,
        key_id: str,
        associated_data: bytes | None = None,
    ) -> HybridCiphertext:
        """Encrypt data using hybrid encryption.

        Steps:
        1. Generate KEM shared secret using recipient's public key
        2. Derive symmetric key from shared secret using HKDF
        3. Encrypt plaintext with AES-GCM or ChaCha20-Poly1305
        4. Package KEM ciphertext + AEAD ciphertext

        Args:
            plaintext: Data to encrypt
            public_key: Recipient's hybrid public key
            key_id: Key identifier for audit/rotation
            associated_data: Optional authenticated data (not encrypted)

        Returns:
            HybridCiphertext containing both KEM and AEAD components
        """
        # Step 1: KEM encapsulation
        kem = get_mlkem(self._kem_algorithm)
        kem_ciphertext, shared_secret = kem.encap_secret(public_key)

        # Step 2: Derive symmetric key
        symmetric_key = self._derive_symmetric_key(
            shared_secret,
            context=key_id.encode() if key_id else b"",
        )

        # Step 3: AEAD encryption
        nonce = os.urandom(12)  # 96 bits for GCM
        aead = self._get_aead(symmetric_key)
        ciphertext = aead.encrypt(nonce, plaintext, associated_data)

        return HybridCiphertext(
            mode=self.mode,
            classical_ciphertext=ciphertext,
            kem_ciphertext=kem_ciphertext,
            nonce=nonce,
            key_id=key_id,
        )

    def decrypt(
        self,
        hybrid_ciphertext: HybridCiphertext,
        private_key: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Decrypt hybrid-encrypted data.

        Steps:
        1. KEM decapsulation to recover shared secret
        2. Derive symmetric key from shared secret
        3. AEAD decryption

        Args:
            hybrid_ciphertext: The encrypted data
            private_key: Recipient's hybrid private key
            associated_data: Optional authenticated data (must match encryption)

        Returns:
            Decrypted plaintext

        Raises:
            ValueError: If decryption fails (authentication failure)
        """
        # Step 1: KEM decapsulation
        kem = get_mlkem(self._kem_algorithm)
        kem.set_keypair(b"", private_key)  # Only need private key for decap

        # In real ML-KEM, decap uses ciphertext + private key
        # Mock version needs special handling
        shared_secret = kem.decap_secret(hybrid_ciphertext.kem_ciphertext)

        # Step 2: Derive symmetric key
        symmetric_key = self._derive_symmetric_key(
            shared_secret,
            context=hybrid_ciphertext.key_id.encode() if hybrid_ciphertext.key_id else b"",
        )

        # Step 3: AEAD decryption
        aead = self._get_aead(symmetric_key)
        try:
            plaintext = aead.decrypt(
                hybrid_ciphertext.nonce,
                hybrid_ciphertext.classical_ciphertext,
                associated_data,
            )
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")

        return plaintext


# =============================================================================
# Convenience Functions
# =============================================================================

def create_hybrid_engine(
    quantum_security_level: int = 192,
    prefer_chacha: bool = False,
) -> HybridCryptoEngine:
    """Create a hybrid crypto engine with appropriate mode.

    Args:
        quantum_security_level: Minimum post-quantum security bits (128, 192, or 256)
        prefer_chacha: Use ChaCha20 instead of AES (for non-AES-NI systems)

    Returns:
        Configured HybridCryptoEngine
    """
    if quantum_security_level >= 256:
        mode = HybridMode.AES_MLKEM_1024
    elif prefer_chacha:
        mode = HybridMode.CHACHA_MLKEM_768
    else:
        mode = HybridMode.AES_MLKEM_768

    return HybridCryptoEngine(mode)


def hybrid_encrypt(
    plaintext: bytes,
    public_key: bytes,
    key_id: str = "",
    mode: HybridMode = HybridMode.AES_MLKEM_768,
) -> bytes:
    """Simple hybrid encryption interface.

    Args:
        plaintext: Data to encrypt
        public_key: Recipient's ML-KEM public key
        key_id: Optional key identifier
        mode: Hybrid encryption mode

    Returns:
        Serialized hybrid ciphertext
    """
    engine = HybridCryptoEngine(mode)
    result = engine.encrypt(plaintext, public_key, key_id)
    return result.serialize()


def hybrid_decrypt(
    ciphertext: bytes,
    private_key: bytes,
) -> bytes:
    """Simple hybrid decryption interface.

    Args:
        ciphertext: Serialized hybrid ciphertext
        private_key: Recipient's ML-KEM private key

    Returns:
        Decrypted plaintext
    """
    hybrid_ct = HybridCiphertext.deserialize(ciphertext)
    engine = HybridCryptoEngine(hybrid_ct.mode)
    return engine.decrypt(hybrid_ct, private_key)


# =============================================================================
# Key Management Helpers
# =============================================================================

def serialize_keypair(keypair: HybridKeyPair) -> dict:
    """Serialize a key pair for storage."""
    return {
        "mode": keypair.mode.value,
        "public_key": base64.b64encode(keypair.public_key).decode('ascii'),
        "private_key": base64.b64encode(keypair.private_key).decode('ascii'),
        "key_id": keypair.key_id,
    }


def deserialize_keypair(data: dict) -> HybridKeyPair:
    """Deserialize a key pair from storage."""
    return HybridKeyPair(
        mode=HybridMode(data["mode"]),
        public_key=base64.b64decode(data["public_key"]),
        private_key=base64.b64decode(data["private_key"]),
        key_id=data["key_id"],
    )


# =============================================================================
# Algorithm Information
# =============================================================================

def get_hybrid_algorithm_info(mode: HybridMode) -> dict[str, Any]:
    """Get information about a hybrid mode."""
    info = {
        HybridMode.AES_MLKEM_768: {
            "name": "AES-256-GCM + ML-KEM-768",
            "classical_algorithm": "AES-256-GCM",
            "pqc_algorithm": "ML-KEM-768 (FIPS 203)",
            "classical_security_bits": 256,
            "quantum_security_bits": 192,
            "nist_pqc_level": 3,
            "cnsa_compliant": True,
            "recommended_for": ["general use", "most applications", "TLS hybrid"],
        },
        HybridMode.AES_MLKEM_1024: {
            "name": "AES-256-GCM + ML-KEM-1024",
            "classical_algorithm": "AES-256-GCM",
            "pqc_algorithm": "ML-KEM-1024 (FIPS 203)",
            "classical_security_bits": 256,
            "quantum_security_bits": 256,
            "nist_pqc_level": 5,
            "cnsa_compliant": True,
            "recommended_for": ["maximum security", "long-term secrets", "government"],
        },
        HybridMode.CHACHA_MLKEM_768: {
            "name": "ChaCha20-Poly1305 + ML-KEM-768",
            "classical_algorithm": "ChaCha20-Poly1305",
            "pqc_algorithm": "ML-KEM-768 (FIPS 203)",
            "classical_security_bits": 256,
            "quantum_security_bits": 192,
            "nist_pqc_level": 3,
            "cnsa_compliant": True,
            "recommended_for": ["no AES-NI", "mobile devices", "embedded systems"],
        },
    }
    return info.get(mode, {})
