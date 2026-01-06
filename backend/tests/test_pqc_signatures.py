"""Tests for Post-Quantum Cryptography signatures.

Tests the SLHDSA (FIPS 205) and MLDSA (FIPS 204) implementations
from hybrid_crypto.py.
"""

import pytest

from app.core.hybrid_crypto import (
    SLHDSA,
    MLDSA,
    PQCError,
    is_pqc_available,
    get_slhdsa,
    get_mldsa,
    get_available_slhdsa_algorithms,
    get_available_sig_algorithms,
    get_all_available_sig_algorithms,
    LIBOQS_AVAILABLE,
)


# Skip all tests if liboqs is not available
pytestmark = pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not installed")


class TestPQCAvailability:
    """Tests for PQC availability checks."""

    def test_is_pqc_available(self):
        """Test PQC availability function."""
        assert is_pqc_available() == LIBOQS_AVAILABLE

    def test_get_available_slhdsa_algorithms(self):
        """Test listing SLH-DSA algorithms."""
        algos = get_available_slhdsa_algorithms()
        assert len(algos) == 6
        assert "SLH-DSA-SHA2-128f" in algos
        assert "SLH-DSA-SHA2-128s" in algos
        assert "SLH-DSA-SHA2-192f" in algos
        assert "SLH-DSA-SHA2-192s" in algos
        assert "SLH-DSA-SHA2-256f" in algos
        assert "SLH-DSA-SHA2-256s" in algos

    def test_get_available_mldsa_algorithms(self):
        """Test listing ML-DSA algorithms."""
        algos = get_available_sig_algorithms()
        assert len(algos) == 3
        assert "ML-DSA-44" in algos
        assert "ML-DSA-65" in algos
        assert "ML-DSA-87" in algos

    def test_get_all_sig_algorithms(self):
        """Test listing all PQC signature algorithms."""
        algos = get_all_available_sig_algorithms()
        assert len(algos) == 9  # 3 ML-DSA + 6 SLH-DSA


class TestSLHDSA:
    """Tests for SLH-DSA (FIPS 205) implementation."""

    @pytest.mark.parametrize(
        "algorithm",
        [
            "SLH-DSA-SHA2-128f",
            "SLH-DSA-SHA2-128s",
        ],
    )
    def test_slhdsa_keypair_generation(self, algorithm):
        """Test SLH-DSA key pair generation."""
        slhdsa = get_slhdsa(algorithm)
        public_key = slhdsa.generate_keypair()

        assert public_key is not None
        assert slhdsa.public_key is not None
        assert slhdsa.private_key is not None
        assert len(public_key) == SLHDSA.PARAMS[algorithm]["pk_len"]
        assert len(slhdsa.private_key) == SLHDSA.PARAMS[algorithm]["sk_len"]

    @pytest.mark.parametrize(
        "algorithm",
        [
            "SLH-DSA-SHA2-128f",
            "SLH-DSA-SHA2-128s",
        ],
    )
    def test_slhdsa_sign_verify(self, algorithm):
        """Test SLH-DSA sign and verify roundtrip."""
        slhdsa = get_slhdsa(algorithm)
        public_key = slhdsa.generate_keypair()

        message = b"Test message for SLH-DSA signature"
        signature = slhdsa.sign(message)

        assert signature is not None
        assert len(signature) == SLHDSA.PARAMS[algorithm]["sig_len"]

        # Verify
        is_valid = slhdsa.verify(message, signature, public_key)
        assert is_valid is True

    def test_slhdsa_verify_wrong_message(self):
        """Test SLH-DSA verification fails for wrong message."""
        slhdsa = get_slhdsa("SLH-DSA-SHA2-128f")
        public_key = slhdsa.generate_keypair()

        message = b"Original message"
        signature = slhdsa.sign(message)

        # Verify with wrong message
        wrong_message = b"Wrong message"
        is_valid = slhdsa.verify(wrong_message, signature, public_key)
        assert is_valid is False

    def test_slhdsa_verify_wrong_signature(self):
        """Test SLH-DSA verification fails for corrupted signature."""
        slhdsa = get_slhdsa("SLH-DSA-SHA2-128f")
        public_key = slhdsa.generate_keypair()

        message = b"Test message"
        signature = slhdsa.sign(message)

        # Corrupt the signature
        corrupted_sig = bytearray(signature)
        corrupted_sig[0] ^= 0xFF
        corrupted_sig = bytes(corrupted_sig)

        is_valid = slhdsa.verify(message, corrupted_sig, public_key)
        assert is_valid is False

    def test_slhdsa_verify_wrong_key(self):
        """Test SLH-DSA verification fails for wrong public key."""
        slhdsa1 = get_slhdsa("SLH-DSA-SHA2-128f")
        slhdsa2 = get_slhdsa("SLH-DSA-SHA2-128f")

        slhdsa1.generate_keypair()
        public_key2 = slhdsa2.generate_keypair()

        message = b"Test message"
        signature = slhdsa1.sign(message)

        # Verify with wrong public key
        is_valid = slhdsa1.verify(message, signature, public_key2)
        assert is_valid is False

    def test_slhdsa_sign_without_key_fails(self):
        """Test SLH-DSA sign without generating key fails."""
        slhdsa = get_slhdsa("SLH-DSA-SHA2-128f")

        with pytest.raises(PQCError, match="No private key"):
            slhdsa.sign(b"Test message")

    def test_slhdsa_set_keypair(self):
        """Test setting an existing key pair."""
        # Generate key pair
        slhdsa1 = get_slhdsa("SLH-DSA-SHA2-128f")
        public_key = slhdsa1.generate_keypair()
        private_key = slhdsa1.private_key

        # Create new instance with existing keys
        slhdsa2 = get_slhdsa("SLH-DSA-SHA2-128f")
        slhdsa2.set_keypair(public_key, private_key)

        # Should be able to sign
        message = b"Test message"
        signature = slhdsa2.sign(message)

        # Verify with original instance
        is_valid = slhdsa1.verify(message, signature, public_key)
        assert is_valid is True

    def test_slhdsa_get_details(self):
        """Test getting algorithm details."""
        slhdsa = get_slhdsa("SLH-DSA-SHA2-128f")
        details = slhdsa.get_details()

        assert details["algorithm"] == "SLH-DSA-SHA2-128f"
        assert details["nist_level"] == 1
        assert details["variant"] == "fast"
        assert details["public_key_bytes"] == 32
        assert details["secret_key_bytes"] == 64
        assert details["signature_bytes"] == 17088
        assert details["standard"] == "NIST FIPS 205"
        assert details["security_basis"] == "hash-based (conservative)"

    def test_slhdsa_invalid_algorithm(self):
        """Test SLH-DSA with invalid algorithm name."""
        with pytest.raises(ValueError, match="Unknown algorithm"):
            get_slhdsa("SLH-DSA-INVALID")


class TestMLDSA:
    """Tests for ML-DSA (FIPS 204) implementation."""

    @pytest.mark.parametrize(
        "algorithm",
        [
            "ML-DSA-44",
            "ML-DSA-65",
            "ML-DSA-87",
        ],
    )
    def test_mldsa_keypair_generation(self, algorithm):
        """Test ML-DSA key pair generation."""
        mldsa = get_mldsa(algorithm)
        public_key = mldsa.generate_keypair()

        assert public_key is not None
        assert mldsa.public_key is not None
        assert mldsa.private_key is not None
        assert len(public_key) == MLDSA.PARAMS[algorithm]["pk_len"]
        assert len(mldsa.private_key) == MLDSA.PARAMS[algorithm]["sk_len"]

    @pytest.mark.parametrize(
        "algorithm",
        [
            "ML-DSA-44",
            "ML-DSA-65",
            "ML-DSA-87",
        ],
    )
    def test_mldsa_sign_verify(self, algorithm):
        """Test ML-DSA sign and verify roundtrip."""
        mldsa = get_mldsa(algorithm)
        public_key = mldsa.generate_keypair()

        message = b"Test message for ML-DSA signature"
        signature = mldsa.sign(message)

        assert signature is not None
        assert len(signature) == MLDSA.PARAMS[algorithm]["sig_len"]

        # Verify
        is_valid = mldsa.verify(message, signature, public_key)
        assert is_valid is True

    def test_mldsa_verify_wrong_message(self):
        """Test ML-DSA verification fails for wrong message."""
        mldsa = get_mldsa("ML-DSA-65")
        public_key = mldsa.generate_keypair()

        message = b"Original message"
        signature = mldsa.sign(message)

        # Verify with wrong message
        wrong_message = b"Wrong message"
        is_valid = mldsa.verify(wrong_message, signature, public_key)
        assert is_valid is False

    def test_mldsa_verify_wrong_signature(self):
        """Test ML-DSA verification fails for corrupted signature."""
        mldsa = get_mldsa("ML-DSA-65")
        public_key = mldsa.generate_keypair()

        message = b"Test message"
        signature = mldsa.sign(message)

        # Corrupt the signature
        corrupted_sig = bytearray(signature)
        corrupted_sig[0] ^= 0xFF
        corrupted_sig = bytes(corrupted_sig)

        is_valid = mldsa.verify(message, corrupted_sig, public_key)
        assert is_valid is False

    def test_mldsa_get_details(self):
        """Test getting algorithm details."""
        mldsa = get_mldsa("ML-DSA-65")
        details = mldsa.get_details()

        assert details["algorithm"] == "ML-DSA-65"
        assert details["nist_level"] == 3
        assert details["public_key_bytes"] == 1952
        assert details["secret_key_bytes"] == 4032
        assert details["signature_bytes"] == 3309
        assert details["standard"] == "NIST FIPS 204"


class TestFactoryFunctions:
    """Tests for factory functions."""

    def test_get_slhdsa_default(self):
        """Test get_slhdsa with default algorithm."""
        slhdsa = get_slhdsa()
        assert slhdsa.algorithm == "SLH-DSA-SHA2-128f"

    def test_get_mldsa_default(self):
        """Test get_mldsa with default algorithm."""
        mldsa = get_mldsa()
        assert mldsa.algorithm == "ML-DSA-65"

    def test_get_slhdsa_all_variants(self):
        """Test all SLH-DSA variants can be instantiated."""
        for algo in get_available_slhdsa_algorithms():
            slhdsa = get_slhdsa(algo)
            assert slhdsa.algorithm == algo

    def test_get_mldsa_all_variants(self):
        """Test all ML-DSA variants can be instantiated."""
        for algo in get_available_sig_algorithms():
            mldsa = get_mldsa(algo)
            assert mldsa.algorithm == algo


class TestSecurityLevels:
    """Tests for NIST security levels."""

    @pytest.mark.parametrize(
        "algorithm,expected_level",
        [
            ("SLH-DSA-SHA2-128f", 1),
            ("SLH-DSA-SHA2-128s", 1),
            ("SLH-DSA-SHA2-192f", 3),
            ("SLH-DSA-SHA2-192s", 3),
            ("SLH-DSA-SHA2-256f", 5),
            ("SLH-DSA-SHA2-256s", 5),
        ],
    )
    def test_slhdsa_security_levels(self, algorithm, expected_level):
        """Test SLH-DSA security level mapping."""
        slhdsa = get_slhdsa(algorithm)
        details = slhdsa.get_details()
        assert details["nist_level"] == expected_level

    @pytest.mark.parametrize(
        "algorithm,expected_level",
        [
            ("ML-DSA-44", 2),
            ("ML-DSA-65", 3),
            ("ML-DSA-87", 5),
        ],
    )
    def test_mldsa_security_levels(self, algorithm, expected_level):
        """Test ML-DSA security level mapping."""
        mldsa = get_mldsa(algorithm)
        details = mldsa.get_details()
        assert details["nist_level"] == expected_level


class TestSLHDSAVariants:
    """Tests comparing fast vs small SLH-DSA variants."""

    def test_small_variant_smaller_signatures(self):
        """Test that 'small' variant produces smaller signatures than 'fast'."""
        fast = get_slhdsa("SLH-DSA-SHA2-128f")
        small = get_slhdsa("SLH-DSA-SHA2-128s")

        fast_details = fast.get_details()
        small_details = small.get_details()

        assert small_details["signature_bytes"] < fast_details["signature_bytes"]
        # Fast: 17088 bytes, Small: 7856 bytes
        assert fast_details["signature_bytes"] == 17088
        assert small_details["signature_bytes"] == 7856
