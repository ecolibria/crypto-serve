"""Tests for the key export/import engine."""

import pytest
import os

from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from app.core.key_export import (
    KeyExportEngine,
    KeyFormat,
    KeyType,
    KeyExportError,
    KeyImportError,
)


@pytest.fixture
def fresh_engine():
    """Create a fresh key export engine."""
    return KeyExportEngine()


class TestSymmetricKeyExport:
    """Tests for symmetric key export."""

    def test_export_raw(self, fresh_engine):
        """Test exporting symmetric key as raw bytes."""
        key = os.urandom(32)

        result = fresh_engine.export_symmetric_key(key, KeyFormat.RAW)

        assert result.key_data == key
        assert result.format == KeyFormat.RAW
        assert result.key_type == KeyType.SYMMETRIC
        assert result.is_private

    def test_export_jwk(self, fresh_engine):
        """Test exporting symmetric key as JWK."""
        key = os.urandom(32)

        result = fresh_engine.export_symmetric_key(key, KeyFormat.JWK, kid="test-key")

        assert isinstance(result.key_data, dict)
        assert result.key_data["kty"] == "oct"
        assert result.key_data["kid"] == "test-key"
        assert "k" in result.key_data

    def test_export_wrapped(self, fresh_engine):
        """Test exporting symmetric key with AES Key Wrap."""
        key = os.urandom(32)
        kek = os.urandom(32)

        result = fresh_engine.export_symmetric_key(key, KeyFormat.WRAPPED, kek=kek)

        assert result.format == KeyFormat.WRAPPED
        assert len(result.key_data) == 40  # 32 + 8 bytes overhead

    def test_export_wrapped_requires_kek(self, fresh_engine):
        """Test that wrapped export requires KEK."""
        key = os.urandom(32)

        with pytest.raises(KeyExportError):
            fresh_engine.export_symmetric_key(key, KeyFormat.WRAPPED)

    def test_export_encrypted(self, fresh_engine):
        """Test exporting symmetric key with password encryption."""
        key = os.urandom(32)
        password = "test-password-123"

        result = fresh_engine.export_symmetric_key(key, KeyFormat.ENCRYPTED, password=password)

        assert result.format == KeyFormat.ENCRYPTED
        assert isinstance(result.key_data, str)
        # Should be JSON
        import json

        data = json.loads(result.key_data)
        assert "salt" in data
        assert "iv" in data
        assert "ciphertext" in data

    def test_export_encrypted_requires_password(self, fresh_engine):
        """Test that encrypted export requires password."""
        key = os.urandom(32)

        with pytest.raises(KeyExportError):
            fresh_engine.export_symmetric_key(key, KeyFormat.ENCRYPTED)


class TestSymmetricKeyImport:
    """Tests for symmetric key import."""

    def test_import_raw(self, fresh_engine):
        """Test importing raw symmetric key."""
        key = os.urandom(32)

        result = fresh_engine.import_symmetric_key(key, KeyFormat.RAW)

        assert result.key == key
        assert result.key_type == KeyType.SYMMETRIC

    def test_import_jwk(self, fresh_engine):
        """Test importing JWK symmetric key."""
        key = os.urandom(32)
        exported = fresh_engine.export_symmetric_key(key, KeyFormat.JWK, kid="test")

        result = fresh_engine.import_symmetric_key(exported.key_data, KeyFormat.JWK)

        assert result.key == key
        assert result.kid == "test"

    def test_import_wrapped(self, fresh_engine):
        """Test importing wrapped symmetric key."""
        key = os.urandom(32)
        kek = os.urandom(32)
        exported = fresh_engine.export_symmetric_key(key, KeyFormat.WRAPPED, kek=kek)

        result = fresh_engine.import_symmetric_key(exported.key_data, KeyFormat.WRAPPED, kek=kek)

        assert result.key == key

    def test_import_wrapped_wrong_kek(self, fresh_engine):
        """Test importing wrapped key with wrong KEK fails."""
        key = os.urandom(32)
        kek1 = os.urandom(32)
        kek2 = os.urandom(32)
        exported = fresh_engine.export_symmetric_key(key, KeyFormat.WRAPPED, kek=kek1)

        with pytest.raises(KeyImportError):
            fresh_engine.import_symmetric_key(exported.key_data, KeyFormat.WRAPPED, kek=kek2)

    def test_import_encrypted(self, fresh_engine):
        """Test importing encrypted symmetric key."""
        key = os.urandom(32)
        password = "test-password"
        exported = fresh_engine.export_symmetric_key(key, KeyFormat.ENCRYPTED, password=password)

        result = fresh_engine.import_symmetric_key(exported.key_data, KeyFormat.ENCRYPTED, password=password)

        assert result.key == key

    def test_import_encrypted_wrong_password(self, fresh_engine):
        """Test importing encrypted key with wrong password fails."""
        key = os.urandom(32)
        exported = fresh_engine.export_symmetric_key(key, KeyFormat.ENCRYPTED, password="correct")

        with pytest.raises(KeyImportError):
            fresh_engine.import_symmetric_key(exported.key_data, KeyFormat.ENCRYPTED, password="wrong")


class TestAsymmetricKeyExport:
    """Tests for asymmetric key export."""

    def test_export_ed25519_public_jwk(self, fresh_engine):
        """Test exporting Ed25519 public key as JWK."""
        private_key = ed25519.Ed25519PrivateKey.generate()

        result = fresh_engine.export_asymmetric_key(
            private_key, KeyFormat.JWK, include_private=False, kid="ed25519-key"
        )

        assert result.format == KeyFormat.JWK
        assert result.key_type == KeyType.ED25519
        assert not result.is_private
        assert result.key_data["kty"] == "OKP"
        assert result.key_data["crv"] == "Ed25519"
        assert "d" not in result.key_data

    def test_export_ed25519_private_jwk(self, fresh_engine):
        """Test exporting Ed25519 private key as JWK."""
        private_key = ed25519.Ed25519PrivateKey.generate()

        result = fresh_engine.export_asymmetric_key(private_key, KeyFormat.JWK, include_private=True)

        assert result.is_private
        assert "d" in result.key_data

    def test_export_ec_p256_public_jwk(self, fresh_engine):
        """Test exporting EC P-256 public key as JWK."""
        private_key = ec.generate_private_key(ec.SECP256R1())

        result = fresh_engine.export_asymmetric_key(private_key, KeyFormat.JWK, include_private=False)

        assert result.key_type == KeyType.EC_P256
        assert result.key_data["kty"] == "EC"
        assert result.key_data["crv"] == "P-256"
        assert "d" not in result.key_data

    def test_export_ec_p384_jwk(self, fresh_engine):
        """Test exporting EC P-384 key."""
        private_key = ec.generate_private_key(ec.SECP384R1())

        result = fresh_engine.export_asymmetric_key(private_key, KeyFormat.JWK, include_private=True)

        assert result.key_type == KeyType.EC_P384
        assert result.key_data["crv"] == "P-384"

    def test_export_public_pem(self, fresh_engine):
        """Test exporting public key as PEM."""
        private_key = ed25519.Ed25519PrivateKey.generate()

        result = fresh_engine.export_asymmetric_key(private_key, KeyFormat.PEM, include_private=False)

        assert result.format == KeyFormat.PEM
        assert b"-----BEGIN PUBLIC KEY-----" in result.key_data

    def test_export_private_pem(self, fresh_engine):
        """Test exporting private key as PEM."""
        private_key = ed25519.Ed25519PrivateKey.generate()

        result = fresh_engine.export_asymmetric_key(private_key, KeyFormat.PEM, include_private=True)

        assert b"-----BEGIN PRIVATE KEY-----" in result.key_data

    def test_export_private_pem_encrypted(self, fresh_engine):
        """Test exporting encrypted private key as PEM."""
        private_key = ec.generate_private_key(ec.SECP256R1())

        result = fresh_engine.export_asymmetric_key(
            private_key, KeyFormat.PEM, include_private=True, password="test123"
        )

        assert b"-----BEGIN ENCRYPTED PRIVATE KEY-----" in result.key_data


class TestAsymmetricKeyImport:
    """Tests for asymmetric key import."""

    def test_import_ed25519_public_jwk(self, fresh_engine):
        """Test importing Ed25519 public key from JWK."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        exported = fresh_engine.export_asymmetric_key(private_key, KeyFormat.JWK, include_private=False, kid="test")

        result = fresh_engine.import_asymmetric_key(exported.key_data, KeyFormat.JWK)

        assert isinstance(result.key, ed25519.Ed25519PublicKey)
        assert result.key_type == KeyType.ED25519
        assert not result.is_private
        assert result.kid == "test"

    def test_import_ed25519_private_jwk(self, fresh_engine):
        """Test importing Ed25519 private key from JWK."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        exported = fresh_engine.export_asymmetric_key(private_key, KeyFormat.JWK, include_private=True)

        result = fresh_engine.import_asymmetric_key(exported.key_data, KeyFormat.JWK)

        assert isinstance(result.key, ed25519.Ed25519PrivateKey)
        assert result.is_private

    def test_import_ec_jwk(self, fresh_engine):
        """Test importing EC key from JWK."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        exported = fresh_engine.export_asymmetric_key(private_key, KeyFormat.JWK, include_private=True)

        result = fresh_engine.import_asymmetric_key(exported.key_data, KeyFormat.JWK)

        assert isinstance(result.key, ec.EllipticCurvePrivateKey)
        assert result.key_type == KeyType.EC_P256

    def test_import_public_pem(self, fresh_engine):
        """Test importing public key from PEM."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        exported = fresh_engine.export_asymmetric_key(private_key, KeyFormat.PEM, include_private=False)

        result = fresh_engine.import_asymmetric_key(exported.key_data, KeyFormat.PEM)

        assert isinstance(result.key, ed25519.Ed25519PublicKey)
        assert not result.is_private

    def test_import_private_pem(self, fresh_engine):
        """Test importing private key from PEM."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        exported = fresh_engine.export_asymmetric_key(private_key, KeyFormat.PEM, include_private=True)

        result = fresh_engine.import_asymmetric_key(exported.key_data, KeyFormat.PEM)

        assert isinstance(result.key, ec.EllipticCurvePrivateKey)
        assert result.is_private

    def test_import_encrypted_pem(self, fresh_engine):
        """Test importing encrypted private key from PEM."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        password = "test-password"
        exported = fresh_engine.export_asymmetric_key(
            private_key, KeyFormat.PEM, include_private=True, password=password
        )

        result = fresh_engine.import_asymmetric_key(exported.key_data, KeyFormat.PEM, password=password)

        assert isinstance(result.key, ec.EllipticCurvePrivateKey)


class TestRoundtrip:
    """Tests for export/import roundtrips."""

    def test_symmetric_roundtrip_all_formats(self, fresh_engine):
        """Test symmetric key roundtrip for all formats."""
        key = os.urandom(32)
        kek = os.urandom(32)
        password = "test123"

        for format, kwargs in [
            (KeyFormat.RAW, {}),
            (KeyFormat.JWK, {"kid": "test"}),
            (KeyFormat.WRAPPED, {"kek": kek}),
            (KeyFormat.ENCRYPTED, {"password": password}),
        ]:
            exported = fresh_engine.export_symmetric_key(key, format, **kwargs)

            import_kwargs = {}
            if format == KeyFormat.WRAPPED:
                import_kwargs["kek"] = kek
            elif format == KeyFormat.ENCRYPTED:
                import_kwargs["password"] = password

            imported = fresh_engine.import_symmetric_key(exported.key_data, format, **import_kwargs)

            assert imported.key == key, f"Roundtrip failed for format {format}"

    def test_asymmetric_roundtrip_ed25519(self, fresh_engine):
        """Test Ed25519 key roundtrip."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Test message for signature verification
        message = b"test message"
        private_key.sign(message)

        # Export and import private key
        exported_private = fresh_engine.export_asymmetric_key(private_key, KeyFormat.JWK, include_private=True)
        imported_private = fresh_engine.import_asymmetric_key(exported_private.key_data, KeyFormat.JWK)

        # Verify imported key can sign
        new_sig = imported_private.key.sign(message)
        public_key.verify(new_sig, message)  # Should not raise

    def test_asymmetric_roundtrip_ec(self, fresh_engine):
        """Test EC key roundtrip."""
        private_key = ec.generate_private_key(ec.SECP256R1())

        # Export/import via PEM
        exported = fresh_engine.export_asymmetric_key(private_key, KeyFormat.PEM, include_private=True)
        imported = fresh_engine.import_asymmetric_key(exported.key_data, KeyFormat.PEM)

        # Verify key is functional
        assert isinstance(imported.key, ec.EllipticCurvePrivateKey)
        assert imported.key.curve.name == "secp256r1"
