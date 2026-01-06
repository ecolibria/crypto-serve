"""JOSE (JSON Object Signing and Encryption) Engine.

Implements RFC 7515 (JWS), RFC 7516 (JWE), RFC 7517 (JWK), RFC 7518 (JWA).

Supported JWS Algorithms:
- EdDSA (Ed25519) - Recommended
- ES256 (ECDSA P-256)
- ES384 (ECDSA P-384)
- HS256, HS384, HS512 (HMAC)

Supported JWE Algorithms:
- Key Agreement:
  - ECDH-ES (Elliptic Curve Diffie-Hellman Ephemeral Static)
  - ECDH-ES+A128KW, ECDH-ES+A256KW
- Key Wrapping:
  - A128KW, A256KW (AES Key Wrap)
- Direct:
  - dir (Direct encryption with symmetric key)

Content Encryption:
- A128GCM, A256GCM (AES-GCM)
- A128CBC-HS256, A256CBC-HS512 (AES-CBC with HMAC)
- C20P (ChaCha20-Poly1305 - not in RFC but widely used)
"""

import base64
import json
import os
import struct
from dataclasses import dataclass
from enum import Enum
from typing import Any

from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.exceptions import InvalidTag, InvalidSignature


# JWS Algorithms
class JWSAlgorithm(str, Enum):
    """Supported JWS signature algorithms."""

    EDDSA = "EdDSA"  # Ed25519
    ES256 = "ES256"  # ECDSA P-256 with SHA-256
    ES384 = "ES384"  # ECDSA P-384 with SHA-384
    HS256 = "HS256"  # HMAC SHA-256
    HS384 = "HS384"  # HMAC SHA-384
    HS512 = "HS512"  # HMAC SHA-512


# JWE Algorithms
class JWEAlgorithm(str, Enum):
    """Supported JWE key management algorithms."""

    DIR = "dir"  # Direct encryption
    A128KW = "A128KW"  # AES-128 Key Wrap
    A256KW = "A256KW"  # AES-256 Key Wrap
    ECDH_ES = "ECDH-ES"  # ECDH Ephemeral Static
    ECDH_ES_A128KW = "ECDH-ES+A128KW"
    ECDH_ES_A256KW = "ECDH-ES+A256KW"


class JWEEncryption(str, Enum):
    """Supported JWE content encryption algorithms."""

    A128GCM = "A128GCM"  # AES-128-GCM
    A256GCM = "A256GCM"  # AES-256-GCM
    A128CBC_HS256 = "A128CBC-HS256"  # AES-128-CBC + HMAC-SHA-256
    A256CBC_HS512 = "A256CBC-HS512"  # AES-256-CBC + HMAC-SHA-512
    C20P = "C20P"  # ChaCha20-Poly1305 (extended)


# Exceptions
class JOSEError(Exception):
    """Base JOSE exception."""

    pass


class InvalidJWSError(JOSEError):
    """JWS is invalid or verification failed."""

    pass


class InvalidJWEError(JOSEError):
    """JWE is invalid or decryption failed."""

    pass


class UnsupportedAlgorithmError(JOSEError):
    """Algorithm not supported."""

    pass


# Data classes
@dataclass
class JWSResult:
    """Result of JWS creation."""

    compact: str  # Compact serialization (header.payload.signature)
    header: dict
    payload: bytes
    signature: bytes


@dataclass
class JWEResult:
    """Result of JWE creation."""

    compact: str  # Compact serialization
    header: dict
    encrypted_key: bytes
    iv: bytes
    ciphertext: bytes
    tag: bytes


@dataclass
class JWK:
    """JSON Web Key."""

    kty: str  # Key type
    use: str | None = None  # Use: sig or enc
    key_ops: list[str] | None = None
    alg: str | None = None
    kid: str | None = None
    # EC keys
    crv: str | None = None
    x: str | None = None
    y: str | None = None
    d: str | None = None  # Private key component
    # Symmetric keys
    k: str | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary, excluding None values."""
        return {k: v for k, v in self.__dict__.items() if v is not None}

    @classmethod
    def from_dict(cls, data: dict) -> "JWK":
        """Create from dictionary."""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    """Base64url decode with padding restoration."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


class JOSEEngine:
    """JOSE operations engine."""

    # Algorithm requirements
    HASH_ALGORITHMS = {
        JWSAlgorithm.ES256: hashes.SHA256(),
        JWSAlgorithm.ES384: hashes.SHA384(),
        JWSAlgorithm.HS256: hashes.SHA256(),
        JWSAlgorithm.HS384: hashes.SHA384(),
        JWSAlgorithm.HS512: hashes.SHA512(),
    }

    HMAC_KEY_SIZES = {
        JWSAlgorithm.HS256: 32,
        JWSAlgorithm.HS384: 48,
        JWSAlgorithm.HS512: 64,
    }

    CEK_SIZES = {
        JWEEncryption.A128GCM: 16,
        JWEEncryption.A256GCM: 32,
        JWEEncryption.A128CBC_HS256: 32,  # 16 enc + 16 mac
        JWEEncryption.A256CBC_HS512: 64,  # 32 enc + 32 mac
        JWEEncryption.C20P: 32,
    }

    IV_SIZES = {
        JWEEncryption.A128GCM: 12,
        JWEEncryption.A256GCM: 12,
        JWEEncryption.A128CBC_HS256: 16,
        JWEEncryption.A256CBC_HS512: 16,
        JWEEncryption.C20P: 12,
    }

    # ==================== JWS Operations ====================

    def create_jws(
        self,
        payload: bytes,
        key: bytes | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey,
        algorithm: JWSAlgorithm,
        kid: str | None = None,
        extra_headers: dict | None = None,
    ) -> JWSResult:
        """Create a JWS (JSON Web Signature).

        Args:
            payload: Data to sign
            key: Signing key (symmetric for HMAC, private for asymmetric)
            algorithm: JWS algorithm to use
            kid: Optional key ID for header
            extra_headers: Additional header fields

        Returns:
            JWSResult with compact serialization
        """
        # Build header
        header = {"alg": algorithm.value, "typ": "JWT"}
        if kid:
            header["kid"] = kid
        if extra_headers:
            header.update(extra_headers)

        # Encode header and payload
        header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = _b64url_encode(payload)
        signing_input = f"{header_b64}.{payload_b64}".encode()

        # Sign
        signature = self._jws_sign(signing_input, key, algorithm)

        # Build compact serialization
        signature_b64 = _b64url_encode(signature)
        compact = f"{header_b64}.{payload_b64}.{signature_b64}"

        return JWSResult(
            compact=compact,
            header=header,
            payload=payload,
            signature=signature,
        )

    def verify_jws(
        self,
        jws: str,
        key: bytes | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey,
        algorithms: list[JWSAlgorithm] | None = None,
    ) -> tuple[bytes, dict]:
        """Verify a JWS and return payload.

        Args:
            jws: Compact serialization
            key: Verification key
            algorithms: Allowed algorithms (None = all)

        Returns:
            Tuple of (payload, header)

        Raises:
            InvalidJWSError: If verification fails
        """
        try:
            parts = jws.split(".")
            if len(parts) != 3:
                raise InvalidJWSError("Invalid JWS format")

            header_b64, payload_b64, signature_b64 = parts

            # Decode header
            header = json.loads(_b64url_decode(header_b64))
            alg_str = header.get("alg")
            if not alg_str:
                raise InvalidJWSError("Missing 'alg' header")

            try:
                algorithm = JWSAlgorithm(alg_str)
            except ValueError:
                raise UnsupportedAlgorithmError(f"Unsupported algorithm: {alg_str}")

            # Check allowed algorithms
            if algorithms and algorithm not in algorithms:
                raise InvalidJWSError(f"Algorithm {algorithm} not allowed")

            # Decode signature and payload
            signature = _b64url_decode(signature_b64)
            payload = _b64url_decode(payload_b64)

            # Verify
            signing_input = f"{header_b64}.{payload_b64}".encode()
            if not self._jws_verify(signing_input, signature, key, algorithm):
                raise InvalidJWSError("Signature verification failed")

            return payload, header

        except InvalidJWSError:
            raise
        except Exception as e:
            raise InvalidJWSError(f"JWS verification failed: {e}")

    def _jws_sign(
        self,
        data: bytes,
        key: bytes | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey,
        algorithm: JWSAlgorithm,
    ) -> bytes:
        """Create JWS signature."""
        if algorithm == JWSAlgorithm.EDDSA:
            if not isinstance(key, ed25519.Ed25519PrivateKey):
                raise JOSEError("EdDSA requires Ed25519 private key")
            return key.sign(data)

        elif algorithm in [JWSAlgorithm.ES256, JWSAlgorithm.ES384]:
            if not isinstance(key, ec.EllipticCurvePrivateKey):
                raise JOSEError("ECDSA requires EC private key")
            hash_alg = self.HASH_ALGORITHMS[algorithm]
            der_sig = key.sign(data, ec.ECDSA(hash_alg))
            # Convert DER to raw R||S format
            r, s = decode_dss_signature(der_sig)
            key_size = 32 if algorithm == JWSAlgorithm.ES256 else 48
            return r.to_bytes(key_size, "big") + s.to_bytes(key_size, "big")

        elif algorithm in [JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512]:
            if not isinstance(key, bytes):
                raise JOSEError("HMAC requires symmetric key")
            hash_alg = self.HASH_ALGORITHMS[algorithm]
            h = crypto_hmac.HMAC(key, hash_alg)
            h.update(data)
            return h.finalize()

        else:
            raise UnsupportedAlgorithmError(f"Unsupported JWS algorithm: {algorithm}")

    def _jws_verify(
        self,
        data: bytes,
        signature: bytes,
        key: bytes | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey,
        algorithm: JWSAlgorithm,
    ) -> bool:
        """Verify JWS signature."""
        try:
            if algorithm == JWSAlgorithm.EDDSA:
                if not isinstance(key, ed25519.Ed25519PublicKey):
                    raise JOSEError("EdDSA requires Ed25519 public key")
                key.verify(signature, data)
                return True

            elif algorithm in [JWSAlgorithm.ES256, JWSAlgorithm.ES384]:
                if not isinstance(key, ec.EllipticCurvePublicKey):
                    raise JOSEError("ECDSA requires EC public key")
                # Convert raw R||S to DER
                key_size = 32 if algorithm == JWSAlgorithm.ES256 else 48
                r = int.from_bytes(signature[:key_size], "big")
                s = int.from_bytes(signature[key_size:], "big")
                der_sig = encode_dss_signature(r, s)
                hash_alg = self.HASH_ALGORITHMS[algorithm]
                key.verify(der_sig, data, ec.ECDSA(hash_alg))
                return True

            elif algorithm in [JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512]:
                if not isinstance(key, bytes):
                    raise JOSEError("HMAC requires symmetric key")
                hash_alg = self.HASH_ALGORITHMS[algorithm]
                h = crypto_hmac.HMAC(key, hash_alg)
                h.update(data)
                h.verify(signature)
                return True

            else:
                raise UnsupportedAlgorithmError(f"Unsupported algorithm: {algorithm}")

        except InvalidSignature:
            return False

    # ==================== JWE Operations ====================

    def create_jwe(
        self,
        plaintext: bytes,
        key: bytes | ec.EllipticCurvePublicKey,
        algorithm: JWEAlgorithm,
        encryption: JWEEncryption,
        kid: str | None = None,
        aad: bytes | None = None,
        extra_headers: dict | None = None,
    ) -> JWEResult:
        """Create a JWE (JSON Web Encryption).

        Args:
            plaintext: Data to encrypt
            key: Encryption key
            algorithm: Key management algorithm
            encryption: Content encryption algorithm
            kid: Optional key ID
            aad: Additional authenticated data
            extra_headers: Additional header fields

        Returns:
            JWEResult with compact serialization
        """
        # Build header
        header = {"alg": algorithm.value, "enc": encryption.value}
        if kid:
            header["kid"] = kid
        if extra_headers:
            header.update(extra_headers)

        header_json = json.dumps(header, separators=(",", ":")).encode()
        header_b64 = _b64url_encode(header_json)

        # Generate Content Encryption Key (CEK)
        cek_size = self.CEK_SIZES[encryption]
        iv_size = self.IV_SIZES[encryption]

        if algorithm == JWEAlgorithm.DIR:
            # Direct encryption - key is the CEK
            if not isinstance(key, bytes) or len(key) != cek_size:
                raise JOSEError(f"Direct encryption requires {cek_size}-byte key")
            cek = key
            encrypted_key = b""

        elif algorithm in [JWEAlgorithm.A128KW, JWEAlgorithm.A256KW]:
            # AES Key Wrap
            if not isinstance(key, bytes):
                raise JOSEError("AES Key Wrap requires symmetric key")
            expected_size = 16 if algorithm == JWEAlgorithm.A128KW else 32
            if len(key) != expected_size:
                raise JOSEError(f"AES Key Wrap requires {expected_size}-byte key")
            cek = os.urandom(cek_size)
            encrypted_key = aes_key_wrap(key, cek)

        elif algorithm in [JWEAlgorithm.ECDH_ES, JWEAlgorithm.ECDH_ES_A128KW, JWEAlgorithm.ECDH_ES_A256KW]:
            # ECDH Ephemeral Static
            if not isinstance(key, ec.EllipticCurvePublicKey):
                raise JOSEError("ECDH requires EC public key")
            cek, encrypted_key, epk_header = self._ecdh_derive_key(key, algorithm, encryption, cek_size)
            header["epk"] = epk_header
            header_json = json.dumps(header, separators=(",", ":")).encode()
            header_b64 = _b64url_encode(header_json)

        else:
            raise UnsupportedAlgorithmError(f"Unsupported JWE algorithm: {algorithm}")

        # Generate IV
        iv = os.urandom(iv_size)

        # Encrypt content
        aad_input = header_b64.encode() if aad is None else aad
        ciphertext, tag = self._jwe_encrypt_content(plaintext, cek, iv, aad_input, encryption)

        # Build compact serialization
        compact = ".".join(
            [
                header_b64,
                _b64url_encode(encrypted_key),
                _b64url_encode(iv),
                _b64url_encode(ciphertext),
                _b64url_encode(tag),
            ]
        )

        return JWEResult(
            compact=compact,
            header=header,
            encrypted_key=encrypted_key,
            iv=iv,
            ciphertext=ciphertext,
            tag=tag,
        )

    def decrypt_jwe(
        self,
        jwe: str,
        key: bytes | ec.EllipticCurvePrivateKey,
        algorithms: list[JWEAlgorithm] | None = None,
        encryptions: list[JWEEncryption] | None = None,
    ) -> tuple[bytes, dict]:
        """Decrypt a JWE and return plaintext.

        Args:
            jwe: Compact serialization
            key: Decryption key
            algorithms: Allowed key management algorithms
            encryptions: Allowed content encryption algorithms

        Returns:
            Tuple of (plaintext, header)

        Raises:
            InvalidJWEError: If decryption fails
        """
        try:
            parts = jwe.split(".")
            if len(parts) != 5:
                raise InvalidJWEError("Invalid JWE format")

            header_b64, encrypted_key_b64, iv_b64, ciphertext_b64, tag_b64 = parts

            # Decode components
            header = json.loads(_b64url_decode(header_b64))
            encrypted_key = _b64url_decode(encrypted_key_b64)
            iv = _b64url_decode(iv_b64)
            ciphertext = _b64url_decode(ciphertext_b64)
            tag = _b64url_decode(tag_b64)

            # Parse algorithms
            alg_str = header.get("alg")
            enc_str = header.get("enc")
            if not alg_str or not enc_str:
                raise InvalidJWEError("Missing 'alg' or 'enc' header")

            try:
                algorithm = JWEAlgorithm(alg_str)
                encryption = JWEEncryption(enc_str)
            except ValueError as e:
                raise UnsupportedAlgorithmError(str(e))

            # Check allowed algorithms
            if algorithms and algorithm not in algorithms:
                raise InvalidJWEError(f"Algorithm {algorithm} not allowed")
            if encryptions and encryption not in encryptions:
                raise InvalidJWEError(f"Encryption {encryption} not allowed")

            # Derive CEK
            cek_size = self.CEK_SIZES[encryption]

            if algorithm == JWEAlgorithm.DIR:
                if not isinstance(key, bytes) or len(key) != cek_size:
                    raise JOSEError(f"Direct requires {cek_size}-byte key")
                cek = key

            elif algorithm in [JWEAlgorithm.A128KW, JWEAlgorithm.A256KW]:
                if not isinstance(key, bytes):
                    raise JOSEError("AES Key Wrap requires symmetric key")
                cek = aes_key_unwrap(key, encrypted_key)

            elif algorithm in [JWEAlgorithm.ECDH_ES, JWEAlgorithm.ECDH_ES_A128KW, JWEAlgorithm.ECDH_ES_A256KW]:
                if not isinstance(key, ec.EllipticCurvePrivateKey):
                    raise JOSEError("ECDH requires EC private key")
                epk = header.get("epk")
                if not epk:
                    raise InvalidJWEError("Missing 'epk' header for ECDH")
                cek = self._ecdh_decrypt_key(key, epk, encrypted_key, algorithm, encryption, cek_size)

            else:
                raise UnsupportedAlgorithmError(f"Unsupported algorithm: {algorithm}")

            # Decrypt content
            aad = header_b64.encode()
            plaintext = self._jwe_decrypt_content(ciphertext, tag, cek, iv, aad, encryption)

            return plaintext, header

        except InvalidJWEError:
            raise
        except InvalidTag:
            raise InvalidJWEError("Decryption failed: authentication tag mismatch")
        except Exception as e:
            raise InvalidJWEError(f"JWE decryption failed: {e}")

    def _jwe_encrypt_content(
        self,
        plaintext: bytes,
        cek: bytes,
        iv: bytes,
        aad: bytes,
        encryption: JWEEncryption,
    ) -> tuple[bytes, bytes]:
        """Encrypt content using JWE content encryption algorithm."""
        if encryption in [JWEEncryption.A128GCM, JWEEncryption.A256GCM]:
            aesgcm = AESGCM(cek)
            ciphertext_and_tag = aesgcm.encrypt(iv, plaintext, aad)
            # Split ciphertext and tag (tag is last 16 bytes)
            return ciphertext_and_tag[:-16], ciphertext_and_tag[-16:]

        elif encryption == JWEEncryption.C20P:
            chacha = ChaCha20Poly1305(cek)
            ciphertext_and_tag = chacha.encrypt(iv, plaintext, aad)
            return ciphertext_and_tag[:-16], ciphertext_and_tag[-16:]

        elif encryption in [JWEEncryption.A128CBC_HS256, JWEEncryption.A256CBC_HS512]:
            # Split CEK into MAC and ENC keys
            half = len(cek) // 2
            mac_key = cek[:half]
            enc_key = cek[half:]

            # Encrypt with AES-CBC
            cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
            encryptor = cipher.encryptor()

            # PKCS7 padding
            block_size = 16
            padding_len = block_size - (len(plaintext) % block_size)
            padded = plaintext + bytes([padding_len] * padding_len)

            ciphertext = encryptor.update(padded) + encryptor.finalize()

            # Compute authentication tag
            al = struct.pack(">Q", len(aad) * 8)  # AAD length in bits
            mac_input = aad + iv + ciphertext + al

            hash_alg = hashes.SHA256() if encryption == JWEEncryption.A128CBC_HS256 else hashes.SHA512()
            h = crypto_hmac.HMAC(mac_key, hash_alg)
            h.update(mac_input)
            mac = h.finalize()

            # Tag is first half of MAC
            tag = mac[: len(mac) // 2]
            return ciphertext, tag

        else:
            raise UnsupportedAlgorithmError(f"Unsupported encryption: {encryption}")

    def _jwe_decrypt_content(
        self,
        ciphertext: bytes,
        tag: bytes,
        cek: bytes,
        iv: bytes,
        aad: bytes,
        encryption: JWEEncryption,
    ) -> bytes:
        """Decrypt content using JWE content encryption algorithm."""
        if encryption in [JWEEncryption.A128GCM, JWEEncryption.A256GCM]:
            aesgcm = AESGCM(cek)
            return aesgcm.decrypt(iv, ciphertext + tag, aad)

        elif encryption == JWEEncryption.C20P:
            chacha = ChaCha20Poly1305(cek)
            return chacha.decrypt(iv, ciphertext + tag, aad)

        elif encryption in [JWEEncryption.A128CBC_HS256, JWEEncryption.A256CBC_HS512]:
            # Split CEK
            half = len(cek) // 2
            mac_key = cek[:half]
            enc_key = cek[half:]

            # Verify authentication tag
            al = struct.pack(">Q", len(aad) * 8)
            mac_input = aad + iv + ciphertext + al

            hash_alg = hashes.SHA256() if encryption == JWEEncryption.A128CBC_HS256 else hashes.SHA512()
            h = crypto_hmac.HMAC(mac_key, hash_alg)
            h.update(mac_input)
            computed_mac = h.finalize()

            expected_tag = computed_mac[: len(computed_mac) // 2]
            if crypto_hmac.HMAC.verify is not None:
                # Use constant-time comparison
                import hmac as std_hmac

                if not std_hmac.compare_digest(tag, expected_tag):
                    raise InvalidTag()

            # Decrypt
            cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()

            # Remove PKCS7 padding
            padding_len = padded[-1]
            if padding_len > 16 or not all(b == padding_len for b in padded[-padding_len:]):
                raise InvalidJWEError("Invalid padding")

            return padded[:-padding_len]

        else:
            raise UnsupportedAlgorithmError(f"Unsupported encryption: {encryption}")

    def _ecdh_derive_key(
        self,
        recipient_public_key: ec.EllipticCurvePublicKey,
        algorithm: JWEAlgorithm,
        encryption: JWEEncryption,
        cek_size: int,
    ) -> tuple[bytes, bytes, dict]:
        """Derive key using ECDH.

        Returns:
            Tuple of (cek, encrypted_key, epk_header)
        """
        # Determine curve
        curve = recipient_public_key.curve
        if curve.name == "secp256r1":
            crv = "P-256"
            key_size = 32
        elif curve.name == "secp384r1":
            crv = "P-384"
            key_size = 48
        elif curve.name == "secp521r1":
            crv = "P-521"
            key_size = 66
        else:
            raise JOSEError(f"Unsupported curve: {curve.name}")

        # Generate ephemeral key pair
        ephemeral_private = ec.generate_private_key(curve)
        ephemeral_public = ephemeral_private.public_key()

        # Perform ECDH
        shared_key = ephemeral_private.exchange(ec.ECDH(), recipient_public_key)

        # Build AlgorithmID
        if algorithm == JWEAlgorithm.ECDH_ES:
            alg_id = encryption.value.encode()
            key_data_len = cek_size
        else:
            alg_id = algorithm.value.encode()
            key_data_len = 16 if "128" in algorithm.value else 32

        # Concat KDF (RFC 7518 Section 4.6.2)
        # AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo
        other_info = (
            struct.pack(">I", len(alg_id))
            + alg_id
            + struct.pack(">I", 0)  # PartyUInfo empty
            + struct.pack(">I", 0)  # PartyVInfo empty
            + struct.pack(">I", key_data_len * 8)  # keydatalen in bits
        )

        ckdf = ConcatKDFHash(
            algorithm=hashes.SHA256(),
            length=key_data_len,
            otherinfo=other_info,
        )
        derived_key = ckdf.derive(shared_key)

        # Build ephemeral public key JWK
        epk_numbers = ephemeral_public.public_numbers()
        epk = {
            "kty": "EC",
            "crv": crv,
            "x": _b64url_encode(epk_numbers.x.to_bytes(key_size, "big")),
            "y": _b64url_encode(epk_numbers.y.to_bytes(key_size, "big")),
        }

        if algorithm == JWEAlgorithm.ECDH_ES:
            # Direct key agreement - derived key is CEK
            return derived_key, b"", epk
        else:
            # Key agreement with key wrapping
            cek = os.urandom(cek_size)
            encrypted_key = aes_key_wrap(derived_key, cek)
            return cek, encrypted_key, epk

    def _ecdh_decrypt_key(
        self,
        private_key: ec.EllipticCurvePrivateKey,
        epk: dict,
        encrypted_key: bytes,
        algorithm: JWEAlgorithm,
        encryption: JWEEncryption,
        cek_size: int,
    ) -> bytes:
        """Decrypt key using ECDH."""
        # Parse EPK
        crv = epk.get("crv")
        x = _b64url_decode(epk["x"])
        y = _b64url_decode(epk["y"])

        if crv == "P-256":
            curve = ec.SECP256R1()
        elif crv == "P-384":
            curve = ec.SECP384R1()
        elif crv == "P-521":
            curve = ec.SECP521R1()
        else:
            raise JOSEError(f"Unsupported curve: {crv}")

        # Reconstruct public key
        x_int = int.from_bytes(x, "big")
        y_int = int.from_bytes(y, "big")
        public_numbers = ec.EllipticCurvePublicNumbers(x_int, y_int, curve)
        ephemeral_public = public_numbers.public_key()

        # Perform ECDH
        shared_key = private_key.exchange(ec.ECDH(), ephemeral_public)

        # Derive key (same as encryption)
        if algorithm == JWEAlgorithm.ECDH_ES:
            alg_id = encryption.value.encode()
            key_data_len = cek_size
        else:
            alg_id = algorithm.value.encode()
            key_data_len = 16 if "128" in algorithm.value else 32

        other_info = (
            struct.pack(">I", len(alg_id))
            + alg_id
            + struct.pack(">I", 0)
            + struct.pack(">I", 0)
            + struct.pack(">I", key_data_len * 8)
        )

        ckdf = ConcatKDFHash(
            algorithm=hashes.SHA256(),
            length=key_data_len,
            otherinfo=other_info,
        )
        derived_key = ckdf.derive(shared_key)

        if algorithm == JWEAlgorithm.ECDH_ES:
            return derived_key
        else:
            return aes_key_unwrap(derived_key, encrypted_key)

    # ==================== JWK Operations ====================

    def generate_jwk(
        self,
        kty: str,
        use: str = "sig",
        kid: str | None = None,
        crv: str | None = None,
        key_size: int | None = None,
    ) -> tuple[JWK, JWK | None]:
        """Generate a JWK key pair or symmetric key.

        Args:
            kty: Key type (EC, OKP, oct)
            use: Key use (sig or enc)
            kid: Key ID
            crv: Curve for EC/OKP keys
            key_size: Size for symmetric keys

        Returns:
            Tuple of (public_jwk, private_jwk) for asymmetric,
            or (jwk, None) for symmetric
        """
        if kid is None:
            kid = _b64url_encode(os.urandom(8))

        if kty == "oct":
            # Symmetric key
            size = key_size or 32
            k = os.urandom(size)
            jwk = JWK(
                kty="oct",
                k=_b64url_encode(k),
                use=use,
                kid=kid,
                alg="A256GCM" if use == "enc" else "HS256",
            )
            return jwk, None

        elif kty == "EC":
            crv = crv or "P-256"
            if crv == "P-256":
                curve = ec.SECP256R1()
                key_size = 32
                alg = "ES256" if use == "sig" else "ECDH-ES"
            elif crv == "P-384":
                curve = ec.SECP384R1()
                key_size = 48
                alg = "ES384" if use == "sig" else "ECDH-ES"
            elif crv == "P-521":
                curve = ec.SECP521R1()
                key_size = 66
                alg = "ES512" if use == "sig" else "ECDH-ES"
            else:
                raise JOSEError(f"Unsupported curve: {crv}")

            private_key = ec.generate_private_key(curve)
            public_key = private_key.public_key()
            numbers = public_key.public_numbers()

            public_jwk = JWK(
                kty="EC",
                crv=crv,
                x=_b64url_encode(numbers.x.to_bytes(key_size, "big")),
                y=_b64url_encode(numbers.y.to_bytes(key_size, "big")),
                use=use,
                kid=kid,
                alg=alg,
            )

            private_jwk = JWK(
                kty="EC",
                crv=crv,
                x=_b64url_encode(numbers.x.to_bytes(key_size, "big")),
                y=_b64url_encode(numbers.y.to_bytes(key_size, "big")),
                d=_b64url_encode(private_key.private_numbers().private_value.to_bytes(key_size, "big")),
                use=use,
                kid=kid,
                alg=alg,
            )

            return public_jwk, private_jwk

        elif kty == "OKP":
            crv = crv or "Ed25519"
            if crv == "Ed25519":
                private_key = ed25519.Ed25519PrivateKey.generate()
                public_key = private_key.public_key()

                public_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
                private_bytes = private_key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )

                public_jwk = JWK(
                    kty="OKP",
                    crv="Ed25519",
                    x=_b64url_encode(public_bytes),
                    use="sig",
                    kid=kid,
                    alg="EdDSA",
                )

                private_jwk = JWK(
                    kty="OKP",
                    crv="Ed25519",
                    x=_b64url_encode(public_bytes),
                    d=_b64url_encode(private_bytes),
                    use="sig",
                    kid=kid,
                    alg="EdDSA",
                )

                return public_jwk, private_jwk
            else:
                raise JOSEError(f"Unsupported curve: {crv}")

        else:
            raise JOSEError(f"Unsupported key type: {kty}")

    def jwk_to_key(self, jwk: JWK | dict) -> Any:
        """Convert JWK to cryptography key object.

        Args:
            jwk: JWK object or dictionary

        Returns:
            Key object (EC, Ed25519, or bytes for symmetric)
        """
        if isinstance(jwk, dict):
            jwk = JWK.from_dict(jwk)

        if jwk.kty == "oct":
            return _b64url_decode(jwk.k)

        elif jwk.kty == "EC":
            x = int.from_bytes(_b64url_decode(jwk.x), "big")
            y = int.from_bytes(_b64url_decode(jwk.y), "big")

            if jwk.crv == "P-256":
                curve = ec.SECP256R1()
            elif jwk.crv == "P-384":
                curve = ec.SECP384R1()
            elif jwk.crv == "P-521":
                curve = ec.SECP521R1()
            else:
                raise JOSEError(f"Unsupported curve: {jwk.crv}")

            public_numbers = ec.EllipticCurvePublicNumbers(x, y, curve)

            if jwk.d:
                # Private key
                d = int.from_bytes(_b64url_decode(jwk.d), "big")
                private_numbers = ec.EllipticCurvePrivateNumbers(d, public_numbers)
                return private_numbers.private_key()
            else:
                return public_numbers.public_key()

        elif jwk.kty == "OKP":
            if jwk.crv == "Ed25519":
                if jwk.d:
                    return ed25519.Ed25519PrivateKey.from_private_bytes(_b64url_decode(jwk.d))
                else:
                    return ed25519.Ed25519PublicKey.from_public_bytes(_b64url_decode(jwk.x))
            else:
                raise JOSEError(f"Unsupported curve: {jwk.crv}")

        else:
            raise JOSEError(f"Unsupported key type: {jwk.kty}")

    def key_to_jwk(
        self,
        key: Any,
        kid: str | None = None,
        use: str = "sig",
    ) -> JWK:
        """Convert cryptography key to JWK.

        Args:
            key: Key object (EC, Ed25519, or bytes)
            kid: Key ID
            use: Key use

        Returns:
            JWK object
        """
        if kid is None:
            kid = _b64url_encode(os.urandom(8))

        if isinstance(key, bytes):
            return JWK(
                kty="oct",
                k=_b64url_encode(key),
                use=use,
                kid=kid,
            )

        elif isinstance(key, ed25519.Ed25519PrivateKey):
            public = key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            private = key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            return JWK(
                kty="OKP",
                crv="Ed25519",
                x=_b64url_encode(public),
                d=_b64url_encode(private),
                use="sig",
                kid=kid,
                alg="EdDSA",
            )

        elif isinstance(key, ed25519.Ed25519PublicKey):
            public = key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            return JWK(
                kty="OKP",
                crv="Ed25519",
                x=_b64url_encode(public),
                use="sig",
                kid=kid,
                alg="EdDSA",
            )

        elif isinstance(key, ec.EllipticCurvePrivateKey):
            public = key.public_key()
            numbers = public.public_numbers()
            curve_name = key.curve.name

            if curve_name == "secp256r1":
                crv, size, alg = "P-256", 32, "ES256"
            elif curve_name == "secp384r1":
                crv, size, alg = "P-384", 48, "ES384"
            elif curve_name == "secp521r1":
                crv, size, alg = "P-521", 66, "ES512"
            else:
                raise JOSEError(f"Unsupported curve: {curve_name}")

            return JWK(
                kty="EC",
                crv=crv,
                x=_b64url_encode(numbers.x.to_bytes(size, "big")),
                y=_b64url_encode(numbers.y.to_bytes(size, "big")),
                d=_b64url_encode(key.private_numbers().private_value.to_bytes(size, "big")),
                use=use,
                kid=kid,
                alg=alg if use == "sig" else "ECDH-ES",
            )

        elif isinstance(key, ec.EllipticCurvePublicKey):
            numbers = key.public_numbers()
            curve_name = key.curve.name

            if curve_name == "secp256r1":
                crv, size, alg = "P-256", 32, "ES256"
            elif curve_name == "secp384r1":
                crv, size, alg = "P-384", 48, "ES384"
            elif curve_name == "secp521r1":
                crv, size, alg = "P-521", 66, "ES512"
            else:
                raise JOSEError(f"Unsupported curve: {curve_name}")

            return JWK(
                kty="EC",
                crv=crv,
                x=_b64url_encode(numbers.x.to_bytes(size, "big")),
                y=_b64url_encode(numbers.y.to_bytes(size, "big")),
                use=use,
                kid=kid,
                alg=alg if use == "sig" else "ECDH-ES",
            )

        else:
            raise JOSEError(f"Unsupported key type: {type(key)}")

    def compute_thumbprint(self, jwk: JWK | dict, hash_algorithm: str = "SHA-256") -> str:
        """Compute JWK thumbprint per RFC 7638.

        Args:
            jwk: JWK object or dictionary
            hash_algorithm: Hash algorithm (default SHA-256)

        Returns:
            Base64url-encoded thumbprint
        """
        import hashlib

        if isinstance(jwk, dict):
            jwk = JWK.from_dict(jwk)

        # Per RFC 7638, only include required members in canonical order
        kty = jwk.kty
        if kty == "EC":
            # For EC keys: crv, kty, x, y
            canonical = {
                "crv": jwk.crv,
                "kty": kty,
                "x": jwk.x,
                "y": jwk.y,
            }
        elif kty == "OKP":
            # For OKP keys: crv, kty, x
            canonical = {
                "crv": jwk.crv,
                "kty": kty,
                "x": jwk.x,
            }
        elif kty == "oct":
            # For symmetric keys: k, kty
            canonical = {
                "k": jwk.k,
                "kty": kty,
            }
        else:
            raise JOSEError(f"Unsupported key type for thumbprint: {kty}")

        # Serialize with lexicographic key ordering and no whitespace
        canonical_json = json.dumps(canonical, separators=(",", ":"), sort_keys=True)
        digest = hashlib.sha256(canonical_json.encode()).digest()
        return _b64url_encode(digest)


# Singleton instance
jose_engine = JOSEEngine()
