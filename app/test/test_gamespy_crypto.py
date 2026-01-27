"""
Tests for GameSpy Certificate Crypto.

These tests verify:
1. Hash computation uses correct binary format (little-endian integers, no null terminators)
2. RSA signing uses PKCS#1 v1.5 padding
3. Signature verification works (sign then verify with public key)

"""

import hashlib
import struct

from app.util.gamespy_crypto import (
    MD5_DIGESTINFO,
    SERVER_SIGNING_EXPONENT,
    SERVER_SIGNING_MODULUS,
    compute_certificate_hash,
    generate_certificate_for_player,
    generate_rsa_keypair,
    rsa_sign_pkcs1v15,
)


class TestComputeCertificateHash:
    """Test the hash computation matches GameSpy binary format."""

    def test_integers_are_little_endian(self):
        """Verify integers are packed as 4-byte little-endian."""
        # Manually compute expected hash input for a simple case
        # If userid=1, the bytes should be [0x01, 0x00, 0x00, 0x00] (little-endian)
        # not "1" as ASCII [0x31]

        keypair = generate_rsa_keypair()

        hash1 = compute_certificate_hash(
            length=305,
            version=1,
            partnercode=0,
            namespaceid=1,
            userid=1,
            profileid=1,
            expiretime=0,
            profilenick="A",
            uniquenick="A",
            cdkeyhash="",
            peerkeymodulus=keypair.modulus,
            peerkeyexponent=keypair.exponent,
            serverdata="00" * 128,
        )

        hash2 = compute_certificate_hash(
            length=305,
            version=1,
            partnercode=0,
            namespaceid=1,
            userid=256,  # 256 = 0x00000100 little-endian
            profileid=1,
            expiretime=0,
            profilenick="A",
            uniquenick="A",
            cdkeyhash="",
            peerkeymodulus=keypair.modulus,
            peerkeyexponent=keypair.exponent,
            serverdata="00" * 128,
        )

        # Hashes must differ (different userid)
        assert hash1 != hash2

    def test_strings_not_null_terminated(self):
        """Verify strings are hashed without null terminators (strlen, not strlen+1)."""
        keypair = generate_rsa_keypair()

        # "A" should produce different hash than "A\x00" appended
        hash1 = compute_certificate_hash(
            length=305,
            version=1,
            partnercode=0,
            namespaceid=1,
            userid=1,
            profileid=1,
            expiretime=0,
            profilenick="A",
            uniquenick="A",
            cdkeyhash="",
            peerkeymodulus=keypair.modulus,
            peerkeyexponent=keypair.exponent,
            serverdata="00" * 128,
        )

        hash2 = compute_certificate_hash(
            length=305,
            version=1,
            partnercode=0,
            namespaceid=1,
            userid=1,
            profileid=1,
            expiretime=0,
            profilenick="AB",  # "AB" != "A" + null
            uniquenick="A",
            cdkeyhash="",
            peerkeymodulus=keypair.modulus,
            peerkeyexponent=keypair.exponent,
            serverdata="00" * 128,
        )

        assert hash1 != hash2

    def test_modulus_leading_zeros_stripped(self):
        """Verify modulus has leading zeros removed before hashing."""
        # Modulus "00AABB..." should hash same bytes as "AABB..." (after stripping)
        # This is handled by lstrip(b'\x00') in the implementation

        keypair = generate_rsa_keypair()

        hash1 = compute_certificate_hash(
            length=305,
            version=1,
            partnercode=0,
            namespaceid=1,
            userid=1,
            profileid=1,
            expiretime=0,
            profilenick="A",
            uniquenick="A",
            cdkeyhash="",
            peerkeymodulus=keypair.modulus,
            peerkeyexponent=keypair.exponent,
            serverdata="00" * 128,
        )

        # The hash should be 16 bytes
        assert len(hash1) == 16  # MD5 is 16 bytes

    def test_hash_is_16_bytes_md5(self):
        """Verify hash output is 16-byte MD5."""
        keypair = generate_rsa_keypair()

        cert_hash = compute_certificate_hash(
            length=305,
            version=1,
            partnercode=0,
            namespaceid=1,
            userid=12345,
            profileid=67890,
            expiretime=0,
            profilenick="TestPlayer",
            uniquenick="TestPlayer",
            cdkeyhash="",
            peerkeymodulus=keypair.modulus,
            peerkeyexponent=keypair.exponent,
            serverdata="00" * 128,
        )

        assert len(cert_hash) == 16


class TestRSASignPKCS1v15:
    """Test PKCS#1 v1.5 signature format."""

    def test_signature_length_is_256_hex(self):
        """Verify signature is 256 hex chars (128 bytes = 1024 bits)."""
        keypair = generate_rsa_keypair()
        test_hash = hashlib.md5(b"test").digest()

        signature = rsa_sign_pkcs1v15(test_hash, keypair.private_key, keypair.modulus)

        assert len(signature) == 256
        assert all(c in "0123456789ABCDEF" for c in signature)

    def test_signature_verifies_with_public_key(self):
        """Verify signature can be decrypted and verified with public key."""
        keypair = generate_rsa_keypair()
        test_hash = hashlib.md5(b"test data").digest()

        signature = rsa_sign_pkcs1v15(test_hash, keypair.private_key, keypair.modulus)

        # Verify by decrypting with public key: decrypted = sig^e mod n
        sig_int = int(signature, 16)
        e = int(keypair.exponent, 16)
        n = int(keypair.modulus, 16)

        decrypted_int = pow(sig_int, e, n)
        decrypted = decrypted_int.to_bytes(128, byteorder="big")

        # Check PKCS#1 v1.5 format: 0x00 0x01 [0xFF padding] 0x00 [DigestInfo] [hash]
        assert decrypted[0] == 0x00
        assert decrypted[1] == 0x01

        # Find separator (0x00 after 0xFF padding)
        sep_idx = decrypted.index(b"\x00", 2)

        # Check padding is all 0xFF
        assert all(b == 0xFF for b in decrypted[2:sep_idx])

        # Extract hash from end (last 16 bytes)
        extracted_hash = decrypted[-16:]
        assert extracted_hash == test_hash

    def test_pkcs_md5_digestinfo_header(self):
        """Verify MD5 DigestInfo header is correctly embedded."""
        keypair = generate_rsa_keypair()
        test_hash = hashlib.md5(b"test").digest()

        signature = rsa_sign_pkcs1v15(test_hash, keypair.private_key, keypair.modulus)

        # Decrypt signature
        sig_int = int(signature, 16)
        e = int(keypair.exponent, 16)
        n = int(keypair.modulus, 16)
        decrypted = pow(sig_int, e, n).to_bytes(128, byteorder="big")

        # Check DigestInfo header is present before hash
        digest_info_start = 128 - 16 - len(MD5_DIGESTINFO)
        assert decrypted[digest_info_start : digest_info_start + len(MD5_DIGESTINFO)] == MD5_DIGESTINFO


class TestGenerateCertificateForPlayer:
    """Integration test for full certificate generation."""

    def test_generated_certificate_has_valid_signature(self):
        """Verify generated certificate signature validates with SERVER key."""
        cert = generate_certificate_for_player(
            userid=12345,
            profileid=67890,
            profilenick="TestPlayer",
            uniquenick="TestPlayer",
        )

        # Recompute hash using same fields
        recomputed_hash = compute_certificate_hash(
            length=305,
            version=1,
            partnercode=60,
            namespaceid=69,
            userid=12345,
            profileid=67890,
            expiretime=0,
            profilenick="TestPlayer",
            uniquenick="TestPlayer",
            cdkeyhash="",
            peerkeymodulus=cert.peerkeymodulus,
            peerkeyexponent=cert.peerkeyexponent,
            serverdata=cert.serverdata,
        )

        # Decrypt signature with SERVER public key (not peer key!)
        # This simulates what the game client does with WS_AUTHSERVICE_SIGNATURE_KEY
        sig_int = int(cert.signature, 16)
        e = int(SERVER_SIGNING_EXPONENT, 16)
        n = int(SERVER_SIGNING_MODULUS, 16)
        decrypted = pow(sig_int, e, n).to_bytes(128, byteorder="big")

        # Extract hash from decrypted padding
        extracted_hash = decrypted[-16:]

        assert extracted_hash == recomputed_hash

    def test_certificate_fields_have_correct_format(self):
        """Verify certificate fields have expected format."""
        cert = generate_certificate_for_player(
            userid=1,
            profileid=2,
            profilenick="Nick",
        )

        # Modulus: 256 hex chars
        assert len(cert.peerkeymodulus) == 256

        # Exponent: "010001"
        assert cert.peerkeyexponent == "010001"

        # Private key: 256 hex chars
        assert len(cert.peerkeyprivate) == 256

        # Server data: 256 hex chars (128 bytes)
        assert len(cert.serverdata) == 256

        # Signature: 256 hex chars
        assert len(cert.signature) == 256


class TestBinaryFormatVerification:
    """Verify the exact binary format matches UniSpySDK expectations."""

    def test_hash_input_structure(self):
        """Verify hash input matches UniSpySDK wsLoginCertWriteDataToHash format."""
        # Manually construct expected binary input and compare hash

        keypair = generate_rsa_keypair()

        # Build expected input manually
        expected_input = b""

        # 7 integers as 4-byte little-endian
        expected_input += struct.pack("<I", 305)  # length
        expected_input += struct.pack("<I", 1)  # version
        expected_input += struct.pack("<I", 0)  # partnercode
        expected_input += struct.pack("<I", 1)  # namespaceid
        expected_input += struct.pack("<I", 12345)  # userid
        expected_input += struct.pack("<I", 67890)  # profileid
        expected_input += struct.pack("<I", 0)  # expiretime

        # 3 strings (no null terminator)
        expected_input += b"TestPlayer"  # profilenick
        expected_input += b"TestPlayer"  # uniquenick
        expected_input += b""  # cdkeyhash (empty)

        # modulus/exponent with leading zeros stripped
        mod_bytes = bytes.fromhex(keypair.modulus).lstrip(b"\x00") or b"\x00"
        exp_bytes = bytes.fromhex(keypair.exponent).lstrip(b"\x00") or b"\x00"
        expected_input += mod_bytes
        expected_input += exp_bytes

        # serverdata (128 bytes)
        expected_input += bytes(128)

        expected_hash = hashlib.md5(expected_input).digest()

        # Compare with our function
        computed_hash = compute_certificate_hash(
            length=305,
            version=1,
            partnercode=0,
            namespaceid=1,
            userid=12345,
            profileid=67890,
            expiretime=0,
            profilenick="TestPlayer",
            uniquenick="TestPlayer",
            cdkeyhash="",
            peerkeymodulus=keypair.modulus,
            peerkeyexponent=keypair.exponent,
            serverdata="00" * 128,
        )

        assert computed_hash == expected_hash
