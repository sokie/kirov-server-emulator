"""
GameSpy RSA/MD5 Certificate Crypto.

Implements certificate generation and signing compatible with GameSpy's AuthService.
Based on UniSpySDK source code analysis.

Key details:
- 1024-bit RSA keys
- MD5 hash over binary-encoded certificate fields (integers as 4-byte little-endian)
- PKCS#1 v1.5 padded RSA signing
- Exponent always "010001" (65537)
"""

import hashlib
import secrets
import struct
from dataclasses import dataclass

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa


@dataclass
class GameSpyKeyPair:
    """RSA key pair in GameSpy format."""

    modulus: str  # 256-char hex (1024-bit)
    exponent: str  # "010001"
    private_key: str  # 256-char hex (private exponent d)


def generate_rsa_keypair() -> GameSpyKeyPair:
    """
    Generate 1024-bit RSA key pair for GameSpy certificate.

    Returns:
        GameSpyKeyPair with modulus, exponent, and private key as hex strings.
    """
    # Generate 1024-bit RSA key with public exponent 65537
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend(),
    )

    private_numbers = key.private_numbers()
    public_numbers = private_numbers.public_numbers

    # Extract and format as uppercase hex, padded to 256 chars (1024 bits = 128 bytes = 256 hex chars)
    modulus_hex = format(public_numbers.n, "0256X")
    private_key_hex = format(private_numbers.d, "0256X")

    return GameSpyKeyPair(
        modulus=modulus_hex,
        exponent="010001",  # Always 65537
        private_key=private_key_hex,
    )


def generate_serverdata() -> str:
    """
    Generate 128 random bytes for serverdata field.

    Returns:
        256-character uppercase hex string (128 bytes).
    """
    random_bytes = secrets.token_bytes(128)
    return random_bytes.hex().upper()


def compute_certificate_hash(
    length: int,
    version: int,
    partnercode: int,
    namespaceid: int,
    userid: int,
    profileid: int,
    expiretime: int,
    profilenick: str,
    uniquenick: str,
    cdkeyhash: str,
    peerkeymodulus: str,
    peerkeyexponent: str,
    serverdata: str,
) -> bytes:
    """
    Compute MD5 hash over certificate fields in GameSpy binary format.

    Based on UniSpySDK wsLoginCertWriteDataToHash():
    - Integers are 4-byte little-endian
    - Strings are raw ASCII (no null terminators)
    - modulus/exponent are big-endian bytes with leading zeros stripped
    - serverdata is 128 raw bytes

    Args:
        All certificate fields in the order GameSpy expects.

    Returns:
        16-byte MD5 hash.
    """
    md5 = hashlib.md5()

    # 7 integers as 4-byte little-endian (matches wsiMakeLittleEndian32 in SDK)
    md5.update(struct.pack("<I", length))
    md5.update(struct.pack("<I", version))
    md5.update(struct.pack("<I", partnercode))
    md5.update(struct.pack("<I", namespaceid))
    md5.update(struct.pack("<I", userid))
    md5.update(struct.pack("<I", profileid))
    md5.update(struct.pack("<I", expiretime))

    # 3 strings as raw ASCII (no null terminators)
    md5.update(profilenick.encode("ascii"))
    md5.update(uniquenick.encode("ascii"))
    md5.update(cdkeyhash.encode("ascii"))

    # modulus: big-endian bytes, strip leading zeros
    mod_bytes = bytes.fromhex(peerkeymodulus)
    mod_bytes = mod_bytes.lstrip(b"\x00") or b"\x00"
    md5.update(mod_bytes)

    # exponent: big-endian bytes, strip leading zeros
    exp_bytes = bytes.fromhex(peerkeyexponent)
    exp_bytes = exp_bytes.lstrip(b"\x00") or b"\x00"
    md5.update(exp_bytes)

    # serverdata: 128 raw bytes
    md5.update(bytes.fromhex(serverdata))

    return md5.digest()


def rsa_sign_raw(hash_bytes: bytes, private_key_hex: str, modulus_hex: str) -> str:
    """
    Perform raw RSA signing without PKCS padding.

    Computes: signature = hash^d mod n

    Args:
        hash_bytes: The MD5 hash to sign (16 bytes).
        private_key_hex: Private exponent 'd' as hex string.
        modulus_hex: RSA modulus 'n' as hex string.

    Returns:
        256-character uppercase hex string (signature).
    """
    # Convert to integers
    hash_int = int.from_bytes(hash_bytes, byteorder="big")
    d = int(private_key_hex, 16)
    n = int(modulus_hex, 16)

    # Raw RSA: sig = hash^d mod n
    sig_int = pow(hash_int, d, n)

    # Convert back to 256-char hex (padded)
    return format(sig_int, "0256X")


# MD5 DigestInfo header for PKCS#1 v1.5 (18 bytes)
# ASN.1 encoding: SEQUENCE { SEQUENCE { OID md5, NULL }, OCTET STRING (16 bytes) }
MD5_DIGESTINFO = bytes([
    0x30, 0x20,  # SEQUENCE, 32 bytes total
    0x30, 0x0C,  # SEQUENCE, 12 bytes
    0x06, 0x08,  # OID, 8 bytes
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05,  # OID 1.2.840.113549.2.5 (MD5)
    0x05, 0x00,  # NULL
    0x04, 0x10,  # OCTET STRING, 16 bytes (hash follows)
])


def rsa_sign_pkcs1v15(hash_bytes: bytes, private_key_hex: str, modulus_hex: str) -> str:
    """
    Perform RSA signing with PKCS#1 v1.5 padding.

    Based on UniSpySDK gsCryptRSASignHash():
    - Constructs padded message: [0x00][0x01][0xFF padding][0x00][DigestInfo][hash]
    - Computes: signature = padded_message^d mod n

    For 1024-bit key (128 bytes):
        2 bytes: 0x00 0x01 (block type)
        91 bytes: 0xFF padding
        1 byte: 0x00 separator
        18 bytes: MD5 DigestInfo
        16 bytes: MD5 hash
        Total: 128 bytes

    Args:
        hash_bytes: The MD5 hash to sign (16 bytes).
        private_key_hex: Private exponent 'd' as hex string.
        modulus_hex: RSA modulus 'n' as hex string.

    Returns:
        256-character uppercase hex string (signature).
    """
    # Key size in bytes (1024-bit key = 128 bytes)
    key_size = len(bytes.fromhex(modulus_hex))

    # Calculate padding length
    # Format: 0x00 0x01 [padding] 0x00 [DigestInfo] [hash]
    # padding_len = key_size - 3 - len(DigestInfo) - len(hash)
    padding_len = key_size - 3 - len(MD5_DIGESTINFO) - len(hash_bytes)

    if padding_len < 8:
        raise ValueError("Key too small for PKCS#1 v1.5 signing")

    # Construct PKCS#1 v1.5 padded message
    padded = (
        b"\x00\x01"  # Block type
        + b"\xff" * padding_len  # Padding
        + b"\x00"  # Separator
        + MD5_DIGESTINFO  # DigestInfo header
        + hash_bytes  # Hash
    )

    assert len(padded) == key_size, f"Padded length {len(padded)} != key size {key_size}"

    # Convert to integer and sign
    padded_int = int.from_bytes(padded, byteorder="big")
    d = int(private_key_hex, 16)
    n = int(modulus_hex, 16)

    # RSA sign: sig = padded^d mod n
    sig_int = pow(padded_int, d, n)

    # Convert back to hex (padded to key size * 2 hex chars)
    return format(sig_int, f"0{key_size * 2}X")


def generate_certificate_signature(
    length: int,
    version: int,
    partnercode: int,
    namespaceid: int,
    userid: int,
    profileid: int,
    expiretime: int,
    profilenick: str,
    uniquenick: str,
    cdkeyhash: str,
    peerkeymodulus: str,
    peerkeyexponent: str,
    serverdata: str,
    peerkeyprivate: str,
) -> str:
    """
    Generate a complete certificate signature.

    Computes MD5 hash over all certificate fields and signs with RSA.

    Args:
        All certificate fields plus the private key.

    Returns:
        256-character uppercase hex signature string.
    """
    # Compute hash over certificate fields
    cert_hash = compute_certificate_hash(
        length=length,
        version=version,
        partnercode=partnercode,
        namespaceid=namespaceid,
        userid=userid,
        profileid=profileid,
        expiretime=expiretime,
        profilenick=profilenick,
        uniquenick=uniquenick,
        cdkeyhash=cdkeyhash,
        peerkeymodulus=peerkeymodulus,
        peerkeyexponent=peerkeyexponent,
        serverdata=serverdata,
    )

    # Sign the hash with PKCS#1 v1.5 padding (per GameSpy SDK gsCryptRSASignHash)
    return rsa_sign_pkcs1v15(cert_hash, peerkeyprivate, peerkeymodulus)


@dataclass
class GeneratedCertificate:
    """Complete generated certificate data."""

    peerkeymodulus: str
    peerkeyexponent: str
    peerkeyprivate: str
    serverdata: str
    signature: str


def generate_certificate_for_player(
    userid: int,
    profileid: int,
    profilenick: str,
    uniquenick: str | None = None,
    cdkeyhash: str = "",
    length: int = 305,
    version: int = 1,
    partnercode: int = 60,
    namespaceid: int = 69,
    expiretime: int = 0,
) -> GeneratedCertificate:
    """
    Generate a complete certificate with valid signature for a player.

    Args:
        userid: Player's user ID.
        profileid: Player's profile ID.
        profilenick: Player's nickname.
        uniquenick: Player's unique nick (defaults to profilenick).
        cdkeyhash: CD key hash (usually empty).
        length: Certificate length (default 305 for RA3).
        version: Certificate version (default 1).
        partnercode: Partner code (default 60 for RA3).
        namespaceid: Namespace ID (default 69 for RA3).
        expiretime: Expiration time (default 0 = never).

    Returns:
        GeneratedCertificate with all crypto fields.
    """
    if uniquenick is None:
        uniquenick = profilenick

    # Generate RSA keypair
    keypair = generate_rsa_keypair()

    # Generate random serverdata
    serverdata = generate_serverdata()

    # Compute signature over all fields
    signature = generate_certificate_signature(
        length=length,
        version=version,
        partnercode=partnercode,
        namespaceid=namespaceid,
        userid=userid,
        profileid=profileid,
        expiretime=expiretime,
        profilenick=profilenick,
        uniquenick=uniquenick,
        cdkeyhash=cdkeyhash,
        peerkeymodulus=keypair.modulus,
        peerkeyexponent=keypair.exponent,
        serverdata=serverdata,
        peerkeyprivate=keypair.private_key,
    )

    return GeneratedCertificate(
        peerkeymodulus=keypair.modulus,
        peerkeyexponent=keypair.exponent,
        peerkeyprivate=keypair.private_key,
        serverdata=serverdata,
        signature=signature,
    )
