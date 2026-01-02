"""
GameSpy EncTypeX Cipher implementation.

This cipher is used to encrypt server responses in the GameSpy master server protocol.
Only server responses are encrypted; client requests are sent in plaintext.

The encryption uses:
- A game-specific key
- A validate token from the client request (8 bytes)
- A random salt/IV generated per-response

Based on: https://github.com/teknogods/eaEmu/blob/master/eaEmu/gamespy/cipher.py
"""

import random
from array import array
from typing import Optional, Union

from app.util.logging_helper import get_logger

logger = get_logger(__name__)


class EncTypeX:
    """
    GameSpy EncTypeX cipher for encrypting master server responses.

    Usage:
        cipher = EncTypeX(key="", validate="")
        encrypted = cipher.encode(response_data)
    """

    # Valid characters for random validate token generation
    alphabet = "".join(chr(x) for x in range(0x21, 0x7F))

    @staticmethod
    def get_random_validate() -> str:
        """Generate a random 8-character validate token."""
        return "".join(random.choice(EncTypeX.alphabet) for _ in range(8))

    def __init__(self, key: Union[str, bytes], validate: Optional[Union[str, bytes]] = None):
        """
        Initialize the cipher.

        Args:
            key: The game-specific encryption key
            validate: The validate token from the client request (8 bytes).
                     If not provided, a random one is generated.
        """
        if isinstance(key, str):
            key = key.encode("latin-1")
        self.key = array("B", key)

        self.start = 0

        if validate is None:
            validate = self.get_random_validate()
        if isinstance(validate, str):
            validate = validate.encode("latin-1")
        self.validate = array("B", validate)

        # Initialize with random salt
        salt_len = random.randint(9, 15)
        salt = bytes(random.getrandbits(8) for _ in range(salt_len))
        self._init_encoder(salt)

    def _init_encoder(self, salt: bytes):
        """
        Initialize the encoder state with the given salt.

        Args:
            salt: Random bytes used as initialization vector
        """
        self.salt = array("B", salt)
        self.iv = array("B", self.validate)

        # Mix salt into IV using key
        for i in range(len(self.salt)):
            key_idx = (self.key[i % len(self.key)] * i) & 7
            self.iv[key_idx] ^= self.iv[i & 7] ^ self.salt[i]

        # Initialize encxkey array (256 bytes + 5 extra)
        self.encxkey = array("B", list(range(256)) + [0] * 5)
        self.n1 = 0
        self.n2 = 0

        if len(self.iv) < 1:
            return

        # Shuffle encxkey using _func5
        for i in reversed(range(256)):
            t1 = self._func5(i)
            t2 = self.encxkey[i]
            self.encxkey[i] = self.encxkey[t1]
            self.encxkey[t1] = t2

        # Set up final state values
        self.encxkey[256] = self.encxkey[1]
        self.encxkey[257] = self.encxkey[3]
        self.encxkey[258] = self.encxkey[5]
        self.encxkey[259] = self.encxkey[7]
        self.encxkey[260] = self.encxkey[self.n1 & 0xFF]

    def _func5(self, cnt: int) -> int:
        """
        Helper function for key schedule generation.

        Args:
            cnt: Counter value

        Returns:
            Computed index value
        """
        if not cnt:
            return 0

        mask = 0
        while mask < cnt:
            mask = (mask << 1) + 1

        i = 0
        while True:
            self.n1 = self.encxkey[self.n1 & 0xFF] + self.iv[self.n2]
            self.n2 += 1
            if self.n2 >= len(self.iv):
                self.n2 = 0
                self.n1 += len(self.iv)
            tmp = self.n1 & mask
            i += 1
            if i > 11:
                tmp %= cnt
            if tmp <= cnt:
                break
        return tmp

    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt data using the cipher.

        Args:
            data: Plaintext data to encrypt

        Returns:
            Encrypted data
        """
        return self._crypt(data, encrypt=True)

    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypt data using the cipher.

        Args:
            data: Encrypted data to decrypt

        Returns:
            Decrypted plaintext
        """
        return self._crypt(data, encrypt=False)

    def _crypt(self, data: bytes, encrypt: bool) -> bytes:
        """
        Core encryption/decryption routine.

        Args:
            data: Input data
            encrypt: True for encryption, False for decryption

        Returns:
            Transformed data
        """
        data = array("B", data)

        for i in range(len(data)):
            d = data[i]

            a = self.encxkey[256]
            b = self.encxkey[257]
            c = self.encxkey[a]
            self.encxkey[256] = (a + 1) & 0xFF
            self.encxkey[257] = (b + c) & 0xFF

            a = self.encxkey[260]
            b = self.encxkey[257]
            b = self.encxkey[b]
            c = self.encxkey[a]
            self.encxkey[a] = b

            a = self.encxkey[259]
            b = self.encxkey[257]
            a = self.encxkey[a]
            self.encxkey[b] = a

            a = self.encxkey[256]
            b = self.encxkey[259]
            a = self.encxkey[a]
            self.encxkey[b] = a

            a = self.encxkey[256]
            self.encxkey[a] = c

            b = self.encxkey[258]
            a = self.encxkey[c]
            c = self.encxkey[259]
            b = (b + a) & 0xFF
            self.encxkey[258] = b

            a = b
            c = self.encxkey[c]
            b = self.encxkey[257]
            b = self.encxkey[b]
            a = self.encxkey[a]
            c = (c + b) & 0xFF

            b = self.encxkey[260]
            b = self.encxkey[b]
            c = (c + b) & 0xFF

            b = self.encxkey[c]
            c = self.encxkey[256]
            c = self.encxkey[c]
            a = (a + c) & 0xFF

            c = self.encxkey[b]
            b = self.encxkey[a]
            c ^= b ^ d

            if encrypt:
                self.encxkey[259] = d
                self.encxkey[260] = c
            else:
                self.encxkey[259] = c
                self.encxkey[260] = d

            data[i] = c

        return data.tobytes()

    def encode(self, data: bytes) -> bytes:
        """
        Encode data for transmission (adds header + encrypts).

        The encoded format is:
            [1 byte]  header_length ^ 0xEC - 2
            [header]  random padding bytes
            [1 byte]  iv_length ^ 0xEA (at header_length - 1)
            [iv]      salt/IV bytes
            [data]    encrypted payload

        Args:
            data: Plaintext response data to encode

        Returns:
            Complete encoded message with header and encrypted data
        """
        # Generate header with random padding
        # Header length is between 2 and some small value
        # The first byte encodes the header length
        # The last byte of header encodes the IV length

        header_len = random.randint(2, 10)
        header = array("B", [0] * header_len)

        # First byte: (header_len - 2) ^ 0xEC
        header[0] = (header_len - 2) ^ 0xEC

        # Fill middle bytes with random data
        for i in range(1, header_len - 1):
            header[i] = random.getrandbits(8)

        # Last byte of header: iv_len ^ 0xEA
        header[header_len - 1] = len(self.salt) ^ 0xEA

        # Build complete message: header + salt + encrypted_data
        encrypted_data = self.encrypt(data)

        result = header.tobytes() + self.salt.tobytes() + encrypted_data

        logger.debug(
            "Encoded response: header_len=%d, iv_len=%d, data_len=%d, total=%d",
            header_len,
            len(self.salt),
            len(encrypted_data),
            len(result),
        )

        return result

    def decode(self, data: bytes) -> bytes:
        """
        Decode received data (strips header + decrypts).

        This is primarily used for decrypting responses, but can also
        be used to verify encryption/decryption round-trips.

        Args:
            data: Encoded message with header and encrypted data

        Returns:
            Decrypted plaintext
        """
        data = array("B", data)

        if self.start == 0:
            assert len(data) > 0

            # Parse header length from first byte
            hdr_len = (data[0] ^ 0xEC) + 2
            assert len(data) >= hdr_len

            # Parse IV length from last header byte
            iv_len = data[hdr_len - 1] ^ 0xEA
            self.start = hdr_len + iv_len
            assert len(data) >= self.start

            # Re-initialize decoder with extracted IV
            self._init_encoder(data[hdr_len : hdr_len + iv_len].tobytes())
            data = data[self.start :]

        return self.decrypt(data.tobytes())


def create_encoder(gamekey: str, validate: bytes) -> EncTypeX:
    """
    Create an encoder for encrypting master server responses.

    Args:
        gamekey: Game-specific encryption key
        validate: The validate token from the client request (8 bytes)

    Returns:
        Configured EncTypeX encoder instance
    """
    return EncTypeX(key=gamekey, validate=validate)
