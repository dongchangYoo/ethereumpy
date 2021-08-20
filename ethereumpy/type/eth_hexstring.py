from unittest import TestCase

from ethereumpy.exception.exceptions import *
from typing import Union


class EthHexString:
    def __init__(self, value: Union[bytes, None]):
        if not isinstance(value, bytes) and value is not None:
            raise EthTypeError("Invalid input type")
        self.value = value

    @classmethod
    def from_hex(cls, value: str):
        # define empty hash
        if value is None or value == "":
            return cls(None)

        # type check
        if not isinstance(value, str):
            raise EthTypeError("expected type: str, but {}".format(type(value)))

        # value must have prefix: "0x"
        if value.startswith("0x"):
            value = value[2:]

        return cls(bytes.fromhex(value))

    def __repr__(self) -> str:
        if self.is_empty():
            return "EthHash()"
        return "EthHash(0x" + self.value.hex() + ")"

    def __str__(self) -> str:
        if self.is_empty():
            return ""
        return "0x" + self.value.hex()

    def __eq__(self, other):
        if not isinstance(__class__, other):
            raise EthTypeError("EthHash type cannot be compared with type: {}".format(type(other)))
        if self.is_empty() and other.is_empty():
            return True
        return self.value == other.value

    def to_string_with_0x(self) -> str:
        if self.is_empty():
            return ""
        return "0x" + self.value.hex()

    def to_string_without_0x(self) -> str:
        if self.is_empty():
            return ""
        return self.value.hex()

    def to_bytes(self) -> bytes:
        return self.value

    def is_empty(self):
        return True if self.value is None or self.value == b'' else False


class EthHashString(EthHexString):
    def __init__(self, value: bytes):
        if len(value) != 32 and value is not None:
            raise EthValueError("expected byte-length: {}, but {}".format(32, len(value)))
        super().__init__(value)


class BytesTest(TestCase):
    def test_bytes_constructor(self):
        bytes_with_0x = "0x04008020c2e11875645373fd2ef8217dd51a1969b8711c863b030400000000000000000012eb8bf7f335e8bd6f5beb76c651574cf7c3ec72f7a0cf3dbe4ac27f425bb83a31791b610b18121738d16c2e"
        bytes_without_0x = "04008020c2e11875645373fd2ef8217dd51a1969b8711c863b030400000000000000000012eb8bf7f335e8bd6f5beb76c651574cf7c3ec72f7a0cf3dbe4ac27f425bb83a31791b610b18121738d16c2e"

        custom_bytes = EthHexString.from_hex(bytes_with_0x)
        self.assertEqual(custom_bytes.to_string_with_0x(), bytes_with_0x)

        custom_bytes = EthHexString.from_hex(bytes_without_0x)
        self.assertEqual(custom_bytes.to_string_with_0x(), bytes_with_0x)

    def test_hash_constructor(self):
        tx_hash_0x = "0x0890d66d6e8b577e73770abb14574db553a25fe09068831e5bc6756178697a4d"
        tx_hash = "0890d66d6e8b577e73770abb14574db553a25fe09068831e5bc6756178697a4d"

        tx_hash_bytes = EthHashString.from_hex(tx_hash)
        self.assertEqual(tx_hash_bytes.to_string_with_0x(), tx_hash_0x)

        tx_hash_bytes = EthHashString.from_hex(tx_hash_0x)
        self.assertEqual(tx_hash_bytes.to_string_with_0x(), tx_hash_0x)