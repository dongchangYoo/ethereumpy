from exception.basic_exceptions import *
from typing import Union


class EthHash:
    def __init__(self, value: bytes = None):
        if len(value) != 32 and value is not None:
            raise EthValueError("expected byte-length: 32, but {}".format(len(value)))
        self.value: Union[bytes, None] = value

    @classmethod
    def from_hex(cls, value: str):
        if not isinstance(value, str) and value is not None:
            raise EthTypeError("expected type: str, but {}".format(type(value)))
        if value is None or value == "":
            return cls()
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
        if not isinstance(EthHash, other):
            raise EthTypeError("EthHash type cannot be compared with type: {}".format(type(other)))
        if self.is_empty() and other.is_empty():
            return True
        return self.value == other.value

    def to_string_with_0x(self):
        if self.is_empty():
            return ""
        return "0x" + self.value.hex()

    def to_string_without_0x(self):
        if self.is_empty():
            return ""
        return self.value.hex()

    def is_empty(self):
        return True if self.value is None or self.value == b'' else False
