from exception.basic_exceptions import *
from sha3 import keccak_256
from typing import Union


class ChecksumAddress:
    def __init__(self, value: str = None):
        # store empty address
        if value is None or value == "":
            self.value = None

        # type check
        if not isinstance(value, str):
            raise EthTypeError("expected type: str, but {}".format(type(value)))

        # length check (20 byte)
        if len(value) != 40:
            raise EthValueError("expected byte-length: 20, but {}".format(len(value)//2))

        # value must have prefix: "0x"
        if not value.startswith("0x"):
            value = "0x" + value

        # store value in encoded checksum form
        self.value: Union[str, None] = ChecksumAddress.checksum_encode(value)[2:] if value is not None else None

    def __repr__(self):
        return "Address(" + str(self) + ")"

    def __str__(self):
        if self.is_empty():
            return "0x" + self.value
        else:
            return ""

    def __eq__(self, other):
        if not isinstance(other, ChecksumAddress):
            raise EthTypeError("Address type cannot be compared with type: {}".format(type(other)))
        return True if self.value.lower() == other.value.lower() else False

    def is_empty(self) -> bool:
        return self.value is None

    def to_lower(self):
        return self.value.lower()

    def to_upper(self):
        return self.value.upper()

    @staticmethod
    def checksum_encode(addr: str):
        addr = addr.replace("0x", "")
        o = ''
        v = int(keccak_256(bytes.fromhex(addr)).hexdigest(), 16)
        for i, c in enumerate(addr):
            if c in '0123456789':
                o += c
            else:
                o += c.upper() if (v & (2**(255 - i))) else c.lower()
        return '0x'+o

    @staticmethod
    def is_checksum_address(address: str) -> bool:
        address = address.replace('0x', '')
        addr_hash = keccak_256(address.lower()).hexdigest()
        for i in range(40):
            if int(addr_hash[i], 16) > 7 and address[i].upper() != address[i]:
                return False
            elif int(addr_hash[i], 16) <= 7 and address[i].lower() != address[i]:
                return False
            else:
                return True

    @classmethod
    def zero_address(cls):
        return cls("0x0000000000000000000000000000000000000000")


