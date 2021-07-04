from exception.basic_exceptions import *
from sha3 import keccak_256
from typing import Union


class ChecksumAddress:
    def __init__(self, value: str = None):
        if not isinstance(value, str) and value is not None:
            raise EthTypeError("expected type: str, but {}".format(type(value)))
        # remove "0x"
        if value is not None and value.startswith("0x"):
            value = value[2:]
        if len(value) != 40 and value is not None:
            raise EthValueError("expected byte-length: 20, but {}".format(len(value)//2))
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
        return True if self.value is None or self.value == "" else False

    def to_raw_address(self):
        return self.value.lower()

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



