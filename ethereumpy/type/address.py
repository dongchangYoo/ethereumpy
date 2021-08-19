from unittest import TestCase

import web3

from ethereumpy.exception.basic_exceptions import *
from sha3 import keccak_256
from string import hexdigits
import binascii
from typing import Union


class ChecksumAddress:
    def __init__(self, value: str = None):

        # store empty address
        if value is None or value == "":
            self.value = None
        else:
            # type check
            if not isinstance(value, str):
                raise EthTypeError("expected type: str, but {}".format(type(value)))

            # value must have prefix: "0x"
            if not value.startswith("0x"):
                value = "0x" + value

            if not ChecksumAddress.is_hex(value):
                raise EthValueError("only allowed hexadecimal")

            # length check (20 byte)
            if len(value) != 42:
                raise EthValueError("expected byte-length: 20, but {}".format(len(value)//2))

            # store value in encoded checksum form
            self.value = ChecksumAddress.checksum_encode(value)

    def __repr__(self):
        return "ChecksumAddress(" + self.value + ")"

    def __str__(self):
        return "ChecksumAddress(" + self.value + ")"

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

    def to_string_with_0x(self):
        return self.value

    def to_string_without_0x(self):
        return self.value[2:] if not self.is_empty() else self.value

    @staticmethod
    def is_hex(value: str):
        if value.startswith("0x"):
            value = value[2:]
        hex_digits = set(hexdigits)
        return all(c in hex_digits for c in value) and len(value) % 2 == 0

    @staticmethod
    def checksum_encode(addr: str) -> Union[str, None]:
        # encoding address to bytes
        norm_addr = addr.replace("0x", "").lower()
        addr_bytes = norm_addr.encode("utf-8")
        address_hash = keccak_256(addr_bytes).hexdigest()

        checksum_address = "0x"
        for i in range(40):
            if int(address_hash[i], 16) > 7:
                checksum_address += norm_addr[i].upper()
            else:
                checksum_address += norm_addr[i]
        return checksum_address

    @staticmethod
    def is_checksum_address(address: str) -> bool:
        address = address.replace('0x', '')
        addr_hash = keccak_256(address.lower()).hexdigest()
        for i in range(40):
            if int(addr_hash[i], 16) > 7 and address[i].upper() != address[i]:
                return False
            if int(addr_hash[i], 16) <= 7 and address[i].lower() != address[i]:
                return False
        return True

    @classmethod
    def zero_address(cls):
        return cls("0x0000000000000000000000000000000000000000")


class AddressTest(TestCase):
    def setUp(self) -> None:
        self.addr = "0x99C85bb64564D9eF9A99621301f22C9993Cb89E3"

    def test_constructor(self):
        addr = ChecksumAddress(self.addr)
        self.assertEqual(self.addr, addr.to_string_with_0x())

        addr = ChecksumAddress()
        self.assertEqual(None, addr.to_string_with_0x())
