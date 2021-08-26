from typing import Union
from unittest import TestCase

import rlp
import copy

from ethereumpy.base.crypto.hash import eth_hash
from ethereumpy.type.eth_address import ChecksumAddress
from ethereumpy.type.eth_hexstring import EthHexString, EthHashString

DEFAULT_GAS_LIMIT = 5000000
DEFAULT_GAS_PRICE = 1000000000  # means 1 Giga wei


class SenderTransaction:
    def __init__(self,
                 nonce: int,
                 to: ChecksumAddress,
                 value: int = None,
                 data: EthHexString = None,
                 gas_limit: int = None,
                 gas_price: int = None,
                 chain_id: int = None,
                 v: int = None,
                 r: int = None,
                 s: int = None):

        self.chain_id = chain_id
        self.nonce = nonce
        self.to = to
        self.value = value
        self.data = data
        self.gas_limit = gas_limit
        self.gas_price = gas_price
        self.v = v
        self.r = r
        self.s = s

    @classmethod
    def build(cls,
              nonce: int,
              to: Union[ChecksumAddress, str],
              value: int = None,
              data: Union[EthHexString, str] = None,
              gas_limit: int = None,
              gas_price: int = None,
              chain_id: int = None):

        # revise "nonce"
        if not isinstance(nonce, int):
            raise Exception("Invalid nonce type")

        # revise "to" address
        to = to if isinstance(to, ChecksumAddress) else ChecksumAddress(to)
        if to.is_empty():
            raise Exception("\"to\" must be not empty")

        # revise "value"
        if value is None:
            value = 0

        # revise "gas_limit"
        if gas_limit is None:
            gas_limit = DEFAULT_GAS_LIMIT

        # revise "gas_price"
        if gas_price is None:
            gas_price = DEFAULT_GAS_PRICE

        # revise "data"
        if isinstance(data, EthHexString):
            data = data
        elif isinstance(data, str):
            data = EthHexString.from_hex(data)
        else:
            data = EthHexString(data)

        v = chain_id if chain_id is not None else None
        r = None
        s = None

        return cls(nonce, to, value, data, gas_limit, gas_price, chain_id, v, r, s)

    def set_sig(self, v: int, r: int, s: int):
        if v is None or r is None or s is None:
            raise Exception("any one of vrs can be not None")
        self.v = v
        self.r = r
        self.s = s

    def hash(self) -> EthHashString:
        encoded: EthHexString = self.serialize()
        return eth_hash(encoded)

    def serialize(self) -> EthHexString:
        nonce: int = self.nonce
        to: bytes = self.to.to_bytes()
        data: bytes = self.data.to_bytes()
        value: int = self.value
        gas_limit: int = self.gas_limit
        gas_price: int = self.gas_price

        if self.r is None and self.s is None:
            if self.chain_id is None:
                # unsigned transaction and no chain id
                raw_data = [nonce, gas_price, gas_limit, to, value, data]
            else:
                raw_data = [nonce, gas_price, gas_limit, to, value, data, self.chain_id, 0, 0]
        elif self.r is not None or self.s is not None:
            # signed transaction
            raw_data = [nonce, gas_price, gas_limit, to, value, data, self.v, self.r, self.s]
        else:
            raise Exception("only one of r and s is None")

        encoded: bytes = rlp.encode(raw_data)
        return EthHexString.from_bytes(encoded)


class TestTransaction(TestCase):
    def setUp(self) -> None:
        pass

    def test_hash_with_chain_id(self):
        transaction = SenderTransaction.build(0, to="0xF0109fC8DF283027b6285cc889F5aA624EaC1F55", value=1000000000,
                                              gas_limit=2000000, gas_price=234567897654321, chain_id=1)
        expected_hash = "0x6893a6ee8df79b0f5d64a180cd1ef35d030f3e296a5361cf04d02ce720d32ec5"

        self.assertEqual(expected_hash, transaction.hash().to_string_with_0x())

    def test_hash_without_chain_id(self):
        transaction = SenderTransaction.build(0, to="0xF0109fC8DF283027b6285cc889F5aA624EaC1F55", value=1000000000,
                                              gas_limit=2000000, gas_price=234567897654321)
        expected_hash = "0x4a1b248a77d82640e1bb1e855a73e56649b78da87861417574fb2a040e15ca0e"

        self.assertEqual(expected_hash, transaction.hash().to_string_with_0x())


