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
                 chain_id: int = 1):

        self.nonce = nonce
        self.to = to
        self.value = value
        self.data = data
        self.gas_limit = gas_limit
        self.gas_price = gas_price
        self.r = 0
        self.s = 0
        self.v = 0
        self.chain_id = chain_id

    @classmethod
    def build(cls,
              nonce: int,
              to: Union[ChecksumAddress, str],
              value: int = None,
              data: Union[EthHexString, str] = None,
              gas_limit: int = None,
              gas_price: int = None,
              chain_id: int = 1):

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

        return cls(nonce, to, value, data, gas_limit, gas_price, chain_id)

    def set_sig(self, v: int, r: int, s: int):
        self.v = v
        self.r = r
        self.s = s

    def hash(self) -> EthHashString:
        # backup
        tx = copy.deepcopy(self)
        tx.set_sig(1, 0, 0)
        encoded = tx.encode_transaction()
        return eth_hash(encoded)

    def encode_transaction(self) -> EthHexString:
        nonce: int = self.nonce
        to: bytes = self.to.to_bytes()
        data: bytes = self.data.to_bytes()
        value: int = self.value
        gas_limit: int = self.gas_limit
        gas_price: int = self.gas_price
        v: int = self.v
        r: int = self.r
        s: int = self.s
        encoded: bytes = rlp.encode([nonce, gas_price, gas_limit, to, value, data, v, r, s])
        return EthHexString.from_bytes(encoded)


class TestTransaction(TestCase):
    def setUp(self) -> None:
        self.transaction = SenderTransaction.build(0, to="0xF0109fC8DF283027b6285cc889F5aA624EaC1F55",
                                                   value=1000000000, gas_limit=2000000, gas_price=234567897654321)
        self.expected_hash = "0x6893a6ee8df79b0f5d64a180cd1ef35d030f3e296a5361cf04d02ce720d32ec5"

    def test_transaction_hash(self):
        self.assertEqual(self.expected_hash, self.transaction.hash().to_string_with_0x())

