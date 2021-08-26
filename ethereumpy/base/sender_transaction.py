from typing import Union
from unittest import TestCase

import rlp
import copy

import web3

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
    def set_metadata(cls,
                     nonce: int,
                     gas_limit: int = None,
                     gas_price: int = None,
                     chain_id: int = None):

        # revise "nonce"
        if not isinstance(nonce, int):
            raise Exception("Invalid nonce type")

        # revise "gas_limit"
        if gas_limit is None:
            gas_limit = DEFAULT_GAS_LIMIT

        # revise "gas_price"
        if gas_price is None:
            gas_price = DEFAULT_GAS_PRICE

        # initiate optional data
        value = 0
        data = EthHexString()
        to = ChecksumAddress()

        # initiate signature data
        v = chain_id if chain_id is not None else None
        r = None
        s = None

        return cls(nonce, to, value, data, gas_limit, gas_price, chain_id, v, r, s)

    def set_to(self, to: Union[ChecksumAddress, str]):
        to = to if isinstance(to, ChecksumAddress) else ChecksumAddress(to)
        if to.is_empty():
            raise Exception("\"to\" must be not empty")
        self.to = to
        return self

    def set_value(self, value: int):
        if not isinstance(value, int):
            raise Exception("Invalid input type")
        self.value = value
        return self

    def set_input(self, *args):
        args_list = list(args)
        normalized: list = SenderTransaction.normalize_parameter(args_list)
        # abi_encoded: str =

    @staticmethod
    def normalize_parameter(arg: Union[int, str, bytes, ChecksumAddress, list]):
        if isinstance(arg, int):
            if arg < 0 or 2**256 < arg:
                raise Exception("Invalid int param")
            encoded_input = arg
        elif isinstance(arg, str):
            if not arg.startswith("0x"):
                arg = arg.encode().hex()
            encoded_input = arg
        elif isinstance(arg, bytes):
            encoded_input = arg.hex()
        elif isinstance(arg, ChecksumAddress):
            encoded_input = arg.to_string_with_0x()
        elif isinstance(arg, list):
            encoded_input = [SenderTransaction.normalize_parameter(item) for item in arg]
        else:
            raise Exception("Invalid Input type: {}".format(type(arg)))
        return encoded_input

    @staticmethod
    def abi_encode(normalized_param: Union[str, int, list]):
        # function_sig = "0x2289b18c"
        padding = SenderTransaction.get_padded_data
        calc_len = SenderTransaction.calc_byte_len

        encoded = ""
        if isinstance(normalized_param, str):
            byte_len = calc_len(normalized_param)
            encoded += padding(byte_len)
            encoded += padding(normalized_param)
        elif isinstance(normalized_param, int):
            encoded = padding(normalized_param)
        elif isinstance(normalized_param, list):
            encoded_data = [SenderTransaction.abi_encode(param) for param in normalized_param]
            encoded += "".join(encoded_data)

            encoded_count = len(encoded_data)  # count
            offsets = [encoded_count * 32]
            for i in range(len(encoded_data) - 1):
                offset = offsets[-1] + calc_len(encoded_data[i])
                offsets.append(offset)

            encoded_offsets = [padding(item) for item in offsets]
            encoded = "".join([padding(encoded_count)] + encoded_offsets) + encoded
        else:
            raise Exception("Not supported type")
        return encoded

    @staticmethod
    def get_padded_data(target: Union[str, int]):
        if isinstance(target, int):
            target_str = hex(target).replace("0x", "")
        elif isinstance(target, str):
            target_str = target
        else:
            raise Exception("Not supported input type")
        r = len(target_str) % 64
        pad = "0" * (64 - r)
        return target_str + pad if isinstance(target, str) else pad + target_str

    @staticmethod
    def calc_byte_len(target: str) -> int:
        len_ = len(target.encode())
        q = len_ // 2
        r = len_ % 2
        return q if r == 0 else q + 1

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
        transaction = SenderTransaction.set_metadata(0, to="0xF0109fC8DF283027b6285cc889F5aA624EaC1F55", value=1000000000,
                                                     gas_limit=2000000, gas_price=234567897654321, chain_id=1)
        expected_hash = "0x6893a6ee8df79b0f5d64a180cd1ef35d030f3e296a5361cf04d02ce720d32ec5"

        self.assertEqual(expected_hash, transaction.hash().to_string_with_0x())

    def test_hash_without_chain_id(self):
        transaction = SenderTransaction.set_metadata(0, to="0xF0109fC8DF283027b6285cc889F5aA624EaC1F55", value=1000000000,
                                                     gas_limit=2000000, gas_price=234567897654321)
        expected_hash = "0x4a1b248a77d82640e1bb1e855a73e56649b78da87861417574fb2a040e15ca0e"

        self.assertEqual(expected_hash, transaction.hash().to_string_with_0x())

    def test_abi_encode(self):
        inputs = [[[1, 2], [3]], ["one", "two", "three"]]
        # inputs = ["one", "two", "three"]
        normalized = SenderTransaction.normalize_parameter(inputs)
        print(normalized)
        result = SenderTransaction.abi_encode(normalized)

        while True:
            print(result[:64])
            result = result[64:]
            if len(result) == 0:
                break
        # web3.Web3.eth.contract().encodeABI