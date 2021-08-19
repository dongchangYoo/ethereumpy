from ethereumpy.type.eth_hexstring import EthHexString, EthHashString
from ethereumpy.type.eth_address import ChecksumAddress
from unittest import TestCase
import json


class EthTransaction:
    def __init__(self, block_hash: EthHashString, block_number: int, from_: ChecksumAddress, gas: int, gas_price: int,
                 hash_: EthHashString, input_: EthHexString, nonce: int, r: int, s: int, to: ChecksumAddress,
                 transaction_index: int, type_: int, v: int, value: int):

        self.block_hash: EthHashString = block_hash
        self.block_number: int = block_number
        self.from_: ChecksumAddress = from_
        self.gas: int = gas
        self.gas_price: int = gas_price
        self.hash_: EthHashString = hash_
        self.input_: EthHexString = input_
        self.nonce: int = nonce
        self.r: int = r
        self.s: int = s
        self.to: ChecksumAddress = to
        self.transaction_index: int = transaction_index
        self.type_: int = type_
        self.v: int = v
        self.value: int = value

    @classmethod
    def from_dict(cls, transaction_dict: dict):
        block_hash: EthHashString = EthHashString.from_hex(transaction_dict["blockHash"])
        block_number: int = int(transaction_dict["blockNumber"], 16)
        from_: ChecksumAddress = ChecksumAddress(transaction_dict["from"])
        gas: int = int(transaction_dict["gas"], 16)
        gas_price: int = int(transaction_dict["gasPrice"], 16)
        hash_: EthHashString = EthHashString.from_hex(transaction_dict["hash"])
        input_: EthHexString = EthHexString.from_hex(transaction_dict["input"])
        nonce: int = int(transaction_dict["nonce"], 16)
        r: int = int(transaction_dict["r"], 16)
        s: int = int(transaction_dict["s"], 16)
        to: ChecksumAddress = ChecksumAddress(transaction_dict["to"])
        transaction_index: int = int(transaction_dict["transactionIndex"], 16)
        type_: int = int(transaction_dict["transactionIndex"], 16)
        v: int = int(transaction_dict["transactionIndex"], 16)
        value: int = int(transaction_dict["transactionIndex"], 16)

        return cls(block_hash, block_number, from_, gas, gas_price, hash_, input_, nonce,
                   r, s, to, transaction_index, type_, v, value)

    def to_dict(self):
        ret_dict = dict()
        ret_dict["blockHash"] = self.block_hash.to_string_with_0x()
        ret_dict["blockNumber"] = hex(self.block_number)
        ret_dict["from"] = self.from_.to_string_with_0x()
        ret_dict["gas"] = hex(self.gas)
        ret_dict["gasPrice"] = hex(self.gas_price)
        ret_dict["hash"] = self.hash_.to_string_with_0x()
        ret_dict["input"] = self.input_.to_string_with_0x()
        ret_dict["nonce"] = hex(self.block_number)
        ret_dict["r"] = hex(self.block_number)
        ret_dict["s"] = hex(self.block_number)
        ret_dict["to"] = self.to.to_string_with_0x()
        ret_dict["transactionIndex"] = hex(self.block_number)
        ret_dict["type"] = hex(self.block_number)
        ret_dict["v"] = hex(self.block_number)
        ret_dict["value"] = hex(self.block_number)
        return ret_dict

    def serialize(self):
        pass

    @property
    def hash(self):
        return None


class EthTransactionTest(TestCase):
    def setUp(self) -> None:
        with open("test_data/transaction_example.json", "r") as json_data:
            self.transaction_dict = json.load(json_data)

    def test_block_constructor(self):
        tx = EthTransaction.from_dict(self.transaction_dict)
        self.assertEqual(tx.block_hash.to_string_with_0x(), self.transaction_dict["blockHash"])




