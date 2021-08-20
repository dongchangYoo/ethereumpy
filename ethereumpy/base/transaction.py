from ethereumpy.type.eth_hexstring import EthHexString, EthHashString
from ethereumpy.type.eth_address import ChecksumAddress
from unittest import TestCase
import json


class Access:
    def __init__(self, address: ChecksumAddress, storage_keys: list):
        self._address: ChecksumAddress = address
        self._storage_keys: list = storage_keys

    @classmethod
    def from_dict(cls, access_dict: dict):
        address: ChecksumAddress = ChecksumAddress(access_dict["address"])
        storage_keys: list = [EthHashString.from_hex(storage_key) for storage_key in access_dict["storageKeys"]]
        return cls(address, storage_keys)

    def to_dict(self) -> dict:
        ret_dict = dict()
        ret_dict["address"] = self._address.to_string_with_0x()
        ret_dict["storageKeys"] = [key.to_string_with_0x() for key in self._storage_keys]
        return ret_dict

    def serialize(self) -> bytes:
        pass  # TODO implementation

    @property
    def address(self) -> str:
        return self._address.to_string_with_0x()

    @property
    def storage_keys(self) -> list:
        return self._storage_keys

    def get_storage_key_by_index(self, index: int) -> str:
        return self._storage_keys[index].to_string_with_0x()

class EthTransaction:
    def __init__(self, block_hash: EthHashString, block_number: int, sender: ChecksumAddress, gas: int, gas_price: int,
                 transaction_hash: EthHashString, input_: EthHexString, nonce: int, r: int, s: int, to: ChecksumAddress,
                 transaction_index: int, type_: int, v: int, value: int):

        self._block_hash: EthHashString = block_hash
        self._block_number: int = block_number
        self._from: ChecksumAddress = sender
        self._gas: int = gas
        self._gas_price: int = gas_price
        self._transaction_hash: EthHashString = transaction_hash
        self._input: EthHexString = input_
        self._nonce: int = nonce
        self._r: int = r
        self._s: int = s
        self._to: ChecksumAddress = to
        self._transaction_index: int = transaction_index
        self._type: int = type_
        self._v: int = v
        self._value: int = value

    @classmethod
    def from_dict(cls, transaction_dict: dict):
        block_hash: EthHashString = EthHashString.from_hex(transaction_dict["blockHash"])
        block_number: int = int(transaction_dict["blockNumber"], 16)
        sender: ChecksumAddress = ChecksumAddress(transaction_dict["from"])
        gas: int = int(transaction_dict["gas"], 16)
        gas_price: int = int(transaction_dict["gasPrice"], 16)
        transaction_hash: EthHashString = EthHashString.from_hex(transaction_dict["hash"])
        input_: EthHexString = EthHexString.from_hex(transaction_dict["input"])
        nonce: int = int(transaction_dict["nonce"], 16)
        r: int = int(transaction_dict["r"], 16)
        s: int = int(transaction_dict["s"], 16)
        to: ChecksumAddress = ChecksumAddress(transaction_dict["to"])
        transaction_index: int = int(transaction_dict["transactionIndex"], 16)
        transaction_type: int = int(transaction_dict["type"], 16)
        v: int = int(transaction_dict["v"], 16)
        value: int = int(transaction_dict["value"], 16)

        return cls(block_hash, block_number, sender, gas, gas_price, transaction_hash, input_, nonce,
                   r, s, to, transaction_index, transaction_type, v, value)

    def to_dict(self):
        ret_dict = dict()
        ret_dict["blockHash"] = self._block_hash.to_string_with_0x()
        ret_dict["blockNumber"] = hex(self._block_number)
        ret_dict["from"] = self._from.to_string_with_0x()
        ret_dict["gas"] = hex(self._gas)
        ret_dict["gasPrice"] = hex(self._gas_price)
        ret_dict["hash"] = self._transaction_hash.to_string_with_0x()
        ret_dict["input"] = self._input.to_string_with_0x()
        ret_dict["nonce"] = hex(self._block_number)
        ret_dict["r"] = hex(self._block_number)
        ret_dict["s"] = hex(self._block_number)
        ret_dict["to"] = self._to.to_string_with_0x()
        ret_dict["transactionIndex"] = hex(self._block_number)
        ret_dict["type"] = hex(self._block_number)
        ret_dict["v"] = hex(self._block_number)
        ret_dict["value"] = hex(self._block_number)
        return ret_dict

    def serialize(self):
        pass

    @property
    def block_hash(self) -> str:
        return self._block_hash.to_string_with_0x()

    @property
    def block_number(self) -> str:
        return hex(self._block_number)

    @property
    def sender(self) -> str:
        return self._from.to_string_with_0x()

    @property
    def gas(self) -> str:
        return hex(self._gas)

    @property
    def gas_price(self) -> str:
        return hex(self._gas_price)

    @property
    def transaction_hash(self) -> str:
        return self._transaction_hash.to_string_with_0x()

    @property
    def input(self) -> str:
        return self._input.to_string_with_0x()

    @property
    def nonce(self) -> str:
        return hex(self._nonce)

    @property
    def signature(self) -> tuple:
        return hex(self._r), hex(self._s), hex(self._v)

    @property
    def to(self) -> str:
        return self._to.to_string_with_0x()

    @property
    def transaction_index(self) -> str:
        return hex(self._transaction_index)

    @property
    def transaction_type(self) -> str:
        return hex(self._type)

    @property
    def value(self) -> str:
        return hex(self._value)


class EthTransactionTest(TestCase):
    def setUp(self) -> None:
        with open("test_data/transaction_example.json", "r") as json_data:
            self.transaction_dict = json.load(json_data)

    def test_block_constructor(self):
        tx = EthTransaction.from_dict(self.transaction_dict)
        self.assertEqual(self.transaction_dict["blockHash"], tx.block_hash)
        self.assertEqual(self.transaction_dict["blockNumber"], tx.block_number)
        self.assertEqual(self.transaction_dict["from"], tx.sender.lower())
        self.assertEqual(self.transaction_dict["gas"], tx.gas)
        self.assertEqual(self.transaction_dict["gasPrice"], tx.gas_price)
        self.assertEqual(self.transaction_dict["hash"], tx.transaction_hash)
        self.assertEqual(self.transaction_dict["input"], tx.input)
        self.assertEqual(self.transaction_dict["nonce"], tx.nonce)
        expected_sig = (self.transaction_dict["r"], self.transaction_dict["s"], self.transaction_dict["v"])
        self.assertEqual(expected_sig, tx.signature)
        self.assertEqual(self.transaction_dict["to"], tx.to.lower())
        self.assertEqual(self.transaction_dict["transactionIndex"], tx.transaction_index)
        self.assertEqual(self.transaction_dict["type"], tx.transaction_type)
        self.assertEqual(self.transaction_dict["value"], tx.value)


