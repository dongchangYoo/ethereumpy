from ethereumpy.type.eth_hexstring import EthHexString, EthHashString
from ethereumpy.type.eth_address import ChecksumAddress
from unittest import TestCase
import json


TRANSACTION_TYPES = ["0x0", "0x2"]


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
        ret_dict["address"] = self._address.to_string_with_0x().lower()
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
    def __init__(self, access_list: list, block_hash: EthHashString, block_number: int, chain_id: int, sender: ChecksumAddress, gas: int, gas_price: int,
                 transaction_hash: EthHashString, _input: EthHexString, max_fee_per_gas: int, max_priority_fee_per_gas: int, nonce: int, r: int, s: int, to: ChecksumAddress,
                 transaction_index: int, type_: int, v: int, value: int):

        if type_ not in TRANSACTION_TYPES:
            self._type: int = type_
        else:
            raise Exception("Not supported type: {}".format(type_))

        self._access_list: list = access_list
        self._block_hash: EthHashString = block_hash
        self._block_number: int = block_number
        self._chainId: int = chain_id
        self._from: ChecksumAddress = sender
        self._gas: int = gas
        self._gas_price: int = gas_price
        self._transaction_hash: EthHashString = transaction_hash
        self._input: EthHexString = _input
        self._max_fee_per_gas: int = max_fee_per_gas
        self._max_priority_fee_per_gas: int = max_priority_fee_per_gas
        self._nonce: int = nonce
        self._r: int = r
        self._s: int = s
        self._to: ChecksumAddress = to
        self._transaction_index: int = transaction_index
        self._v: int = v
        self._value: int = value

    @classmethod
    def from_dict(cls, transaction_dict: dict):
        transaction_type: int = int(transaction_dict["type"], 16)

        # In cases of type 0 and type 2
        block_hash: EthHashString = EthHashString.from_hex(transaction_dict["blockHash"])
        block_number: int = int(transaction_dict["blockNumber"], 16)
        sender: ChecksumAddress = ChecksumAddress(transaction_dict["from"])
        gas: int = int(transaction_dict["gas"], 16)
        gas_price: int = int(transaction_dict["gasPrice"], 16)
        transaction_hash: EthHashString = EthHashString.from_hex(transaction_dict["hash"])
        _input: EthHexString = EthHexString.from_hex(transaction_dict["input"])
        nonce: int = int(transaction_dict["nonce"], 16)
        r: int = int(transaction_dict["r"], 16)
        s: int = int(transaction_dict["s"], 16)
        to: ChecksumAddress = ChecksumAddress(transaction_dict["to"])
        transaction_index: int = int(transaction_dict["transactionIndex"], 16)
        v: int = int(transaction_dict["v"], 16)
        value: int = int(transaction_dict["value"], 16)
        access_list = None
        chain_id = None
        max_fee_per_gas = None
        max_priority_fee_per_gas = None

        if transaction_type == 2:
            # In case of type 2 only
            access_list = [Access.from_dict(access) for access in transaction_dict["accessList"]]
            chain_id = int(transaction_dict["chainId"], 16)
            max_fee_per_gas = int(transaction_dict["maxFeePerGas"], 16)
            max_priority_fee_per_gas = int(transaction_dict["maxPriorityFeePerGas"], 16)

        return cls(access_list, block_hash, block_number, chain_id, sender, gas, gas_price, transaction_hash,
                   _input, max_fee_per_gas, max_priority_fee_per_gas, nonce, r, s, to, transaction_index,
                   transaction_type, v, value)

    def to_dict(self):
        ret_dict = dict()

        # In cases of type 0 and type 2
        ret_dict["blockHash"] = self._block_hash.to_string_with_0x()
        ret_dict["blockNumber"] = hex(self._block_number)
        ret_dict["from"] = self._from.to_string_with_0x().lower()
        ret_dict["gas"] = hex(self._gas)
        ret_dict["gasPrice"] = hex(self._gas_price)
        ret_dict["hash"] = self._transaction_hash.to_string_with_0x()
        ret_dict["input"] = self._input.to_string_with_0x()
        ret_dict["nonce"] = hex(self._nonce)
        ret_dict["r"] = hex(self._r)
        ret_dict["s"] = hex(self._s)
        ret_dict["to"] = self._to.to_string_with_0x()
        ret_dict["transactionIndex"] = hex(self._transaction_index)
        ret_dict["type"] = hex(self._type)
        ret_dict["v"] = hex(self._v)
        ret_dict["value"] = hex(self._value)
        if self._type == 2:
            # In case of type 2 only
            ret_dict["accessList"] = [access.to_dict() for access in self._access_list]
            ret_dict["chainId"] = hex(self._chainId)
            ret_dict["maxFeePerGas"] = hex(self._max_fee_per_gas)
            ret_dict["maxPriorityFeePerGas"] = hex(self._max_priority_fee_per_gas)
        return ret_dict

    def serialize(self):
        pass

    @property
    def access_list(self) -> list:
        # it return None when transaction type == 0
        return self._access_list

    @property
    def block_hash(self) -> str:
        return self._block_hash.to_string_with_0x()

    @property
    def block_number(self) -> str:
        return hex(self._block_number)

    @property
    def chain_id(self) -> str:
        # it return None when transaction type == 0
        return hex(self._chainId) if self._chainId is not None else None

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
    def max_fee_per_gas(self) -> str:
        # it return None when transaction type == 0
        return hex(self._max_fee_per_gas) if self._chainId is not None else None

    @property
    def max_priority_fee_per_gas(self) -> str:
        # it return None when transaction type == 0
        return hex(self._max_priority_fee_per_gas) if self._chainId is not None else None

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
        with open("test_data/coinbase_example.json", "r") as json_data:
            self.coinbase = json.load(json_data)

        with open("test_data/transaction_example.json", "r") as json_data:
            self.transaction = json.load(json_data)

    def test_coinbase_constructor(self):
        tx = EthTransaction.from_dict(self.coinbase)
        self.type0_checker(self.coinbase, tx)

    def test_transaction_constructor(self):
        tx = EthTransaction.from_dict(self.transaction)
        self.type0_checker(self.transaction, tx)
        self.type2_checker(self.transaction, tx)

    def type0_checker(self, expected: dict, tx: EthTransaction):
        self.assertEqual(expected["blockHash"], tx.block_hash)
        self.assertEqual(expected["blockNumber"], tx.block_number)
        self.assertEqual(expected["from"], tx.sender.lower())
        self.assertEqual(expected["gas"], tx.gas)
        self.assertEqual(expected["gasPrice"], tx.gas_price)
        self.assertEqual(expected["hash"], tx.transaction_hash)
        self.assertEqual(expected["input"], tx.input)
        self.assertEqual(expected["nonce"], tx.nonce)
        expected_sig = (expected["r"], expected["s"], expected["v"])
        self.assertEqual(expected_sig, tx.signature)
        self.assertEqual(expected["to"], tx.to.lower())
        self.assertEqual(expected["transactionIndex"], tx.transaction_index)
        self.assertEqual(expected["type"], tx.transaction_type)
        self.assertEqual(expected["value"], tx.value)

    def type2_checker(self, expected: dict, tx: EthTransaction):
        for i, access in enumerate(tx.access_list):
            self.assertEqual(expected["accessList"][i], access.to_dict())
        self.assertEqual(expected["chainId"], tx.chain_id)
        self.assertEqual(expected["maxFeePerGas"], tx.max_fee_per_gas)
        self.assertEqual(expected["maxPriorityFeePerGas"], tx.max_priority_fee_per_gas)
