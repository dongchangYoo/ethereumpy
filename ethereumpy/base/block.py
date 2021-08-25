from ethereumpy.base.chain_transaction import ChainTransaction
from ethereumpy.type.eth_hexstring import EthHexString, EthHashString
from ethereumpy.type.eth_address import ChecksumAddress
from unittest import TestCase
import json


class EthBlock:
    def __init__(
            self, base_fee_per_gas: int, difficulty: int, extra_data: EthHexString, gas_limit: int, gas_used: int,
            hash_: EthHashString, logs_bloom: EthHexString, miner: ChecksumAddress, mix_hash: EthHashString, nonce: int,
            number: int, parent_hash: EthHashString, receipts_root: EthHashString, sha3_uncles: EthHashString,
            size: int, state_root: EthHashString, timestamp: int, total_difficulty: int,
            transactions_root: EthHashString, transactions: list, uncles: list):

        self._base_fee_per_gas: int = base_fee_per_gas
        self._difficulty: int = difficulty
        self._extra_data: EthHexString = extra_data
        self._gas_limit: int = gas_limit
        self._gas_used: int = gas_used
        self._hash: EthHashString = hash_
        self._logs_bloom: EthHexString = logs_bloom
        self._miner: ChecksumAddress = miner
        self._mix_hash: EthHashString = mix_hash
        self._nonce: int = nonce
        self._number: int = number
        self._parent_hash: EthHashString = parent_hash
        self._receipts_root: EthHashString = receipts_root
        self._sha3_uncles: EthHashString = sha3_uncles
        self._size: int = size
        self._state_root: EthHashString = state_root
        self._timestamp: int = timestamp
        self._total_difficulty: int = total_difficulty
        self._transactions_root: EthHashString = transactions_root
        self._transactions: list = transactions
        self._uncles: list = uncles

        if len(self._transactions) == 0 or isinstance(self._transactions[0], str):
            self.verbose = False
        elif isinstance(self._transactions[0], ChainTransaction):
            self.verbose = True
        else:
            raise Exception("Unknown Error")

    @classmethod
    def from_dict(cls, block_dict: dict):
        base_fee_per_gas: int = int(block_dict["baseFeePerGas"], 16)
        difficulty: int = int(block_dict["difficulty"], 16)
        extra_data: EthHexString = EthHexString.from_hex(block_dict["extraData"])
        gas_limit: int = int(block_dict["gasLimit"], 16)
        gas_used: int = int(block_dict["gasUsed"], 16)
        _hash: EthHashString = EthHashString.from_hex(block_dict["hash"])
        logs_bloom: EthHexString = EthHexString.from_hex(block_dict["logsBloom"])
        miner: ChecksumAddress = ChecksumAddress(block_dict["miner"])
        mix_hash: EthHashString = EthHashString.from_hex(block_dict["mixHash"])
        nonce: int = int(block_dict["nonce"], 16)
        number: int = int(block_dict["number"], 16)
        parent_hash: EthHashString = EthHashString.from_hex(block_dict["parentHash"])
        receipts_root: EthHashString = EthHashString.from_hex(block_dict["receiptsRoot"])
        sha3_uncles: EthHashString = EthHashString.from_hex(block_dict["sha3Uncles"])
        size: int = int(block_dict["size"], 16)
        state_root: EthHashString = EthHashString.from_hex(block_dict["stateRoot"])
        timestamp: int = int(block_dict["timestamp"], 16)
        total_difficulty: int = int(block_dict["totalDifficulty"], 16)
        transactions_root: EthHashString = EthHashString.from_hex(block_dict["transactionsRoot"])

        # check verbose
        raw_tx_list = block_dict["transactions"]
        verbose: bool = True if isinstance(raw_tx_list[0], dict) else False
        transactions: list = [ChainTransaction.from_dict(tx) for tx in raw_tx_list] if verbose else raw_tx_list
        uncles: list = block_dict["uncles"]

        return cls(base_fee_per_gas, difficulty, extra_data, gas_limit, gas_used, _hash, logs_bloom, miner, mix_hash,
                   nonce, number, parent_hash, receipts_root, sha3_uncles, size, state_root, timestamp, total_difficulty,
                   transactions_root, transactions, uncles)

    def to_dict(self):
        ret_dict = dict()
        ret_dict["baseFeePerGas"] = hex(self._base_fee_per_gas)
        ret_dict["difficulty"] = hex(self._difficulty)
        ret_dict["extraData"] = self._extra_data.to_string_with_0x()
        ret_dict["gasLimit"] = hex(self._gas_limit)
        ret_dict["gasUsed"] = hex(self._gas_used)
        ret_dict["hash"] = self._hash.to_string_with_0x()
        ret_dict["logsBloom"] = self._logs_bloom.to_string_with_0x()
        ret_dict["miner"] = self._miner.to_string_with_0x().lower()
        ret_dict["mixHash"] = self._mix_hash.to_string_with_0x()
        ret_dict["nonce"] = hex(self._nonce)
        ret_dict["number"] = hex(self._number)
        ret_dict["parentHash"] = self._parent_hash.to_string_with_0x()
        ret_dict["receiptsRoot"] = self._receipts_root.to_string_with_0x()
        ret_dict["sha3Uncles"] = self._sha3_uncles.to_string_with_0x()
        ret_dict["size"] = hex(self._size)
        ret_dict["stateRoot"] = self._state_root.to_string_with_0x()
        ret_dict["timestamp"] = hex(self._timestamp)
        ret_dict["totalDifficulty"] = hex(self._total_difficulty)
        ret_dict["transactionsRoot"] = self._transactions_root.to_string_with_0x()
        ret_dict["transactions"] = [tx.to_dict() for tx in self._transactions] if self.verbose else self._transactions
        ret_dict["uncles"] = self._uncles  # TODO change list of dict to object list
        return ret_dict

    def serialize(self):
        # TODO hash value of the "serialize()" output must equals to block hash
        pass

    def self_verify(self):
        # TODO verification of 1) transaction root, 2) condition of the block hash and etc
        pass

    @property
    def base_fee(self) -> str:
        return hex(self._base_fee_per_gas)

    @property
    def difficulty(self) -> str:
        return hex(self._difficulty)

    @property
    def extra_data(self) -> str:
        return self._extra_data.to_string_with_0x()

    @property
    def gas_limit(self) -> str:
        return hex(self._gas_limit)

    @property
    def gas_used(self) -> str:
        return hex(self._gas_used)

    @property
    def hash(self) -> str:
        return self._hash.to_string_with_0x()

    @property
    def logs_bloom(self) -> str:
        return self._logs_bloom.to_string_with_0x()

    @property
    def miner(self) -> str:
        return self._miner.to_string_with_0x()

    @property
    def mix_hash(self) -> str:
        return self._mix_hash.to_string_with_0x()

    @property
    def nonce(self) -> str:
        return hex(self._nonce)

    @property
    def number(self) -> str:
        return hex(self._number)

    @property
    def parent_hash(self) -> str:
        return self._parent_hash.to_string_with_0x()

    @property
    def receipts_hash(self) -> str:
        return self._receipts_root.to_string_with_0x()

    @property
    def uncles_hash(self) -> str:
        return self._sha3_uncles.to_string_with_0x()

    @property
    def size(self) -> str:
        return hex(self._size)

    @property
    def state_root(self) -> str:
        return self._state_root.to_string_with_0x()

    @property
    def timestamp(self) -> str:
        return hex(self._timestamp)

    @property
    def total_difficulty(self) -> str:
        return hex(self._total_difficulty)

    @property
    def transaction_root(self) -> str:
        return self._transactions_root.to_string_with_0x()

    @property
    def transactions(self) -> list:
        return self._transactions

    def get_transaction_by_index(self, index: int) -> ChainTransaction:
        return self._transactions[index]

    @property
    def uncles(self) -> list:
        return self._uncles  # TODO change list of dict to object list

    def get_uncles_by_index(self, index: int) -> str:
        return self._uncles[index]


class EthBlockTest(TestCase):
    def setUp(self) -> None:
        with open("test_data/verbose_true_block.json", "r") as json_data:
            self.verbose_block_dict = json.load(json_data)

        with open("test_data/verbose_false_block.json", "r") as json_data:
            self.block_dict = json.load(json_data)

        # revise transaction input string when it is empty
        for tx in self.verbose_block_dict["transactions"]:
            if tx["input"] == "0x":
                tx["input"] = ""

    def test_block_constructor(self):
        block = EthBlock.from_dict(self.verbose_block_dict)
        self._block_members_check(self.verbose_block_dict, block)

    def test_verbose_block_constructor(self):
        block = EthBlock.from_dict(self.block_dict)
        self._block_members_check(self.block_dict, block)

    def test_exporter(self):
        block = EthBlock.from_dict(self.verbose_block_dict)
        self.assertEqual(self.verbose_block_dict, block.to_dict())

    def _block_members_check(self, expected: dict, block: EthBlock):
        self.assertEqual(expected["baseFeePerGas"], block.base_fee)
        self.assertEqual(expected["difficulty"], block.difficulty)
        self.assertEqual(expected["extraData"], block.extra_data)
        self.assertEqual(expected["gasLimit"], block.gas_limit)
        self.assertEqual(expected["gasUsed"], block.gas_used)
        self.assertEqual(expected["hash"], block.hash)
        self.assertEqual(expected["logsBloom"], block.logs_bloom)
        self.assertEqual(expected["miner"], block.miner.lower())
        self.assertEqual(expected["mixHash"], block.mix_hash)
        self.assertEqual(expected["nonce"], block.nonce)
        self.assertEqual(expected["number"], block.number)
        self.assertEqual(expected["parentHash"], block.parent_hash)
        self.assertEqual(expected["receiptsRoot"], block.receipts_hash)
        self.assertEqual(expected["sha3Uncles"], block.uncles_hash)
        self.assertEqual(expected["size"], block.size)
        self.assertEqual(expected["totalDifficulty"], block.total_difficulty)
        self.assertEqual(expected["transactionsRoot"], block.transaction_root)

        if block.verbose:
            self.assertEqual(expected["transactions"], [tx.to_dict() for tx in block.transactions])
        else:
            self.assertEqual(expected["transactions"], [tx for tx in block.transactions])
