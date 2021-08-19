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

        self.base_fee_per_gas: int = base_fee_per_gas
        self.difficulty: int = difficulty
        self.extra_data: EthHexString = extra_data
        self.gas_limit: int = gas_limit
        self.gas_used: int = gas_used
        self.hash_: EthHashString = hash_
        self.logs_bloom: EthHexString = logs_bloom
        self.miner: ChecksumAddress = miner
        self.mix_hash: EthHashString = mix_hash
        self.nonce: int = nonce
        self.number: int = number
        self.parent_hash: EthHashString = parent_hash
        self.receipts_root: EthHashString = receipts_root
        self.sha3_uncles: EthHashString = sha3_uncles
        self.size: int = size
        self.state_root: EthHashString = state_root
        self.timestamp: int = timestamp
        self.total_difficulty: int = total_difficulty
        self.transactions_root: EthHashString = transactions_root
        self.transactions: list = transactions
        self.uncles: list = uncles

    @classmethod
    def from_dict(cls, block_dict: dict):
        base_fee_per_gas: int = int(block_dict["baseFeePerGas"], 16)
        difficulty: int = int(block_dict["difficulty"], 16)
        extra_data: EthHexString = EthHexString.from_hex(block_dict["extraData"])
        gas_limit: int = int(block_dict["gasLimit"], 16)
        gas_used: int = int(block_dict["gasUsed"], 16)
        hash_: EthHashString = EthHashString.from_hex(block_dict["hash"])
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
        transactions: list = block_dict["transactions"]
        uncles: list = block_dict["uncles"]

        return cls(base_fee_per_gas, difficulty, extra_data, gas_limit, gas_used, hash_, logs_bloom, miner, mix_hash,
                   nonce, number, parent_hash, receipts_root, sha3_uncles, size, state_root, timestamp, total_difficulty,
                   transactions_root, transactions, uncles)

    def to_dict(self):
        ret_dict = dict()
        ret_dict["baseFeePerGas"] = hex(self.base_fee_per_gas)
        ret_dict["difficulty"] = hex(self.difficulty)
        ret_dict["extraData"] = self.extra_data.to_string_with_0x()
        ret_dict["gasLimit"] = hex(self.gas_limit)
        ret_dict["gasUsed"] = hex(self.gas_used)
        ret_dict["hash"] = self.hash_.to_string_with_0x()
        ret_dict["logsBloom"] = self.logs_bloom.to_string_with_0x()
        ret_dict["miner"] = self.miner.to_string_with_0x()
        ret_dict["mixHash"] = self.mix_hash.to_string_with_0x()
        ret_dict["nonce"] = hex(self.nonce)
        ret_dict["number"] = hex(self.number)
        ret_dict["parentHash"] = self.parent_hash.to_string_with_0x()
        ret_dict["receiptsRoot"] = self.receipts_root.to_string_with_0x()
        ret_dict["sha3Uncles"] = self.sha3_uncles.to_string_with_0x()
        ret_dict["size"] = hex(self.size)
        ret_dict["stateRoot"] = self.state_root.to_string_with_0x()
        ret_dict["timestamp"] = hex(self.timestamp)
        ret_dict["totalDifficulty"] = hex(self.total_difficulty)
        ret_dict["transactionsRoot"] = self.transactions_root.to_string_with_0x()

        ret_dict["transactions"] = self.transactions  # TODO change list of dict to object list
        ret_dict["uncles"] = self.uncles  # TODO change list of dict to object list
        return ret_dict

    def serialize(self):
        pass

    @property
    def hash(self):
        return None


class EthBlockTest(TestCase):
    def setUp(self) -> None:
        with open("test_data/block_example.json", "r") as json_data:
            self.block_dict = json.load(json_data)

    def test_block_constructor(self):
        block = EthBlock.from_dict(self.block_dict)
        print(block.to_dict())



