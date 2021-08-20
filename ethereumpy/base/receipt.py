import json
from unittest import TestCase

from ethereumpy.type.eth_hexstring import EthHexString, EthHashString
from ethereumpy.type.eth_address import ChecksumAddress


class Log:
    def __init__(self, emitter: ChecksumAddress, block_hash: EthHashString, block_number: int, data: EthHexString,
                 log_index: int, removed: bool, topics: list, transaction_hash: EthHashString, transaction_index: int):
        self._emitter: ChecksumAddress = emitter
        self._block_hash: EthHashString = block_hash
        self._block_number: int = block_number
        self._data: EthHexString = data
        self._log_index: int = log_index
        self._removed: bool = removed
        self._topics: list = topics
        self._transaction_hash: EthHashString = transaction_hash
        self._transaction_index: int = transaction_index

    @classmethod
    def from_dict(cls, log_dict: dict):
        emitter: ChecksumAddress = ChecksumAddress(log_dict["address"])
        block_hash: EthHashString = EthHashString.from_hex(log_dict["blockHash"])
        block_number: int = int(log_dict["blockNumber"], 16)
        data: EthHexString = EthHexString.from_hex(log_dict["data"])
        log_index: int = int(log_dict["logIndex"], 16)
        removed: bool = log_dict["removed"]
        topics: list = [EthHashString.from_hex(topic) for topic in log_dict["topics"]]   # store only first topic
        transaction_hash: EthHashString = EthHashString.from_hex(log_dict["transactionHash"])
        transaction_index: int = int(log_dict["transactionIndex"], 16)
        return cls(emitter, block_hash, block_number, data, log_index, removed, topics,
                   transaction_hash, transaction_index)

    def serialize(self) -> bytes:
        pass # TODO implementation

    @property
    def emitter_addr(self) -> str:
        return self._emitter.to_string_with_0x()

    @property
    def block_hash(self) -> str:
        return self._block_hash.to_string_with_0x()

    @property
    def block_number(self) -> str:
        return hex(self._block_number)

    @property
    def data(self) -> str:
        return self._data.to_string_with_0x()

    @property
    def log_index(self) -> str:
        return hex(self._log_index)

    @property
    def removed(self) -> bool:
        return self._removed

    @property
    def topics(self) -> list:
        return self._topics

    def get_topic_by_index(self, index: int) -> str:
        return self._topics[index].to_string_with_0x()

    @property
    def transaction_hash(self) -> str:
        return self._transaction_hash.to_string_with_0x()

    @property
    def transaction_index(self) -> str:
        return hex(self._transaction_index)


class EthReceipt:
    def __init__(self, block_hash: EthHashString, block_number: int, contract_addr: ChecksumAddress,
                 cumulative_gas_used: int, effective_gas_price: int, from_: ChecksumAddress, gas_used: int, logs: list,
                 logs_bloom: EthHexString, status: bool, to_: ChecksumAddress, tx_hash: EthHashString, tx_index: int,
                 type_: int):
        self._block_hash: EthHashString = block_hash
        self.block_number: int = block_number
        self._contract_addr: ChecksumAddress = contract_addr
        self.cumulative_gas_used: int = cumulative_gas_used
        self.effective_gas_price: int = effective_gas_price
        self.from_: ChecksumAddress = from_
        self.gas_used: int = gas_used
        self._logs: list = logs
        self.logs_bloom: EthHexString = logs_bloom
        self._status: bool = status
        self.to_: ChecksumAddress = to_
        self._tx_hash: EthHashString = tx_hash
        self._tx_index: int = tx_index
        self.type: int = type_

    @classmethod
    def from_dict(cls, receipt_dict: dict):
        block_hash: EthHashString = EthHashString.from_hex(receipt_dict["blockHash"])
        block_number: int = int(receipt_dict["blockNumber"], 16)
        contract_addr: ChecksumAddress = ChecksumAddress(receipt_dict["contractAddress"])
        cumulative_gas_used: int = int(receipt_dict["cumulativeGasUsed"], 16)
        effective_gas_price: int = int(receipt_dict["cumulativeGasUsed"], 16)
        sender: ChecksumAddress = ChecksumAddress(receipt_dict["from"])
        gas_used: int = int(receipt_dict["gasUsed"], 16)
        logs: list = [Log(log) for log in receipt_dict["logs"]]
        logs_bloom: EthHexString = EthHexString.from_hex(receipt_dict["logsBloom"])
        status: bool = receipt_dict["status"] == "0x1"
        to_: ChecksumAddress = ChecksumAddress(receipt_dict["to"])
        tx_hash: EthHashString = EthHashString.from_hex(receipt_dict["transactionHash"])
        tx_index: int = int(receipt_dict["transactionIndex"], 16)
        type_: int = int(receipt_dict["type"], 16)
        return cls(block_hash, block_number, contract_addr, cumulative_gas_used, effective_gas_price, sender, gas_used, logs, logs_bloom, status, to_, tx_hash, tx_index, type_)

    def to_dict(self):
        ret_dict = dict()
        ret_dict["blockHash"] = self.block_hash.to_string_with_0x()
        ret_dict["blockNumber"] = hex(self.block_number)
        ret_dict["contractAddress"] = self.contract_addr.to_string_with_0x()
        ret_dict["cumulativeGasUsed"] = hex(self.cumulative_gas_used)
        ret_dict["effectiveGasPrice"] = hex(self.effective_gas_price)
        ret_dict["from"] = self.from_.to_string_with_0x()
        ret_dict["gasUsed"] = hex(self.gas_used)

        ret_dict["logsBloom"] = self.logs_bloom.to_string_with_0x()
        ret_dict["status"] = "0x1" if self.status else "0x0"
        ret_dict["to"] = self.to_.to_string_with_0x()
        ret_dict["transactionHash"] = self.tx_hash.to_string_with_0x()
        ret_dict["transactionIndex"] = hex(self._tx_index)
        ret_dict["type"] = hex(self.type)

    @property
    def logs(self) -> list:
        return self._logs

    @property
    def status(self) -> bool:
        return self._status

    @property
    def block_hash(self) -> EthHashString:
        return self._block_hash

    @property
    def contract_addr(self) -> ChecksumAddress:
        return self._contract_addr

    @property
    def tx_hash(self) -> EthHashString:
        return self._tx_hash

    def tx_idx(self) -> int:
        return self._tx_index


class ReceiptTest(TestCase):
    def setUp(self) -> None:
        with open("test_data/receipt_example.json", "r") as json_data:
            self.receipt_dict = json.load(json_data)

    def test_log_constructor(self):
        log_dict = self.receipt_dict["logs"][0]
        log_obj = Log.from_dict(log_dict)
        self.assertEqual(log_dict["address"], log_obj.emitter_addr.lower())
        self.assertEqual(log_dict["blockHash"], log_obj.block_hash)
        self.assertEqual(log_dict["blockNumber"], log_obj.block_number)
        self.assertEqual(log_dict["data"], log_obj.data)
        self.assertEqual(log_dict["logIndex"], log_obj.log_index)
        self.assertEqual(log_dict["removed"], log_obj.removed)
        for i, topic in enumerate(log_dict["topics"]):
            self.assertEqual(topic, log_obj.get_topic_by_index(i).lower())
        self.assertEqual(log_dict["transactionHash"], log_obj.transaction_hash)
        self.assertEqual(log_dict["transactionIndex"], log_obj.transaction_index)

    def test_block_constructor(self):
        tx = EthReceipt.from_dict(self.receipt_dict)
        self.assertEqual(tx.block_hash.to_string_with_0x(), self.receipt_dict["blockHash"])
