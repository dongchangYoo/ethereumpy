import json
from typing import Union
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

    def to_dict(self):
        ret_dict = dict()
        ret_dict["address"] = self._emitter.to_string_with_0x().lower()
        ret_dict["blockHash"] =  self._block_hash.to_string_with_0x()
        ret_dict["blockNumber"] = hex(self._block_number)
        ret_dict["data"] = self._data.to_string_with_0x()
        ret_dict["logIndex"] = hex(self._log_index)
        ret_dict["removed"] = self.removed
        ret_dict["topics"] = [topic.to_string_with_0x() for topic in self._topics]
        ret_dict["transactionHash"] = self._transaction_hash.to_string_with_0x()
        ret_dict["transactionIndex"] = hex(self._transaction_index)
        return ret_dict

    def serialize(self) -> bytes:
        pass  # TODO implementation

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
                 cumulative_gas_used: int, effective_gas_price: int, _from: ChecksumAddress, gas_used: int, logs: list,
                 logs_bloom: EthHexString, status: bool, _to: ChecksumAddress, tx_hash: EthHashString, tx_index: int,
                 _type: int):
        self._block_hash: EthHashString = block_hash
        self._block_number: int = block_number
        self._contract_addr: ChecksumAddress = contract_addr
        self._cumulative_gas_used: int = cumulative_gas_used
        self._effective_gas_price: int = effective_gas_price
        self._from: ChecksumAddress = _from
        self._gas_used: int = gas_used
        self._logs: list = logs
        self._logs_bloom: EthHexString = logs_bloom
        self._status: bool = status
        self._to: ChecksumAddress = _to
        self._tx_hash: EthHashString = tx_hash
        self._tx_index: int = tx_index
        self._type: int = _type

    @classmethod
    def from_dict(cls, receipt_dict: dict):
        block_hash: EthHashString = EthHashString.from_hex(receipt_dict["blockHash"])
        block_number: int = int(receipt_dict["blockNumber"], 16)
        contract_addr: ChecksumAddress = ChecksumAddress(receipt_dict["contractAddress"])
        cumulative_gas_used: int = int(receipt_dict["cumulativeGasUsed"], 16)
        effective_gas_price: int = int(receipt_dict["effectiveGasPrice"], 16)
        sender: ChecksumAddress = ChecksumAddress(receipt_dict["from"])
        gas_used: int = int(receipt_dict["gasUsed"], 16)
        logs: list = [Log.from_dict(log) for log in receipt_dict["logs"]]
        logs_bloom: EthHexString = EthHexString.from_hex(receipt_dict["logsBloom"])
        status: bool = receipt_dict["status"] == "0x1"
        _to: ChecksumAddress = ChecksumAddress(receipt_dict["to"])
        tx_hash: EthHashString = EthHashString.from_hex(receipt_dict["transactionHash"])
        tx_index: int = int(receipt_dict["transactionIndex"], 16)
        _type: int = int(receipt_dict["type"], 16)
        return cls(block_hash, block_number, contract_addr, cumulative_gas_used, effective_gas_price,
                   sender, gas_used, logs, logs_bloom, status, _to, tx_hash, tx_index, _type)

    def to_dict(self) -> dict:
        ret_dict = dict()
        ret_dict["blockHash"] = self._block_hash.to_string_with_0x()
        ret_dict["blockNumber"] = hex(self._block_number)
        ret_dict["contractAddress"] = self._contract_addr.to_string_with_0x()
        ret_dict["cumulativeGasUsed"] = hex(self._cumulative_gas_used)
        ret_dict["effectiveGasPrice"] = hex(self._effective_gas_price)
        ret_dict["from"] = self._from.to_string_with_0x().lower()
        ret_dict["gasUsed"] = hex(self._gas_used)
        ret_dict["logs"] = [log.to_dict() for log in self._logs]
        ret_dict["logsBloom"] = self._logs_bloom.to_string_with_0x()
        ret_dict["status"] = "0x1" if self._status else "0x0"
        ret_dict["to"] = self._to.to_string_with_0x().lower()
        ret_dict["transactionHash"] = self._tx_hash.to_string_with_0x()
        ret_dict["transactionIndex"] = hex(self._tx_index)
        ret_dict["type"] = hex(self._type)
        return ret_dict

    @property
    def block_hash(self) -> str:
        return self._block_hash.to_string_with_0x()

    @property
    def block_number(self) -> str:
        return hex(self._block_number)

    @property
    def contract_addr(self) -> Union[str, None]:
        if self._contract_addr:
            return None
        return self._contract_addr.to_string_with_0x()

    @property
    def cumulative_gas_used(self) -> str:
        return hex(self._cumulative_gas_used)

    @property
    def effective_gas_price(self) -> str:
        return hex(self._effective_gas_price)

    @property
    def sender(self) -> str:
        # TODO it may mean msg.sender?
        return self._from.to_string_with_0x()

    @property
    def gas_used(self) -> str:
        return hex(self._gas_used)

    @property
    def logs(self) -> list:
        return self._logs

    def get_log_by_index(self, index: int) -> Log:
        return self._logs[index]

    @property
    def logs_bloom(self) -> str:
        return self._logs_bloom.to_string_with_0x()

    @property
    def status(self) -> str:
        return "0x1" if self._status else "0x0"

    @property
    def to(self) -> str:
        return self._to.to_string_with_0x()

    @property
    def transaction_hash(self) -> str:
        return self._tx_hash.to_string_with_0x()

    @property
    def transaction_index(self) -> str:
        return hex(self._tx_index)

    @property
    def transaction_type(self) -> str:
        return hex(self._type)


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

    def test_constructor(self):
        receipt_obj = EthReceipt.from_dict(self.receipt_dict)
        self.assertEqual(self.receipt_dict["blockHash"], receipt_obj.block_hash)
        self.assertEqual(self.receipt_dict["blockNumber"], receipt_obj.block_number)

        actual_contract_addr = receipt_obj.contract_addr.lower() if receipt_obj.contract_addr else None
        self.assertEqual(self.receipt_dict["contractAddress"], actual_contract_addr)
        self.assertEqual(self.receipt_dict["cumulativeGasUsed"], receipt_obj.cumulative_gas_used)
        self.assertEqual(self.receipt_dict["effectiveGasPrice"], receipt_obj.effective_gas_price)
        self.assertEqual(self.receipt_dict["from"], receipt_obj.sender.lower())
        self.assertEqual(self.receipt_dict["gasUsed"], receipt_obj.gas_used)
        self.assertEqual(self.receipt_dict["logsBloom"], receipt_obj.logs_bloom)
        self.assertEqual(self.receipt_dict["to"], receipt_obj.to.lower())
        self.assertEqual(self.receipt_dict["transactionHash"], receipt_obj.transaction_hash)
        self.assertEqual(self.receipt_dict["transactionIndex"], receipt_obj.transaction_index)
        self.assertEqual(self.receipt_dict["type"], receipt_obj.transaction_type)

    def test_exporter(self):
        receipt_obj = EthReceipt.from_dict(self.receipt_dict)
        self.assertEqual(self.receipt_dict, receipt_obj.to_dict())
