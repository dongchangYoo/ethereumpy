from backend.eth_module.base.eth_string import AddressString, EthString, HashString


class Log:
    def __init__(self, log: dict):
        self.addr: AddressString = AddressString(log["address"])
        self.data: EthString = EthString(log["data"], len(log["data"]))
        self.log_index: int = int(log["logIndex"], 16)
        self.topic: HashString = HashString(log["topics"][0])   # store only first topic


class EthReceipt:
    def __init__(self, receipt: dict):
        self._block_hash: HashString = HashString(receipt["blockHash"])
        self.block_number: int = int(receipt["blockNumber"], 16)
        self._contract_addr: AddressString = AddressString(receipt["contractAddress"])
        self.cumulative_gas_used: int = int(receipt["cumulativeGasUsed"], 16)
        self.from_: AddressString = AddressString(receipt["from"])
        self.gas_used: int = int(receipt["gasUsed"], 16)
        self._logs: list = [Log(log) for log in receipt["logs"]]
        self.logs_bloom: EthString = EthString(receipt["logsBloom"], len(receipt["logsBloom"]))
        self._status: bool = True if receipt["status"] == "0x1" else False
        self.to_: AddressString = AddressString(receipt["to"])
        self._tx_hash: HashString = HashString(receipt["transactionHash"])
        self._tx_index: int = int(receipt["transactionIndex"], 16)

    @property
    def logs(self) -> list:
        return self._logs

    @property
    def status(self) -> bool:
        return self._status

    @property
    def block_hash(self) -> HashString:
        return self._block_hash

    @property
    def contract_addr(self) -> AddressString:
        return self._contract_addr

    @property
    def tx_hash(self) -> HashString:
        return self._tx_hash

    def tx_idx(self) -> int:
        return self._tx_index
