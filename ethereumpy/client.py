import web3

from ethereumpy.base.receipt import EthReceipt
from ethereumpy.type.eth_address import ChecksumAddress
from ethereumpy.type.eth_hexstring import EthHexString, EthHashString
from ethereumpy.base.block import EthBlock
from ethereumpy.base.transaction import EthTransaction
import time
import requests
from typing import Union

# TODO aggregate configuration parameters
PROCESSED_SLEEP_TIME_SEC = 0.5
NOT_PROCESSED_SLEEP_TIME_SEC = 3
MAX_ITER_TIMES = 5


class RPCRequest:
    def __init__(self, url):
        self.url = url
        self.session = requests.session()

    def send_request(self, method: str, params: list) -> dict:
        body = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        }
        headers = {'Content-type': 'application/json'}
        response = self.session.post(self.url, json=body, headers=headers)
        return response.json()


class EthCaller(RPCRequest):
    def __init__(self, url_with_access_key: str):
        super().__init__(url_with_access_key)

    def query(self, method_name: str, params: list) -> dict:
        return self.send_request(method_name, params)

    def get_nonce(self, addr: ChecksumAddress) -> int:
        resp = self.query("eth_getTransactionCount", [addr.to_string_with_0x(), "latest"])
        return int(resp["result"], 16)

    def get_balance(self, addr_obj: ChecksumAddress) -> int:
        addr = addr_obj.to_string_with_0x()
        resp = self.query("eth_getBalance", [addr, "latest"])
        return int(resp["result"], 16)

    def get_latest_block_number(self) -> int:
        resp = self.query("eth_blockNumber", list())
        return int(resp["result"], 16)

    def get_block(self, indicator: Union[EthHashString, int] = None, verbose: bool = False) -> EthBlock:
        # True -> return block including full-spec transaction
        if indicator is None:
            method: str = "eth_getBlockByNumber"
            params: list = ["latest", verbose]
        elif isinstance(indicator, int):
            method: str = "eth_getBlockByNumber"
            params: list = [hex(indicator), verbose]
        elif isinstance(indicator, EthHashString):
            method: str = "eth_getBlockByHash"
            params: list = [indicator.to_string_with_0x(), verbose]
        else:
            raise Exception("Not allowed input format")
        resp = self.query(method, params)
        return EthBlock.from_dict(resp["result"])

    def get_transaction(self, indicator: Union[EthHashString, list], verbose: bool = False) -> EthTransaction:
        if isinstance(indicator, EthHashString):
            method: str = "eth_getTransactionByHash"
            params: list = [indicator.to_string_with_0x(), verbose]
        elif isinstance(indicator, list):
            if len(indicator) != 2:
                raise Exception("Invalid Parameter")
            if isinstance(indicator[0], EthHashString) and isinstance(indicator[1], int):
                method: str = "eth_getTransactionByBlockHashAndIndex"
                params: list = [indicator[0].to_string_with_0x(), hex(indicator[1]), verbose]
            elif isinstance(indicator[0], int) and isinstance(indicator[1], int):
                method: str = "eth_getTransactionByBlockNumberAndIndex"
                params: list = [indicator[0], hex(indicator[1]), verbose]
            else:
                raise Exception("Invalid Parameter")
        else:
            raise Exception("Invalid Parameter")

        resp = self.query(method, params)
        return EthTransaction.from_dict(resp["result"])

    def get_transaction_receipt(self, tx_hash: EthHashString, processed: bool = True) -> Union[EthReceipt, None]:
        sleep_time = PROCESSED_SLEEP_TIME_SEC if processed else NOT_PROCESSED_SLEEP_TIME_SEC
        max_try = MAX_ITER_TIMES

        for i in range(max_try):
            resp = self.send_request('eth_getTransactionReceipt', [tx_hash.to_string_with_0x()])
            if resp["result"] is not None:
                return EthReceipt.from_dict(resp["result"])
            time.sleep(sleep_time)
        return None


class ETHSender(EthCaller):
    def __init__(self, url: str, secret: str):
        super().__init__(url)

        self.web3_lib = web3.Web3().eth
        account = self.web3_lib.account.from_key(secret)
        self.addr = ChecksumAddress(account.address)
        self.key = account.privateKey

    def build_transaction(self, nonce: int, to: ChecksumAddress, value: int = None, data: EthHexString = None,
                          gas_limit: int = None, gas_price: int = None) -> dict:
        if not isinstance(to, ChecksumAddress):
            raise Exception("Parameter type error.".format(type(to)))

        builder = TransactionBuilder().nonce(nonce)
        if not to.is_empty():
            builder.to(to)
        if value is not None:
            builder.value(value)
        if gas_limit is not None:
            builder.gas_limit(gas_limit)
        if gas_price is not None:
            builder.gas_limit(gas_limit)
        if not data.is_empty():
            builder.data(data)
        return builder.extract_transaction()

    def sign_transaction(self, transaction: dict) -> str:
        signed_transaction = self.web3_lib.account.signTransaction(transaction, self.key)
        return signed_transaction.rawTransaction.hex()

    def send_transaction(self, signed_tx: hex) -> str:
        resp = self.send_request("eth_sendRawTransaction", [signed_tx])
        return resp["result"]

    def call_transaction(self, transaction: dict) -> str:
        resp = self.send_request("eth_call", [transaction])
        return resp["result"]
