from unittest import TestCase
from ethereumpy.base.account import Account, PrivateKey
from ethereumpy.base.receipt import EthReceipt
from ethereumpy.base.sender_transaction import SenderTransaction
from ethereumpy.type.eth_address import ChecksumAddress
from ethereumpy.type.eth_hexstring import EthHexString, EthHashString
from ethereumpy.base.block import EthBlock
from ethereumpy.base.chain_transaction import ChainTransaction
import time
import requests
from typing import Union

# TODO aggregate configuration parameters
PROCESSED_SLEEP_TIME_SEC = 0.5
NOT_PROCESSED_SLEEP_TIME_SEC = 3
MAX_ITER_TIMES = 5

CHAIN_ID_OFFSET = 35
V_OFFSET = 27


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

    def get_transaction(self, indicator: Union[EthHashString, list], verbose: bool = False) -> ChainTransaction:
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
        return ChainTransaction.from_dict(resp["result"])

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
    def __init__(self, url: str, private_key: PrivateKey, chain_id: int = 1):
        super().__init__(url)
        self.account = Account.from_key(private_key)
        self.chain_id = chain_id

    @classmethod
    def from_private_key(cls, url: str, private_key: PrivateKey):
        return cls(url, private_key)

    @classmethod
    def from_private_key_int(cls, url: str, secret: int):
        private_key = PrivateKey.from_secret_int(secret)
        return cls(url, private_key)

    def to_eth_v(self, v_raw) -> int:
        return v_raw + V_OFFSET if self.chain_id is None else v_raw + CHAIN_ID_OFFSET + 2 * self.chain_id

    def sign_transaction(self, transaction: SenderTransaction) -> tuple:
        if not isinstance(transaction, SenderTransaction):
            raise Exception("invalid input type")

        tx_hash: EthHashString = transaction.hash()
        raw_v, r, s = self.account.recoverable_ecdsa_sign(tx_hash)
        v = self.to_eth_v(raw_v)
        transaction.set_sig(v, r, s)
        return v, r, s, transaction.encode_transaction()

    def send_transaction(self, signed_tx: hex) -> str:
        resp = self.send_request("eth_sendRawTransaction", [signed_tx])
        return resp["result"]

    def call_transaction(self, transaction: dict) -> str:
        resp = self.send_request("eth_call", [transaction])
        return resp["result"]


class TestTransaction(TestCase):
    def setUp(self) -> None:
        self.cli = ETHSender("dummy_url", PrivateKey.from_secret_int(0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318), 1)
        self.transaction = SenderTransaction.build(0, to="0xF0109fC8DF283027b6285cc889F5aA624EaC1F55",
                                                   value=1000000000, gas_limit=2000000, gas_price=234567897654321)
        self.expected_tx_hash = "0x6893a6ee8df79b0f5d64a180cd1ef35d030f3e296a5361cf04d02ce720d32ec5"

    def test_sign_transaction(self):
        tx_hash: EthHashString = self.transaction.hash()
        self.assertEqual(self.expected_tx_hash, self.transaction.hash().to_string_with_0x())

        v, r, s, encoded_tx = self.cli.sign_transaction(self.transaction)
        self.assertEqual(37, v)
        self.assertEqual(
            4487286261793418179817841024889747115779324305375823110249149479905075174044,
            r
        )
        self.assertEqual(
            30785525769477805655994251009256770582792548537338581640010273753578382951464,
            s
        )
        self.assertEqual(
            "0xf86a8086d55698372431831e848094f0109fc8df283027b6285cc889f5aa624eac1f55843b9aca008025a009ebb6ca057a0535d6186462bc0b465b561c94a295bdb0621fc19208ab149a9ca0440ffd775ce91a833ab410777204d5341a6f9fa91216a6f3ee2c051fea6a0428",
            encoded_tx.to_string_with_0x()
        )


