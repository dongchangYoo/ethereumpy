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


class EthRpcClient(RPCRequest):
    def __init__(self, url_with_access_key: str):
        super().__init__(url_with_access_key)

    # def query(self, method_name: str, params: list) -> dict:
    #     return self.send_request(method_name, params)

    def get_chain_id(self) -> int:
        resp = self.send_request("net_version", [])
        return int(resp["result"], 16)

    def get_nonce(self, addr: ChecksumAddress) -> int:
        resp = self.send_request("eth_getTransactionCount", [addr.to_string_with_0x(), "latest"])
        return int(resp["result"], 16)

    def get_balance(self, addr_obj: ChecksumAddress) -> int:
        addr = addr_obj.to_string_with_0x()
        resp = self.send_request("eth_getBalance", [addr, "latest"])
        return int(resp["result"], 16)

    def get_latest_block_number(self) -> int:
        resp = self.send_request("eth_blockNumber", list())
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
        resp = self.send_request(method, params)
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

        resp = self.send_request(method, params)
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


class ETHSender(EthRpcClient):
    def __init__(self, url: str, private_key: PrivateKey):
        super().__init__(url)
        self.account = Account.from_key(private_key)
        self.__chain_id = self.get_chain_id()

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
        return v, r, s, transaction.serialize()

    # TODO testing!!
    def send_transaction(self, signed_tx: EthHexString) -> str:
        resp = self.send_request("eth_sendRawTransaction", [signed_tx.to_string_with_0x()])
        return resp["result"]

    # TODO not implemented
    def call_transaction(self, transaction: dict) -> str:
        resp = self.send_request("eth_call", [transaction])
        return resp["result"]

    @property
    def chain_id(self):
        return self.__chain_id


class TestTransaction(TestCase):
    def setUp(self) -> None:
        private_key = PrivateKey.from_secret_int(0x3ae1050e80df0eb730e554287edcd038ccc950c83b26eed19f3b318078dcb41c)
        self.cli = ETHSender("http://127.0.0.1:8545", private_key)
        chain_id = self.cli.chain_id
        self.transaction = SenderTransaction.set_metadata(0, to="0xF0109fC8DF283027b6285cc889F5aA624EaC1F55",
                                                          value=1000000000, gas_limit=2000000, gas_price=234567897654321, chain_id=chain_id)

    def test_serialize_transaction(self):
        # check transaction hash
        expected_tx_hash = "0xeee57600267b2d90650a79e6fb8f95e247288dfbd606f05e8b967798e7487a51"
        self.assertEqual(expected_tx_hash, self.transaction.hash().to_string_with_0x())

    def test_sign_transaction(self):
        v, r, s, encoded_tx = self.cli.sign_transaction(self.transaction)

        chain_id = self.cli.chain_id
        self.assertTrue(2 * chain_id == v or 1 + 2 * chain_id)
        self.assertEqual(
            42193091172634067553896552780179880111632151928716446702506423493552247041490,
            r
        )
        self.assertEqual(
            52476445989149348526628540910471646803993322977790296305050201031126519886925,
            s
        )
        self.assertEqual(
            "0xf8718086d55698372431831e848094f0109fc8df283027b6285cc889f5aa624eac1f55843b9aca00808702c53286a4d0eba05d48717cf0c43bba625f749ce44e4dc64dd5a976d518e1d92891d63b0ec26dd2a074049daa4aac36d708a466ee1fc324f7af80fb4002d45299b11d216bdb2bb44d",
            encoded_tx.to_string_with_0x()
        )

    def test_send_transaction(self):
        self.transaction