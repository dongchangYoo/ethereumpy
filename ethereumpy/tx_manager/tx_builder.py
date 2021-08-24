from ethereumpy.type.eth_address import ChecksumAddress
from ethereumpy.type.eth_hexstring import EthHexString, EthHashString

DEFAULT_GAS_LIMIT = 5000000
DEFAULT_GAS_PRICE = 1000000000  # means 1 Giga wei


class TransactionBuilder:
    def __init__(self, to: ChecksumAddress = None, value: int = None, gas_limit: int = None, gas_price: int = None, nonce: int = None, data: EthHexString = None):
        self._to = to
        self._value = value
        self._gas_limit = gas_limit
        self._gas_price = gas_price
        self._nonce = nonce
        self._data = data

    def nonce(self, nonce: int):
        if not isinstance(nonce, int):
            raise Exception("Invalid type")
        self._nonce = nonce
        return self

    def to(self, to: ChecksumAddress):
        if not isinstance(to, ChecksumAddress):
            raise Exception("Invalid type")
        self._to = to
        return self

    def value(self, value: int):
        if not isinstance(value, int):
            raise Exception("Invalid type")
        self._value = value
        return self

    def gas_limit(self, gas_limit: int):
        if not isinstance(gas_limit, int):
            raise Exception("Invalid type")
        self._gas_limit = gas_limit
        return self

    def gas_price(self, gas_price: int):
        if not isinstance(gas_price, int):
            raise Exception("Invalid type")
        self._gas_price = gas_price
        return self

    def data(self, data: EthHexString):
        if not isinstance(data, EthHexString):
            raise Exception("Invalid type")
        self._data = data
        return self

    def export_as_dict(self) -> dict:
        return {
            "nonce": self._nonce,
            "to": self._to.to_string_with_0x(),
            "value": self._value,
            "gas": self._gas_limit,
            "gasPrice": self._gas_price,
            "data": self._data.to_string_with_0x()
        }

    def serialize(self) -> bytes:
        pass  # TODO implementation