from backend.eth_module.base.eth_string import AddressString, EthString

DEFAULT_GAS_LIMIT = 5000000
DEFAULT_GAS_PRICE = 1000000000  # means 1 Giga wei


class TransactionBuilder:
    def __init__(self):
        self._to = None
        self._value = None
        self._gas_limit = DEFAULT_GAS_LIMIT
        self._gas_price = DEFAULT_GAS_PRICE
        self._nonce = None
        self._data = None

    def nonce(self, nonce: int):
        self._nonce = nonce
        return self

    def to(self, to: AddressString):
        self._to = to.to_string_with_0x()
        return self

    def value(self, value: int):
        self._value = value
        return self

    def gas_limit(self, gas_limit: int):
        self._gas_limit = gas_limit
        return self

    def gas_price(self, gas_price: int):
        self._gas_price = gas_price
        return self

    def data(self, data: EthString):
        self._data = data.to_string_with_0x()
        return self

    def extract_transaction(self) -> dict:
        return {
            "nonce": self._nonce,
            "to": self._to,
            "value": self._value,
            "gas": self._gas_limit,
            "gasPrice": self._gas_price,
            "data": self._data
        }
