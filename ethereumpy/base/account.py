from unittest import TestCase

from ethereumpy.base.crypto.secp256k1 import G
from ethereumpy.type.eth_address import ChecksumAddress


class PrivateKey:
    def __init__(self, secret: int):
        self.secret = secret

    @classmethod
    def from_int(cls, secret: int):
        return cls(secret)

    @classmethod
    def from_bytes(cls, secret: bytes):
        return cls(int.from_bytes(secret, "big"))  # TODO check

    @property
    def address(self) -> ChecksumAddress:
        pubkey = self.secret * G
        return ChecksumAddress(pubkey.address)


class Account:
    def __init__(self, address: ChecksumAddress = None, private_key: PrivateKey = None):
        self.__private_key = private_key
        self.__address = address

    @classmethod
    def from_address(cls, address: ChecksumAddress):
        return cls(address, None)

    @classmethod
    def from_key(cls, private_key: PrivateKey):
        return cls(None, private_key)

    @classmethod
    def from_key_int(cls, private_key: int):
        priv = PrivateKey.from_int(private_key)
        return cls(None, priv)

    @property
    def address(self) -> ChecksumAddress:
        if self.__address is not None:
            return self.__address

        return self.__private_key.address


class AccountTest(TestCase):
    def test_account(self):
        acc = Account.from_key_int(0xf4a2b939592564feb35ab10a8e04f6f2fe0943579fb3c9c33505298978b74893)
        address = acc.address
        self.assertEqual("0xd5e099c71b797516c10ed0f0d895f429c2781142", address.to_string_with_0x().lower())
