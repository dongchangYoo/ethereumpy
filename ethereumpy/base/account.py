from random import SystemRandom
from unittest import TestCase

from ethereumpy.base.crypto.hash import eth_hash
from ethereumpy.base.crypto.secp256k1 import S256Field, S256Point
from ethereumpy.type.eth_address import ChecksumAddress
import hashlib
import hmac
from typing import (Any, Callable, Optional, Tuple)  # noqa: F401

from ethereumpy.type.eth_hexstring import EthHashString, EthHexString


class PrivateKey:
    def __init__(self, secret: int, rng=SystemRandom()):
        self.__secret: int = secret
        self._rng: SystemRandom = rng

    @classmethod
    def from_secret_int(cls, secret: int):
        return cls(secret)

    @classmethod
    def from_secret_bytes(cls, secret: bytes):
        return cls(int.from_bytes(secret, "big"))  # TODO check

    @classmethod
    def by_random_int(cls):
        rng = SystemRandom()
        secret = rng.randint(1, S256Field.P + 1)
        return cls(secret, rng)

    @property
    def pub_key(self) -> S256Point:
        return self.__secret * S256Point.get_generator()

    @property
    def address(self) -> ChecksumAddress:
        pubkey = self.__secret * S256Point.get_generator()
        return ChecksumAddress(pubkey.address)

    def get_random(self) -> int:
        # 0 < rand < P
        return self._rng.randint(1, S256Field.P + 1)

    def sign(self, msg_hash: EthHashString) -> tuple:
        z: int = int.from_bytes(msg_hash.to_bytes(), byteorder="big")
        g = S256Point.get_generator()

        while True:
            k: int = self.get_random()
            r = (k * g).x.num
            if r != 0:
                break

        order = S256Point.get_order()
        k_inv = pow(k, order - 2, order)
        s: int = k_inv * (z + r * self.__secret) % order
        return r, s

    def recoverable_sign(self, msg_hash: EthHashString) -> tuple:
        z: int = int.from_bytes(msg_hash.to_bytes(), byteorder="big")
        g = S256Point.get_generator()

        while True:
            k: int = self.deterministic_generate_k(msg_hash)
            R = (k * g)
            r = R.x.num
            if r != 0:
                break

        order = S256Point.get_order()
        k_inv = pow(k, order - 2, order)
        s: int = k_inv * (z + r * self.__secret) % order
        v = 1 if R.y.num % 2 else 0
        return v, r, s

    def deterministic_generate_k(self, msg_hash: EthHashString) -> int:
        private_key_bytes = self.__secret.to_bytes(32, byteorder="big")
        digest_fn = hashlib.sha256

        v_0 = b'\x01' * 32
        k_0 = b'\x00' * 32

        k_1 = hmac.new(k_0, v_0 + b'\x00' + private_key_bytes + msg_hash.to_bytes(), digest_fn).digest()
        v_1 = hmac.new(k_1, v_0, digest_fn).digest()
        k_2 = hmac.new(k_1, v_1 + b'\x01' + private_key_bytes + msg_hash.to_bytes(), digest_fn).digest()
        v_2 = hmac.new(k_2, v_1, digest_fn).digest()

        kb = hmac.new(k_2, v_2, digest_fn).digest()
        return int.from_bytes(kb, byteorder="big")


class Account:
    def __init__(self, private_key: PrivateKey = None, pub_key: S256Point = None, address: ChecksumAddress = None):
        self.__private_key: PrivateKey = private_key
        self.__pub_key: S256Point = pub_key
        self.__address: ChecksumAddress = address

    @classmethod
    def from_key(cls, private_key: PrivateKey):
        return cls(private_key=private_key)

    @classmethod
    def from_key_int(cls, private_key: int):
        priv = PrivateKey.from_secret_int(private_key)
        return cls(private_key=priv)

    @classmethod
    def from_pub_key(cls, pub_key: S256Point):
        return cls(pub_key=pub_key)

    @classmethod
    def from_address(cls, address: ChecksumAddress):
        return cls(address= address)

    @property
    def pub_key(self) -> S256Point:
        if self.__pub_key is not None:
            return self.__pub_key
        return self.__private_key.pub_key

    @property
    def address(self) -> ChecksumAddress:
        if self.__address is not None:
            return self.__address
        return self.__private_key.address

    def ecdsa_sign(self, msg_hash: EthHashString) -> tuple:
        return self.__private_key.sign(msg_hash)  # r, s

    def recoverable_ecdsa_sign(self, msg_hash: EthHashString) -> tuple:
        return self.__private_key.recoverable_sign(msg_hash)  # v, r, s

    @classmethod
    def verify(cls, msg_hash: EthHashString, r: int, s: int, pub_key: S256Point):
        # pubkey validation
        order = S256Point.get_order()
        criteria = order * pub_key
        if not criteria.is_infinity():
            raise Exception("Invalid Pubkey: {}".format(pub_key))

        if r > order - 1 or s > order - 1:
            raise Exception("Invalid sig: r({}), s({})".format(r, s))

        z = int.from_bytes(msg_hash.to_bytes(), byteorder="big")
        g = S256Point.get_generator()

        s_inv = pow(s, order - 2, order)
        u1 = z * s_inv % order
        u2 = r * s_inv % order

        result = u1 * g + u2 * pub_key
        if result.is_infinity():
            return False

        return True if result.x.num == r else False

    @staticmethod
    def recover_verify(pre: bytes, v: int, r: int, s: int, signer_addr: ChecksumAddress):
        pass  # TODO implementation


class AccountTest(TestCase):
    def setUp(self) -> None:
        private_key = PrivateKey.by_random_int()
        self.account = Account.from_key(private_key)

    def test_account(self):
        private_key = PrivateKey.from_secret_int(0xf4a2b939592564feb35ab10a8e04f6f2fe0943579fb3c9c33505298978b74893)
        address = Account.from_key(private_key).address
        self.assertEqual("0xd5e099c71b797516c10ed0f0d895f429c2781142", address.to_string_with_0x().lower())

    def test_ecdsa(self):
        msg_bytes = EthHexString.from_bytes("testtesttest".encode())
        r, s = self.account.ecdsa_sign(msg_bytes)
        result = Account.verify(msg_bytes, r, s, self.account.pub_key)
        self.assertTrue(result)
