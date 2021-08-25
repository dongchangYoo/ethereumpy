from ethereumpy.base.crypto.field_element import FieldElement
from ethereumpy.base.crypto.ecc_point import ECCPoint
from ethereumpy.base.crypto.hash import eth_hash
from ethereumpy.type.eth_hexstring import EthHexString


class S256Field(FieldElement):
    P = 2**256 - 2**32 - 977

    def __init__(self, num, prime=None):
        super().__init__(num=num, prime=self.P)

    def __repr__(self):
        return '{:x}'.format(self.num).zfill(64)

    def sqrt(self):
        return self**((self.P + 1) // 4)


class S256Point(ECCPoint):
    A = 0
    B = 7
    N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

    def __init__(self, x, y, a=None, b=None):
        a, b = S256Field(self.A), S256Field(self.B)
        if type(x) == int:
            super().__init__(x=S256Field(x), y=S256Field(y), a=a, b=b)
        else:
            super().__init__(x=x, y=y, a=a, b=b)

    def __repr__(self):
        if self.x is None:
            return 'S256Point(infinity)'
        else:
            return 'S256Point({}, {})'.format(self.x, self.y)

    def __rmul__(self, coefficient):
        coef = coefficient % self.N
        return super().__rmul__(coef)

    @classmethod
    def from_pubkey_sec(cls, sec_bytes: bytes):
        """ returns a Point object from a SEC binary (not hex) """
        if not (len(sec_bytes) == 65 or len(sec_bytes) == 33):
            raise Exception("Invalid input len")

        prefix = sec_bytes[0]
        body = sec_bytes[1:]
        if len(body) == 64 and prefix == 4:
            pass
        elif len(body) == 32 and prefix == 2 or prefix == 3:
            pass
        else:
            raise Exception("Invalid encoded input: {}".format(sec_bytes.hex()))

        if prefix == 4:
            x = int.from_bytes(body[:32], 'big')
            y = int.from_bytes(sec_bytes[32:64], 'big')
            return S256Point(x=x, y=y)

        x = S256Field(int.from_bytes(body, 'big'))
        alpha = x**3 + S256Field(cls.B)
        beta = alpha.sqrt()
        if beta.num % 2 == 0:
            even_beta = beta
            odd_beta = S256Field(S256Field.P - beta.num)
        else:
            even_beta = S256Field(S256Field.P - beta.num)
            odd_beta = beta
        if prefix == 2:
            return cls(x, even_beta)
        else:
            return cls(x, odd_beta)

    def pubkey_sec(self, compressed=True):
        """ returns the binary version of the SEC format """
        if compressed:
            if self.y.num % 2 == 0:
                return b'\x02' + self.x.num.to_bytes(32, 'big')
            else:
                return b'\x03' + self.x.num.to_bytes(32, 'big')
        else:
            return b'\x04' + self.x.num.to_bytes(32, 'big') + self.y.num.to_bytes(32, 'big')

    @property
    def address(self) -> str:
        """ Returns the address string """
        # note 1: need to set compress flag False
        # note 2: pre-image must not include prefix of sec encoding
        sec_bytes = EthHexString.from_bytes(self.pubkey_sec(False)[1:])
        pub_key_hash: bytes = eth_hash(sec_bytes).to_bytes()

        return pub_key_hash[-20:].hex()

    @classmethod
    def get_generator(cls):
        return cls(
            x=0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
            y=0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)

    @classmethod
    def get_order(cls):
        return cls.N


if __name__ == "__main__":
    secret = 0xf4a2b939592564feb35ab10a8e04f6f2fe0943579fb3c9c33505298978b74893
    pubkey = secret * S256Point.get_generator()
    address1 = pubkey.address

