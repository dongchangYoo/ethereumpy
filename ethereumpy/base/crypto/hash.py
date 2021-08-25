from typing import Union
from sha3 import keccak_256
from ethereumpy.type.eth_hexstring import EthHashString, EthHexString


def eth_hash(s: Union[EthHashString, EthHexString]) -> EthHashString:
    if not isinstance(s, EthHashString) and not isinstance(s, EthHexString):
        raise Exception("input must be bytes type")
    hash_ = keccak_256(s.to_bytes()).digest()
    return EthHashString.from_bytes(hash_)

