from typing import Union
from ethereumpy.type.eth_address import ChecksumAddress


def normalize_parameter(arg: Union[int, str, bytes, ChecksumAddress,  list]):
    if isinstance(arg, int):
        if arg < 0 or 2**256 < arg:
            raise Exception("Invalid int param")
        encoded_input = arg
    elif isinstance(arg, str):
        if not arg.startswith("0x"):
            arg = arg.encode().hex()
        encoded_input = arg
    elif isinstance(arg, bytes):
        encoded_input = arg.hex()
    elif isinstance(arg, ChecksumAddress):
        encoded_input = arg.to_string_with_0x()
    elif isinstance(arg, list):
        encoded_input = [normalize_parameter(item) for item in arg]
    else:
        raise Exception("Invalid Input type: {}".format(type(arg)))
    return encoded_input


def abi_encode(normalized_param: Union[str, int, list]):
    # function_sig = "0x2289b18c"
    padding = get_padded_data
    calc_len = calc_byte_len

    encoded = ""
    if isinstance(normalized_param, str):
        byte_len = calc_len(normalized_param)
        encoded += padding(byte_len)
        encoded += padding(normalized_param)
    elif isinstance(normalized_param, int):
        encoded = padding(normalized_param)
    elif isinstance(normalized_param, list):
        encoded_data = [abi_encode(param) for param in normalized_param]
        encoded += "".join(encoded_data)

        encoded_count = len(encoded_data)  # count
        offsets = [encoded_count * 32]
        for i in range(len(encoded_data) - 1):
            offset = offsets[-1] + calc_len(encoded_data[i])
            offsets.append(offset)

        encoded_offsets = [padding(item) for item in offsets]
        encoded = "".join([padding(encoded_count)] + encoded_offsets) + encoded
    else:
        raise Exception("Not supported type")
    return encoded


def get_padded_data(target: Union[str, int]):
    if isinstance(target, int):
        target_str = hex(target).replace("0x", "")
    elif isinstance(target, str):
        target_str = target
    else:
        raise Exception("Not supported input type")
    r = len(target_str) % 64
    pad = "0" * (64 - r)
    return target_str + pad if isinstance(target, str) else pad + target_str


def calc_byte_len(target: str) -> int:
    len_ = len(target.encode())
    q = len_ // 2
    r = len_ % 2
    return q if r == 0 else q + 1


# def test_abi_encode):
#     inputs = [[[1, 2], [3]], ["one", "two", "three"]]
#     # inputs = ["one", "two", "three"]
#     normalized = normalize_parameter(inputs)
#     print(normalized)
#     result = abi_encode(normalized)
#
#     while True:
#         print(result[:64])
#         result = result[64:]…
#         if len(result) == 0:
#             break
