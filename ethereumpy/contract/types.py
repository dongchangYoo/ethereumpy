

class UnsignedIntType:
    sol_types = ["uint" + str(m) for m in range(1, 33)]
    compile_type = "uint256"


class SignedIntType:
    sol_types = ["int" + str(m) for m in range(1, 33)]
    compile_type = "int256"


class AddressType:
    sol_types = ["address"]
    compile_type = "address"  # equal to uint160


class BoolType:
    sol_types = ["bool"]
    compile_type = "bool"  # equal to uint8, has only value: 0 or 1


# TODO impl: fixed point variable


class BytesType:
    sol_types = ["bytes" + str(m) for m in range(1, 33)]
    compile_type = "bytes32"


class FunctionType:
    sol_types = ["function"]  # address + function selector
    compile_type = "function"  # equal to bytes24


# TODO imple
class FixedSizeArray:
    pass