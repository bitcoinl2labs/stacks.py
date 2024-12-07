from .hashing import sha256

C32_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def c32_encode(version, data):
    checksum = sha256(sha256(bytes((version,)) + data).digest()).digest()[0:4]

    data += checksum

    carry = 0
    carry_bits = 0

    result = []

    for current_value in reversed(data):
        low_bits_to_take = 5 - carry_bits
        low_bits = current_value & ((1 << low_bits_to_take) - 1)
        c32_value = (low_bits << carry_bits) + carry
        result.append(C32_ALPHABET[c32_value])
        carry_bits = (8 + carry_bits) - 5
        carry = current_value >> (8 - carry_bits)

        if carry_bits >= 5:
            c32_value = carry & ((1 << 5) - 1)
            result.append(C32_ALPHABET[c32_value])
            carry_bits -= 5
            carry >>= 5

    if carry_bits > 0:
        result.append(C32_ALPHABET[carry])

    # remove leading zero
    while True:
        value = result.pop()
        if value != C32_ALPHABET[0]:
            result.append(value)
            break

    for current_value in data:
        if current_value == 0:
            result.append(0)
        else:
            break

    return "S" + "T" + "".join(reversed(result))
