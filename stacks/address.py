from .hashing import sha256

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

"""
fn c32_encode(input_bytes: &[u8]) -> String {
    // ASCII characters are 8-bits and c32-encoding encodes 5-bits per
    // character, so the c32-encoded size should be ceil((ascii size) * 8 / 5)
    let size = input_bytes.len().saturating_mul(8).div_ceil(5);
    let mut result = Vec::with_capacity(size);
    let mut carry = 0;
    let mut carry_bits = 0;

    for current_value in input_bytes.iter().rev() {
        let low_bits_to_take = 5 - carry_bits;
        let low_bits = current_value & ((1 << low_bits_to_take) - 1);
        let c32_value = (low_bits << carry_bits) + carry;
        result.push(C32_CHARACTERS[c32_value as usize]);
        carry_bits = (8 + carry_bits) - 5;
        carry = current_value >> (8 - carry_bits);

        if carry_bits >= 5 {
            let c32_value = carry & ((1 << 5) - 1);
            result.push(C32_CHARACTERS[c32_value as usize]);
            carry_bits -= 5;
            carry >>= 5;
        }
    }

    if carry_bits > 0 {
        result.push(C32_CHARACTERS[carry as usize]);
    }

    // remove leading zeros from c32 encoding
    while let Some(v) = result.pop() {
        if v != C32_CHARACTERS[0] {
            result.push(v);
            break;
        }
    }

    // add leading zeros from input.
    for current_value in input_bytes.iter() {
        if *current_value == 0 {
            result.push(C32_CHARACTERS[0]);
        } else {
            break;
        }
    }

    let result: Vec<u8> = result.into_iter().rev().collect();
    String::from_utf8(result).unwrap()
}
"""


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
        result.append(ALPHABET[c32_value])
        carry_bits = (8 + carry_bits) - 5
        carry = current_value >> (8 - carry_bits)

        if carry_bits >= 5:
            c32_value = carry & ((1 << 5) - 1)
            result.append(ALPHABET[c32_value])
            carry_bits -= 5
            carry >>= 5

    if carry_bits > 0:
        result.append(ALPHABET[carry])

    # remove leading zero
    while True:
        value = result.pop()
        if value != ALPHABET[0]:
            result.append(value)
            break

    for current_value in data:
        if current_value == 0:
            result.append(0)
        else:
            break

    return "S" + "T" + "".join(reversed(result))
