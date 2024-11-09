import struct
import hashlib


def double_sha256(data):
    """Calculate double SHA-256 hash."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


# Crockford's Base32 alphabet
CROCKFORD_BASE32_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def crockford_base32_encode(data):
    hex_input = data.hex().lower()
    print(hex_input)
    hex = "0123456789abcdef"
    output = []
    carry = 0
    for i in range(len(hex_input) - 1, 0, -1):
        if carry < 4:
            current_code = hex.index(hex_input[i]) >> carry
            next_code = 0
            if i != 0:
                next_code = hex.index(hex_input[i - 1])
            next_bits = 1 + carry
            next_low_bits = next_code % (1 << next_bits) << (5 - next_bits)
            current_c32_digit = CROCKFORD_BASE32_ALPHABET[current_code + next_low_bits]
            carry = next_bits
            output.insert(0, current_c32_digit)
        else:
            carry = 0

    print(output)
    return ""
    """Encode data into Crockford's Base32."""
    num = int.from_bytes(data, byteorder="big")
    print(num)
    result = []
    while num > 0:
        num, remainder = divmod(num, 32)
        result.append(CROCKFORD_BASE32_ALPHABET[remainder])
    print(len(result))
    return "".join(reversed(result)).zfill(39)


class ClarityHexCode:

    def __init__(self, data):
        self.data = b"".join(
            [bytes([int(data[i : i + 2], 16)]) for i in range(0, len(data), 2)]
        )

        self.size = len(self.data)

        self.types = {
            0x00: self.parse_int,
            0x01: self.parse_uint,
            0x03: self.parse_true,
            0x04: self.parse_false,
            0x05: self.parse_standard_principal,
            0x06: self.parse_contract_principal,
            0x0C: self.parse_tuple,
            0x0D: self.parse_string_ascii,
        }
        self.pos = 0

        self.output = ""

        while self.pos < self.size:
            if not self.next_chunk():
                break

        print(self.output)

    def next_chunk(self):
        current_type = self.data[self.pos]
        self.pos += 1
        return self.types[current_type]()

    def parse_standard_principal(self):
        version = self.data[self.pos]
        version_and_address = self.data[self.pos : self.pos + 21]
        version_and_address_and_checksum = self.data[self.pos + 1: self.pos + 21] + (
            double_sha256(version_and_address)[:4]
        )

        self.output += (
            "'S" + "T|" + crockford_base32_encode(version_and_address_and_checksum)
        )  # encoder.finalize()
        self.pos += 21
        return True

    def parse_contract_principal(self):
        version = self.data[self.pos]
        self.pos += 1
        self.output += str(version)
        self.pos += 20
        clarity_name_size = self.data[self.pos]
        self.pos += 1
        self.output += (
            "." + "???"
        )  # self.data[self.pos : self.pos + clarity_name_size].decode(
        # "ascii"
        # )
        self.pos += clarity_name_size
        return True

    def parse_string_ascii(self):
        (number_of_chars,) = struct.unpack(">I", self.data[self.pos : self.pos + 4])
        self.pos += 4
        self.output += (
            '"' + self.data[self.pos : self.pos + number_of_chars].decode("ascii") + '"'
        )
        self.pos += number_of_chars
        return True

    def parse_int(self):
        def two_complement(value):
            if (value & (1 << (128 - 1))) != 0:
                value = value - (1 << 128)
            return value

        (high, low) = struct.unpack(">QQ", self.data[self.pos : self.pos + (8 * 2)])
        self.pos += 8 * 2
        value = two_complement(high << 64 | low)
        self.output += str(value)
        return True

    def parse_uint(self):
        (high, low) = struct.unpack(">QQ", self.data[self.pos : self.pos + (8 * 2)])
        self.pos += 8 * 2
        value = high << 64 | low
        self.output += "u" + str(value)
        return True

    def parse_true(self):
        self.output += "true"
        return True

    def parse_false(self):
        self.output += "false"
        return True

    def parse_tuple(self):
        (number_of_elements,) = struct.unpack(">I", self.data[self.pos : self.pos + 4])
        self.pos += 4
        self.output += "(tuple "
        for i in range(0, number_of_elements):
            clarity_name_size = self.data[self.pos]
            self.pos += 1
            self.output += (
                "("
                + self.data[self.pos : self.pos + clarity_name_size].decode("ascii")
                + " "
            )
            self.pos += clarity_name_size

            if not self.next_chunk():
                break
            self.output += ")"
            if i < number_of_elements - 1:
                self.output += " "
        print(")")
        return True


data = "0c0000000a06616374696f6e0d0000000c737761702d792d666f722d7804646174610c000000110962616c616e63652d7801000000000000000000005af41a18c17f0962616c616e63652d7901000000000000000000005af263d4888909656e642d626c6f636b01ffffffffffffffffffffffffffffffff0a6665652d726174652d78010000000000000000000000000000c3500a6665652d726174652d79010000000000000000000000000000c3500a6665652d72656261746501000000000000000000000000000000000c6d61782d696e2d726174696f0100000000000000000000000001c9c3800d6d61782d6f75742d726174696f0100000000000000000000000001c9c3800e6f7261636c652d617665726167650100000000000000000000000005e69ec00e6f7261636c652d656e61626c656403106f7261636c652d726573696c69656e740100000000000000000000000005f5df2d07706f6f6c2d696401000000000000000000000000000000040a706f6f6c2d6f776e6572051a64481b183106b6411046706a09a9fa67dd0ab26e0b73746172742d626c6f636b01000000000000000000000000000000000b7468726573686f6c642d7801000000000000000000000002540be4000b7468726573686f6c642d7901000000000000000000000002540be4000c746f74616c2d737570706c7901000000000000000000005b2a58e8fb640264780100000000000000000000000005f3aa260264790100000000000000000000000005f5365803666565010000000000000000000000000000c33b0a6665652d7265626174650100000000000000000000000000000000066f626a6563740d00000004706f6f6c0673656e646572051a601b5f251ece957754603da3ca0111a64830352707746f6b656e2d78061a64481b183106b6411046706a09a9fa67dd0ab26e0a746f6b656e2d616c657807746f6b656e2d79061a64481b183106b6411046706a09a9fa67dd0ab26e0d746f6b656e2d776c69616c6578"


clarity_code = ClarityHexCode(data)