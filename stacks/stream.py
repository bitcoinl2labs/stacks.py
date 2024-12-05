import struct
import json


class Stream:

    def __init__(self, data, offset=0):
        self.data = data
        self.pos = offset

    def next_u8(self):
        value = self.data[self.pos]
        self.pos += 1
        return value

    def read_u8(self):
        value = self.data[self.pos]
        self.pos += 1
        return value

    def next_u16(self):
        (value,) = struct.unpack(">H", self.data[self.pos : self.pos + 2])
        self.pos += 2
        return value

    def next_u32(self):
        (value,) = struct.unpack(">I", self.data[self.pos : self.pos + 4])
        self.pos += 4
        return value

    def read_u16_le(self):
        (value,) = struct.unpack("<H", self.data[self.pos : self.pos + 2])
        self.pos += 2
        return value

    def read_u32_le(self):
        (value,) = struct.unpack("<I", self.data[self.pos : self.pos + 4])
        self.pos += 4
        return value

    def next_u64(self):
        (value,) = struct.unpack(">Q", self.data[self.pos : self.pos + 8])
        self.pos += 8
        return value

    def read_u64_le(self):
        (value,) = struct.unpack("<Q", self.data[self.pos : self.pos + 8])
        self.pos += 8
        return value

    def read_varint_le(self):
        b = self.read_u8()
        if b < 0xFD:
            return b
        if b == 0xFD:
            return self.read_u16_le()
        if b == 0xFE:
            return self.read_u32_le()
        if b == 0xFF:
            return self.read_u64_le()

    def next_blob(self, bytes_len):
        output = self.data[self.pos : self.pos + bytes_len]
        self.pos += bytes_len
        return output

    def read_blob(self, bytes_len):
        output = self.data[self.pos : self.pos + bytes_len]
        self.pos += bytes_len
        return output

    def next_contract_name(self):
        contract_name_len = self.next_u8()
        contract_name = self.data[self.pos : self.pos + contract_name_len].decode(
            "ascii"
        )
        self.pos += contract_name_len
        return contract_name

    def next_stacks_string(self):
        stacks_string_len = self.next_u32()
        stacks_string = self.data[self.pos : self.pos + stacks_string_len].decode(
            "utf8"
        )
        self.pos += stacks_string_len
        return stacks_string

    def write_u8(self, u8):
        self.data += struct.pack("B", u8)

    def write_u16(self, u8):
        self.data += struct.pack(">H", u8)

    def write_u32(self, u8):
        self.data += struct.pack(">I", u8)

    def write_u64(self, u8):
        self.data += struct.pack(">Q", u8)


class Streamable:

    @classmethod
    def from_stream(cls, stream):
        token_transfer = cls()
        token_transfer.fill_from_stream(stream)
        return token_transfer

    @classmethod
    def from_bytes(cls, data, offset=0):
        stream = Stream(data, offset)
        return cls.from_stream(stream)
