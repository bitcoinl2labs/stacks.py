import struct
import json
from struct import error as StreamError


class Stream:

    def __init__(self, data=b"", offset=0):
        self.data = bytearray(data)
        self.pos = offset

    def read_u8(self):
        try:
            value = self.data[self.pos]
        except IndexError:
            raise StreamError from None
        self.pos += 1
        return value

    def read_u16_be(self):
        (value,) = struct.unpack(">H", self.data[self.pos : self.pos + 2])
        self.pos += 2
        return value

    def read_u32_be(self):
        (value,) = struct.unpack(">I", self.data[self.pos : self.pos + 4])
        self.pos += 4
        return value

    def read_u64_be(self):
        (value,) = struct.unpack(">Q", self.data[self.pos : self.pos + 8])
        self.pos += 8
        return value

    def read_u16_le(self):
        (value,) = struct.unpack("<H", self.data[self.pos : self.pos + 2])
        self.pos += 2
        return value

    def read_u32_le(self):
        (value,) = struct.unpack("<I", self.data[self.pos : self.pos + 4])
        self.pos += 4
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

    def write_varint_le(self, value):
        if value < 0xFD:
            self.write_u8(value)
        elif value <= 0xFFFF:
            self.write_u8(0xFD)
            self.write_u16_le(value)
        elif value <= 0xFFFFFFFF:
            self.write_u8(0xFE)
            self.write_u32_le(value)
        else:
            self.write_u8(0xFF)
            self.write_u64_le(value)

    def read_bytes(self, bytes_len):
        output = self.data[self.pos : self.pos + bytes_len]
        self.pos += bytes_len
        return bytes(output)

    def read_contract_name(self):
        contract_name_len = self.next_u8()
        contract_name = self.data[self.pos : self.pos + contract_name_len].decode(
            "ascii"
        )
        self.pos += contract_name_len
        return contract_name

    def read_stacks_string(self):
        stacks_string_len = self.next_u32()
        stacks_string = self.data[self.pos : self.pos + stacks_string_len].decode(
            "utf8"
        )
        self.pos += stacks_string_len
        return stacks_string

    def write_u8(self, u8):
        self.data[self.pos : self.pos] += struct.pack("B", u8)
        self.pos += 1

    def write_u16_be(self, u16):
        self.data[self.pos : self.pos] += struct.pack(">H", u16)
        self.pos += 2

    def write_u32_be(self, u32):
        self.data[self.pos : self.pos] += struct.pack(">I", u32)
        self.pos += 4

    def write_u64_be(self, u64):
        self.data[self.pos : self.pos] += struct.pack(">Q", u64)
        self.pos += 8

    def write_u16_le(self, u16):
        self.data[self.pos : self.pos] += struct.pack("<H", u16)
        self.pos += 2

    def write_u32_le(self, u32):
        self.data[self.pos : self.pos] += struct.pack("<I", u32)
        self.pos += 4

    def write_u64_le(self, u64):
        self.data[self.pos : self.pos] += struct.pack("<Q", u64)
        self.pos += 8

    def write_stream(self, stream, offset=0):
        self.data[self.pos : self.pos] += stream.data[offset:]
        self.pos += len(stream.data) - offset

    def write_bytes(self, _bytes):
        self.data[self.pos : self.pos] += _bytes
        self.pos += len(_bytes)


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

    def to_stream(self):
        s = Stream()
        self.fill_stream(s)
        return s

    def to_bytes(self):
        return bytes(self.to_stream().data)
