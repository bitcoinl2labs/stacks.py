import struct


class Serializable:
    def next_u8(self):
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

    def next_u64(self):
        (value,) = struct.unpack(">Q", self.data[self.pos : self.pos + 8])
        self.pos += 8
        return value

    def next_hex(self, bytes_len):
        output = "".join(
            format(x, "02x") for x in self.data[self.pos : self.pos + bytes_len]
        )
        self.pos += bytes_len
        return "0x" + output

    def next_blob(self, bytes_len):
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
