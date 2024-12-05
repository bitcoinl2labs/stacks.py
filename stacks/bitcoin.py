from .stream import Streamable
from .utils import bytes_to_hex, JSON


class Transaction(Streamable, JSON):

    class Input(Streamable, JSON):
        def fill_from_stream(self, stream):
            self.previous_txid = stream.read_blob(32)
            self.previous_txout_index = stream.read_u32_le()
            self.txin_script_length = stream.read_varint_le()
            self.txin_script = stream.read_blob(self.txin_script_length)
            self.sequence_no = stream.read_u32_le()

        def to_dict(self):
            return {
                "txid": bytes_to_hex(reversed(self.previous_txid)),
                "vout": self.previous_txout_index,
                "scriptSig": {"asm": "", "hex": bytes_to_hex(self.txin_script)},
                "sequence": self.sequence_no,
            }

    class Output(Streamable, JSON):
        def fill_from_stream(self, stream):
            self.value = stream.read_u64_le()
            self.txout_script_length = stream.read_varint_le()
            self.txout_script = stream.read_blob(self.txout_script_length)

        def to_dict(self):
            return {
                "value": self.value,
                "scriptPubKey": {"asm": "", "hex": bytes_to_hex(self.txout_script)},
            }

    def fill_from_stream(self, stream):
        self.version = stream.read_u32_le()
        self.flag = stream.read_u16_le()
        self.number_of_inputs = stream.read_varint_le()
        self.inputs = []
        for _ in range(self.number_of_inputs):
            self.inputs.append(Transaction.Input.from_stream(stream))
        self.number_of_outputs = stream.read_varint_le()
        self.outputs = []
        for _ in range(self.number_of_outputs):
            self.outputs.append(Transaction.Output.from_stream(stream))

    def to_dict(self):
        return {"": bytes_to_hex(reversed(self.previous_txid))}
