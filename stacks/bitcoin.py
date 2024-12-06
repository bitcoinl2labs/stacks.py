from .stream import Stream, Streamable
from .utils import bytes_to_hex, bytes_to_hex_reversed, JSON
from .hashing import sha256


class Transaction(Streamable, JSON):

    class Input(Streamable, JSON):
        def fill_from_stream(self, stream):
            self.previous_txid = stream.read_bytes(32)
            self.previous_txout_index = stream.read_u32_le()
            self.txin_script_length = stream.read_varint_le()
            self.txin_script = stream.read_bytes(self.txin_script_length)
            self.sequence_no = stream.read_u32_le()

        def to_dict(self):
            return {
                "txid": bytes_to_hex_reversed(self.previous_txid),
                "vout": self.previous_txout_index,
                "scriptSig": {"asm": "", "hex": bytes_to_hex(self.txin_script)},
                "sequence": self.sequence_no,
            }

    class Output(Streamable, JSON):
        def fill_from_stream(self, stream):
            self.value = stream.read_u64_le()
            self.txout_script_length = stream.read_varint_le()
            self.txout_script = stream.read_bytes(self.txout_script_length)

        def fill_stream(self, stream):
            stream.write_u64_le(self.value)
            stream.write_varint_le(self.txout_script_length)
            stream.write_bytes(self.txout_script)

        def to_dict(self):
            return {
                "value": self.value,
                "scriptPubKey": {"asm": "", "hex": bytes_to_hex(self.txout_script)},
            }

    def __init__(
        self, version=2, flag=0x0100, inputs=[], outputs=[], witnesses=[], locktime=0
    ):
        self.version = version
        self.flag = flag
        self.number_of_inputs = len(inputs)
        self.inputs = inputs
        self.number_of_outputs = len(outputs)
        self.outputs = outputs
        self.witnesses = witnesses
        self.locktime = locktime

    def fill_stream(self, stream):
        stream.write_u32_le(self.version)
        stream.write_u16_le(self.flag)
        stream.write_varint_le(self.number_of_inputs)
        for tx_input in self.inputs:
            stream.write_stream(tx_input.to_stream())
        stream.write_varint_le(self.number_of_outputs)
        for tx_output in self.outputs:
            stream.write_stream(tx_output.to_stream())

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
        self.witnesses = []
        for _ in range(self.number_of_inputs):
            stack_items = stream.read_varint_le()
            witness = []
            for _ in range(stack_items):
                item_size = stream.read_varint_le()
                witness.append(stream.read_bytes(item_size))
            self.witnesses.append(witness)
        self.locktime = stream.read_u32_le()

    def txid(self):
        stream = Stream()
        stream.write_u32_le(self.version)
        stream.write_varint_le(self.number_of_inputs)
        # we cannot use tx_input.to_stream() as the ScriptSig must be removed from the txid
        for tx_input in self.inputs:
            stream.write_bytes(tx_input.previous_txid)
            stream.write_u32_le(tx_input.previous_txout_index)
            # 0-sized scriptsig
            stream.write_u8(0)
            stream.write_u32_le(tx_input.sequence_no)
        stream.write_varint_le(self.number_of_outputs)
        for tx_output in self.outputs:
            stream.write_stream(tx_output.to_stream())
        stream.write_u32_le(self.locktime)
        return sha256(sha256(stream.data).digest()).digest()

    def wtxid(self):
        stream = Stream()
        stream.write_u32_le(self.version)
        stream.write_u16_le(self.flag)
        stream.write_varint_le(self.number_of_inputs)
        # we cannot use tx_input.to_stream() as the ScriptSig must be removed from the txid
        for tx_input in self.inputs:
            stream.write_bytes(tx_input.previous_txid)
            stream.write_u32_le(tx_input.previous_txout_index)
            # 0-sized scriptsig
            stream.write_u8(0)
            stream.write_u32_le(tx_input.sequence_no)
        stream.write_varint_le(self.number_of_outputs)
        for tx_output in self.outputs:
            stream.write_stream(tx_output.to_stream())
        for witness in self.witnesses:
            stream.write_varint_le(len(witness))
            for stack_item in witness:
                stream.write_varint_le(len(stack_item))
                stream.write_bytes(stack_item)
        stream.write_u32_le(self.locktime)
        return sha256(sha256(stream.data).digest()).digest()

    def to_dict(self):
        return {
            "version": self.version,
            "txid": bytes_to_hex_reversed(self.txid()),
            "wtxid": bytes_to_hex_reversed(self.wtxid()),
            "witnesses": [
                tuple(map(bytes_to_hex, witness)) for witness in self.witnesses
            ],
            "locktime": self.locktime,
        }
