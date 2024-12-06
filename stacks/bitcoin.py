from .stream import Stream, Streamable
from .utils import bytes_to_hex, bytes_to_hex_reversed, JSON
from .hashing import sha256, ripemd160
import datetime


def pay_to_witness_public_key_hash(public_key):
    return b"\x00\x14" + ripemd160(public_key).digest()


class Transaction(Streamable, JSON):

    class Input(Streamable, JSON):

        def __init__(
            self,
            previous_txid=bytes(32),
            previous_txout_index=0xFFFFFFFF,
            txin_script=b"",
            sequence_no=0xFFFFFFFF,
        ):
            self.previous_txid = previous_txid
            self.previous_txout_index = previous_txout_index
            self.txin_script_length = len(txin_script)
            self.txin_script = txin_script
            self.sequence_no = sequence_no

        def fill_from_stream(self, stream):
            self.previous_txid = stream.read_bytes(32)
            self.previous_txout_index = stream.read_u32_le()
            self.txin_script_length = stream.read_varint_le()
            self.txin_script = stream.read_bytes(self.txin_script_length)
            self.sequence_no = stream.read_u32_le()

        def fill_stream(self, stream):
            stream.write_bytes(self.previous_txid)
            stream.write_u32_le(self.previous_txout_index)
            stream.write_varint_le(self.txin_script_length)
            stream.write_bytes(self.txin_script)
            stream.write_u32_le(self.sequence_no)

        def to_dict(self):
            return {
                "txid": bytes_to_hex_reversed(self.previous_txid),
                "vout": self.previous_txout_index,
                "scriptSig": {"asm": "", "hex": bytes_to_hex(self.txin_script)},
                "sequence": self.sequence_no,
            }

    class Output(Streamable, JSON):
        def __init__(self, value=0, txout_script=b""):
            self.value = value
            self.txout_script_length = len(txout_script)
            self.txout_script = txout_script

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

    def add_input(
        self,
        previous_txid,
        previous_index,
        script=bytes(32),
        sequence=0xFFFFFFFF,
        witness=[],
    ):
        tx_input = Transaction.Input(previous_txid, previous_index, script, sequence)
        self.number_of_inputs += 1
        self.inputs.append(tx_input)
        self.witnesses.append(witness)
        return tx_input

    def add_output(self, amount, script):
        tx_output = Transaction.Output(amount, script)
        self.number_of_outputs += 1
        self.outputs.append(tx_output)
        return tx_output

    def preimage(self):
        stream = Stream()
        stream.write_u32_le(self.version)
        for tx_input in self.inputs:
            stream.write_bytes(tx_input.previous_txid)
            stream.write_u32_le(tx_input.previous_txout_index)

    def txid(self):
        stream = Stream()
        stream.write_u32_le(self.version)
        stream.write_varint_le(self.number_of_inputs)
        for tx_input in self.inputs:
            stream.write_stream(tx_input.to_stream())
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
        for tx_input in self.inputs:
            stream.write_stream(tx_input.to_stream())
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
            "vin": [tx.to_dict() for tx in self.inputs],
            "vout": [tx.to_dict() for tx in self.outputs],
            "witnesses": [
                tuple(map(bytes_to_hex, witness)) for witness in self.witnesses
            ],
            "locktime": self.locktime,
        }


class Block(Streamable, JSON):
    def __init__(self, previous_block_hash=bytes(range(32)), version=2):
        self.version = version
        self.previous_block_hash = previous_block_hash
        self.merke_root_hash = bytes(range(32))
        self.time = int(datetime.datetime.now(tz=datetime.timezone.utc).timestamp())
        self.bits = 0x207FFFFF
        self.nonce = 0
        self.number_of_transactions = 0
        self.transactions = []

    def fill_stream(self, stream):
        stream.write_u32_le(self.version)
        stream.write_bytes(self.previous_block_hash)
        stream.write_bytes(self.merke_root_hash)
        stream.write_u32_le(self.time)
        stream.write_u32_le(self.bits)
        stream.write_u32_le(self.nonce)
        stream.write_varint_le(self.number_of_transactions)
        for transaction in self.transactions:
            stream.write_stream(transaction.to_stream())

    def fill_from_stream(self, stream):
        self.version = stream.read_u32_le()
        self.previous_block_hash = stream.read_bytes(32)
        self.merke_root_hash = stream.read_bytes(32)
        self.time = stream.read_u32_le()
        self.bits = stream.read_u32_le()
        self.nonce = stream.read_u32_le()
        self.number_of_transactions = stream.read_varint_le()
        self.transactions = []
        for _ in range(self.number_of_transactions):
            self.transactions.append(Transaction.from_stream(stream))

    def merkle_root(self):
        return bytes(32)

    def block_hash(self):
        stream = Stream()
        stream.write_u32_le(self.version)
        stream.write_bytes(self.previous_block_hash)
        stream.write_bytes(self.merke_root_hash)
        stream.write_u32_le(self.time)
        stream.write_u32_le(self.bits)
        stream.write_u32_le(self.nonce)
        return sha256(sha256(stream.data).digest()).digest()

    def to_dict(self):
        return {
            "version": self.version,
            "versionHex": hex(self.version).replace("0x", ""),
            "hash": bytes_to_hex_reversed(self.block_hash()),
            "merkleroot": bytes_to_hex_reversed(self.merke_root_hash),
            "bits": hex(self.bits).replace("0x", ""),
            "time": self.time,
            "nonce": self.nonce,
            "transactions": [tx.to_dict() for tx in self.transactions],
        }
