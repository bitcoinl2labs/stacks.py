from .stream import Stream, Streamable
from .utils import (
    bytes_to_hex,
    bytes_to_hex_reversed,
    JSON,
    hex_to_bytes_reversed,
    hex_to_bytes,
)
from .hashing import sha256, double_sha256
from .keys import sign_der, compress_public_key, public_key_hash
import datetime
import urllib
import json
import base64


def pay_to_witness_public_key_hash(public_key):
    return b"\x00\x14" + public_key_hash(public_key)


def witness_commitment(wtxids):
    return (
        b"\x6a\x24\xaa\x21\xa9\xed"
        + double_sha256(merkle_root([bytes(32)] + wtxids) + bytes(32)).digest()
    )


def merkle_root(items):
    print(items)
    if not items:
        return bytes(32)
    hashes = [item for item in items]
    while len(hashes) > 1:
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])

        merged_hashes = []
        for i in range(0, len(hashes), 2):
            merged_hashes.append(double_sha256(hashes[i] + hashes[i + 1]).digest())
        hashes = merged_hashes
    return hashes[0]


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
        self,
        version=2,
        flag=0x0100,
        inputs=None,
        outputs=None,
        witnesses=None,
        locktime=0,
    ):
        self.version = version
        self.flag = flag
        self.inputs = inputs if inputs else []
        self.number_of_inputs = len(self.inputs)
        self.outputs = outputs if outputs else []
        self.number_of_outputs = len(self.outputs)
        self.witnesses = witnesses if witnesses else []
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
        for witness in self.witnesses:
            stream.write_varint_le(len(witness))
            for stack_item in witness:
                stream.write_varint_le(len(stack_item))
                stream.write_bytes(stack_item)
        stream.write_u32_le(self.locktime)

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
        script=b"",
        sequence=0xFFFFFFFF,
    ):
        tx_input = Transaction.Input(previous_txid, previous_index, script, sequence)
        self.number_of_inputs += 1
        self.inputs.append(tx_input)
        return tx_input

    def add_output(self, amount, script):
        tx_output = Transaction.Output(amount, script)
        self.number_of_outputs += 1
        self.outputs.append(tx_output)
        return tx_output

    def add_witness(self, witness):
        self.witnesses.append(witness)

    def preimage(self, _index, input_amount, public_key):
        stream = Stream()
        stream.write_u32_le(self.version)
        txids_and_inputs = Stream()
        for tx_input in self.inputs:
            txids_and_inputs.write_bytes(tx_input.previous_txid)
            txids_and_inputs.write_u32_le(tx_input.previous_txout_index)
        stream.write_bytes(double_sha256(txids_and_inputs.data).digest())
        sequences = Stream()
        for tx_input in self.inputs:
            sequences.write_u32_le(tx_input.sequence_no)
        stream.write_bytes(double_sha256(sequences.data).digest())
        stream.write_bytes(self.inputs[_index].previous_txid)
        stream.write_u32_le(self.inputs[_index].previous_txout_index)
        scriptcode = b"\x19\x76\xa9\x14" + public_key_hash(public_key) + b"\x88\xac"
        stream.write_bytes(scriptcode)
        stream.write_u64_le(input_amount)
        stream.write_u32_le(self.inputs[_index].sequence_no)
        outputs = Stream()
        for tx_output in self.outputs:
            outputs.write_stream(tx_output.to_stream())
        stream.write_bytes(double_sha256(outputs.data).digest())
        stream.write_u32_le(self.locktime)
        stream.write_u32_le(0x01)  # SIGHASH_ALL
        return double_sha256(stream.data).digest()

    def sign(self, _index, input_amount, private_key, public_key):
        return (
            sign_der(self.preimage(_index, input_amount, public_key), private_key)
            + b"\x01"
        )

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
    def __init__(self, previous_block_hash=bytes(range(32)), version=0x20000000):
        self.version = version
        self.previous_block_hash = previous_block_hash
        self.merkle_root_hash = bytes(32)
        self.set_time_to_now()
        self.bits = 0x207FFFFF
        self.nonce = 0
        self.number_of_transactions = 0
        self.transactions = []

    def fill_stream(self, stream):
        stream.write_u32_le(self.version)
        stream.write_bytes(self.previous_block_hash)
        stream.write_bytes(self.merkle_root_hash)
        stream.write_u32_le(self.time)
        stream.write_u32_le(self.bits)
        stream.write_u32_le(self.nonce)
        stream.write_varint_le(self.number_of_transactions)
        for transaction in self.transactions:
            stream.write_stream(transaction.to_stream())

    def fill_from_stream(self, stream):
        self.version = stream.read_u32_le()
        self.previous_block_hash = stream.read_bytes(32)
        self.merkle_root_hash = stream.read_bytes(32)
        self.time = stream.read_u32_le()
        self.bits = stream.read_u32_le()
        self.nonce = stream.read_u32_le()
        self.number_of_transactions = stream.read_varint_le()
        self.transactions = []
        for _ in range(self.number_of_transactions):
            self.transactions.append(Transaction.from_stream(stream))

    def set_time_to_now(self):
        self.time = int(datetime.datetime.now(tz=datetime.timezone.utc).timestamp())

    def add_transaction(self, transaction):
        self.number_of_transactions += 1
        self.transactions.append(transaction)
        self.merkle_root_hash = self.merkle_root()

    def merkle_root(self):
        if self.number_of_transactions < 1:
            return bytes(32)
        return merkle_root([transaction.txid() for transaction in self.transactions])

    def block_hash(self):
        stream = Stream()
        stream.write_u32_le(self.version)
        stream.write_bytes(self.previous_block_hash)
        stream.write_bytes(self.merkle_root_hash)
        stream.write_u32_le(self.time)
        stream.write_u32_le(self.bits)
        stream.write_u32_le(self.nonce)
        return sha256(sha256(stream.data).digest()).digest()

    def mine(self):
        exponent = self.bits >> 24
        mantissa = self.bits & 0x00FFFFFF
        difficulty = mantissa * 2 ** (8 * (exponent - 3))
        print(difficulty)
        while True:
            for i in range(0, 0xFFFFFFFF):
                self.nonce = i
                proof_of_work = int.from_bytes(self.block_hash(), byteorder="little")
                if proof_of_work < difficulty:
                    print(proof_of_work)
                    return
            self.set_time_to_now()

    def to_dict(self):
        return {
            "version": self.version,
            "versionHex": hex(self.version).replace("0x", ""),
            "hash": bytes_to_hex_reversed(self.block_hash()),
            "merkleroot": bytes_to_hex_reversed(self.merkle_root_hash),
            "bits": hex(self.bits).replace("0x", ""),
            "time": self.time,
            "nonce": self.nonce,
            "transactions": [tx.to_dict() for tx in self.transactions],
        }


class BitcoinHttpException(Exception):
    pass


class BitcoinHttpTimeoutException(Exception):
    pass


class Api:

    def __init__(
        self,
        base_url="http://localhost:18444/",
        timeout=30,
        username=None,
        password=None,
    ):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.timeout = timeout

    def json_rpc(self, json_rpc_method, params=None):
        json_rpc_dict = {
            "jsonrpc": "1.0",
            "id": "stacks.py",
            "method": json_rpc_method,
            "params": params if params else [],
        }
        content = json.dumps(json_rpc_dict)
        request = urllib.request.Request(
            self.base_url,
            content.encode(),
            {"Content-Type": "application/json"},
        )
        request.get_method = lambda: "POST"
        if self.username and self.password:
            auth = base64.b64encode(
                "{}:{}".format(self.username, self.password).encode()
            ).decode()
            request.add_header("Authorization", "Basic {}".format(auth))
        try:
            with urllib.request.urlopen(request) as response:
                return json.loads(response.read())["result"]
        except urllib.error.HTTPError as error:
            raise BitcoinHttpException(
                "{} {}: {}".format(error.status, error.reason, error.fp.read().decode())
            ) from None
        except urllib.error.URLError as error:
            raise BitcoinHttpException(
                "{} {}: {}".format(error.status, error.reason, error.fp.read().decode())
            ) from None
        except TimeoutError:
            raise BitcoinHttpTimeoutException()

    def get_best_block_hash(self):
        return hex_to_bytes_reversed(self.json_rpc("getbestblockhash"))

    def submit_block(self, block):
        return self.json_rpc("submitblock", [block.to_hex()])

    def send_transaction(self, transaction):
        return self.json_rpc("sendrawtransaction", [transaction.to_hex()])

    def get_mempool(self):
        return self.json_rpc("getrawmempool")

    def get_transaction(self, txid):
        return Transaction.from_bytes(
            hex_to_bytes(self.json_rpc("getrawtransaction", [txid]))
        )

    def get_mempool_transactions(self):
        transactions = []
        for txid in self.get_mempool():
            transactions.append(self.get_transaction(txid))
        return transactions
