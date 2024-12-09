import datetime
from .hashing import sha512_256
from .address import c32_encode
from .stream import Stream, Streamable
from .transaction import Transaction
from .utils import JSON, bytes_to_hex


class Block(Streamable, JSON):

    def __init__(self, previous_block_hash=bytes(range(32)), version=0x20000000):
        self.version = version
        """
        self.previous_block_hash = previous_block_hash
        self.merkle_root_hash = bytes(32)
        self.set_time_to_now()
        self.bits = 0x207FFFFF
        self.nonce = 0
        self.number_of_transactions = 0
        self.transactions = []
        """

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
        self.version = stream.read_u8()
        self.chain_length = stream.read_u64_be()
        self.burn_spent = stream.read_u64_be()

        self.consensus_hash = stream.read_bytes(20)
        self.parent_block_id = stream.read_bytes(32)
        self.tx_merkle_root = stream.read_bytes(32)
        self.state_index_root = stream.read_bytes(32)

        self.timestamp = stream.read_u64_be()

        self.miner_signature = stream.read_bytes(65)

        block_header_end = stream.pos

        signer_signatures_len = stream.read_u32_be()

        self.signer_signatures = []
        for i in range(0, signer_signatures_len):
            self.signer_signatures.append(stream.read_bytes(65))

        pox_treatment_start = stream.pos

        self.pox_treatment_len = stream.read_u16_be()

        pox_treatment_data_len = stream.read_u32_be()
        self.pox_treatment = stream.read_bytes(pox_treatment_data_len)

        pox_treatment_end = stream.pos

        self.txs = []

        txs_len = stream.read_u32_be()

        return

        for i in range(0, txs_len):
            tx_offset = self.pos
            tx = Transaction.from_stream(stream)
            """
            tx = {}
            tx["version"] = self.next_u8()

            tx["chain_id"] = self.next_u32()

            transaction_auth_type = self.next_u8()

            if transaction_auth_type == 0x04:
                tx["hash_mode"] = self.next_u8()
                signer = c32_encode(26, self.next_blob(20))
                tx["signer"] = signer

                tx["nonce"] = self.next_u64()
                tx["fee"] = self.next_u64()
                tx["key_encoding"] = self.next_u8()
                tx["signature"] = self.next_hex(65)
                tx["anchor_mode"] = format(self.data[self.pos], "02x")
                self.pos += 1
                tx["post_condition_mode"] = format(self.data[self.pos], "02x")
                self.pos += 1

                tx["post_conditions"] = []
                (post_conditions_len,) = struct.unpack(
                    ">I", self.data[self.pos : self.pos + 4]
                )
                self.pos += 4

                if post_conditions_len > 0:
                    raise Exception("post_conditions are not supported")

                for i in range(0, post_conditions_len):
                    # TODO: check for impl StacksMessageCodec for TransactionPostCondition in transaction.rs
                    pass

                payload_type = self.data[self.pos]
                self.pos += 1
                tx["payload_type"] = format(payload_type, "02x")

                if payload_type == 6:
                    tx["clarity_version"] = format(self.next_u8(), "02x")
                    tx["contract_name"] = self.next_contract_name()
                    tx["code_body"] = self.next_stacks_string()
                elif payload_type == 0:
                    print("PAYLOAD: ", self.data[self.pos :])
                    tx["principal_type"] = self.next_u8()
                    tx["principal_type2"] = self.next_u8()
                    tx["principal"] = c32_encode(26, self.next_blob(20))
                    tx["amount"] = self.next_u64()
                    tx["memo"] = self.next_hex(34)
                else:
                    raise Exception("unsupported payload_type {}".format(payload_type))

            elif transaction_auth_type == 0x05:
                pass
            else:
                raise Exception("invalid transaction auth")
            """
            self.txs.append(tx)

            tx_data = self.data[tx_offset : tx_offset + self.pos]

            tid = sha512_256(tx_data)
            tid_node = sha512_256(b"\x00")
            tid_node.update(tid.digest())
            tid_merkle_root = sha512_256(b"\x01")
            tid_merkle_root.update(tid_node.digest() + tid_node.digest())

            print(
                "TX size:",
                self.pos - tx_offset,
                "tid:",
                tid.hexdigest(),
                "merkle root:",
                tid_merkle_root.hexdigest(),
            )

        block_hash = sha512_256(self.data[:block_header_end])
        block_hash.update(self.data[pox_treatment_start:pox_treatment_end])
        print("block hash:", block_hash.hexdigest())
        print("version:", self.version)
        print("chain_length:", self.chain_length)
        print("burn_spent:", self.burn_spent)
        print("consensus_hash:", self.consensus_hash)
        print("parent_block_id:", self.parent_block_id)
        print("tx_merkle_root:", self.tx_merkle_root)
        print("state_index_root:", self.state_index_root)
        print("timestamp:", datetime.datetime.fromtimestamp(self.timestamp))
        print("miner_signature:", self.miner_signature)
        print("signer_signature:", self.signer_signature)
        print("pox_treatment:", pox_treatment_len)
        print("txs:", self.txs)
        print(self.data[self.pos :])

    def block_hash(self):
        stream = Stream()
        stream.write_u8(self.version)
        stream.write_u64_be(self.chain_length)
        stream.write_u64_be(self.burn_spent)
        stream.write_bytes(self.consensus_hash)
        stream.write_bytes(self.parent_block_id)
        stream.write_bytes(self.tx_merkle_root)
        stream.write_bytes(self.state_index_root)
        stream.write_u64_be(self.timestamp)
        stream.write_bytes(self.miner_signature)
        stream.write_u16_be(self.pox_treatment_len)
        stream.write_u32_be(len(self.pox_treatment))
        stream.write_bytes(self.pox_treatment)
        return sha512_256(stream.data).digest()

    def index_block_hash(self):
        return sha512_256(self.block_hash() + self.consensus_hash).digest()

    def block_id(self):
        """
        StacksBlockId::new(&self.consensus_hash, &self.block_hash())
        """

    def block_height(self):
        return self.chain_length

    def to_dict(self):
        return {
            "version": self.version,
            "versionHex": hex(self.version).replace("0x", ""),
            "height": self.block_height(),
            "block_hash": bytes_to_hex(self.block_hash()),
            "index_block_hash": bytes_to_hex(self.index_block_hash()),
            "timestamp": self.timestamp,
            # "hash": bytes_to_hex_reversed(self.block_hash()),
            # "merkleroot": bytes_to_hex_reversed(self.merkle_root_hash),
            # "time": self.time,
            # "nonce": self.nonce,
            # "transactions": [tx.to_dict() for tx in self.transactions],
        }
