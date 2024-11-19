import struct
import datetime
from .hashing import sha512_256
from .address import c32_encode
from .serializable import Serializable
from .transaction import Transaction


class Block(Serializable):

    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.version = self.next_u8()
        self.chain_length = self.next_u64()
        self.burn_spent = self.next_u64()

        self.consensus_hash = self.next_hex(20)
        self.parent_block_id = self.next_hex(32)
        self.tx_merkle_root = self.next_hex(32)
        self.state_index_root = self.next_hex(32)

        self.timestamp = self.next_u64()

        self.miner_signature = self.next_hex(65)

        block_header_end = self.pos

        signer_signature_len = self.next_u32()

        self.signer_signature = []
        for i in range(0, signer_signature_len):
            self.signer_signature.append(self.next_hex(65))

        pox_treatment_start = self.pos

        pox_treatment_len = self.next_u16()

        pox_treatment_data_len = self.next_u32()

        self.pos += pox_treatment_data_len

        pox_treatment_end = self.pos

        self.txs = []

        txs_len = self.next_u32()

        for i in range(0, txs_len):
            tx_offset = self.pos
            tx = Transaction.from_serializable(self)
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
