import struct
import datetime


class Block:

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

        signer_signature_len = self.next_u32()

        self.signer_signature = []
        for i in range(0, signer_signature_len):
            self.signer_signature.append(self.next_hex(65))

        pox_treatment_len = self.next_u16()

        (pox_treatment_data_len,) = struct.unpack(
            ">I", self.data[self.pos : self.pos + 4]
        )
        self.pos += 4

        self.pos += pox_treatment_data_len

        self.txs = []

        txs_len = self.next_u32()

        for i in range(0, txs_len):
            tx = {}
            tx["version"] = format(self.next_u8(), "02x")

            tx["chain_id"] = "".join(
                format(x, "02x") for x in self.data[self.pos : self.pos + 4]
            )
            self.pos += 4

            transaction_auth_type = self.data[self.pos]
            self.pos += 1

            if transaction_auth_type == 0x04:
                tx["hash_mode"] = format(self.data[self.pos], "02x")
                self.pos += 1
                tx["signer"] = "".join(
                    format(x, "02x") for x in self.data[self.pos : self.pos + 20]
                )
                self.pos += 20

                (tx["nonce"],) = struct.unpack(">Q", self.data[self.pos : self.pos + 8])
                self.pos += 8
                (tx["fee"],) = struct.unpack(">Q", self.data[self.pos : self.pos + 8])
                self.pos += 8
                tx["key_encoding"] = format(self.data[self.pos], "02x")
                self.pos += 1
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
                else:
                    raise Exception("unsupported payload_type {}".format(payload_type))

            elif transaction_auth_type == 0x05:
                pass
            else:
                raise Exception("invalid transaction auth")

            self.txs.append(tx)

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
