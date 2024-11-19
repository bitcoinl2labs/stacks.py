from .serializable import Serializable, bytes_to_hex
from .hashing import sha512_256
from .address import c32_encode


class TransactionPayload(Serializable):
    pass


class TokenTransfer(TransactionPayload):

    def __init__(self):
        pass

    def fill_from_serializable(self, serializable):
        self.principal_type = serializable.next_u8()
        self.principal_type2 = serializable.next_u8()
        self.principal = serializable.next_blob(20)
        self.amount = serializable.next_u64()
        self.memo = serializable.next_blob(34)

    @staticmethod
    def from_serializable(serializable):
        token_transfer = TokenTransfer()
        token_transfer.fill_from_serializable(serializable)
        return token_transfer


class Transaction:

    def __init__(self):
        self.version = 0x80
        self.chain_id = 0x80000000
        self.auth = 0
        self.anchor_mode = 0
        self.post_condition_mode = 0
        self.post_conditions = []
        self.payload = None
        self.raw = None

    def __repr__(self):
        return f"Transaction(txid=0x{bytes_to_hex(self.txid())}, signer=\"{c32_encode(26, self.signer)}\", nonce={self.nonce}, fee={self.fee})"

    def txid(self):
        return sha512_256(self.raw).digest()

    def from_serializable(self, serializable):
        initial_offset = serializable.pos
        self.version = serializable.next_u8()
        self.chain_id = serializable.next_u32()

        self.auth = serializable.next_u8()

        """
        self.auth can be:
        AuthStandard = 0x04,
        AuthSponsored = 0x05,


        """

        self.hash_mode = serializable.next_u8()

        """
        self.hash_mode can be:
        pub enum SinglesigHashMode {
            P2PKH = 0x00,
            P2WPKH = 0x02,
        }

        pub enum MultisigHashMode {
            P2SH = 0x01,
            P2WSH = 0x03,
        }

        pub enum OrderIndependentMultisigHashMode {
            P2SH = 0x05,
            P2WSH = 0x07,
        }
        """

        if self.auth == 0x04:
            # signer = c32_encode(26, serializable.next_blob(20))
            self.signer = serializable.next_blob(20)

            self.nonce = serializable.next_u64()
            self.fee = serializable.next_u64()
            self.key_encoding = serializable.next_u8()
            self.signature = serializable.next_blob(65)
            self.anchor_mode = serializable.next_u8()
            self.post_condition_mode = serializable.next_u8()
            self.post_conditions = []
            post_conditions_len = serializable.next_u32()

            if post_conditions_len > 0:
                raise Exception("post_conditions are not supported")

            for i in range(0, post_conditions_len):
                # TODO: check for impl StacksMessageCodec for TransactionPostCondition in transaction.rs
                pass

            self.payload_type = serializable.next_u8()

            if self.payload_type == 6:
                tx["clarity_version"] = format(self.next_u8(), "02x")
                tx["contract_name"] = self.next_contract_name()
                tx["code_body"] = self.next_stacks_string()
            elif self.payload_type == 0:
                self.payload = TokenTransfer.from_serializable(serializable)
                """
                print("PAYLOAD: ", self.data[self.pos :])
                tx["principal_type"] = self.next_u8()
                tx["principal_type2"] = self.next_u8()
                tx["principal"] = c32_encode(26, self.next_blob(20))
                tx["amount"] = self.next_u64()
                tx["memo"] = self.next_hex(34)
                """
            else:
                raise Exception("unsupported payload_type {}".format(self.payload_type))

            self.raw = serializable.data[initial_offset : serializable.pos]

        elif self.auth == 0x05:
            pass
        else:
            raise Exception("invalid transaction auth")
        return self

    def from_bytes(self, data, offset=0):
        serializable = Serializable()
        serializable.data = data
        serializable.pos = offset
        self.from_serializable(serializable)
        return self

    def serialize(self):
        blob = struct.pack(">BI", self.version, self.chain_id)

        # auth Standard + SingleSig(SinglesigSpendingCondition)
        blob += struct.pack(">B", 0x04)

        return blob
