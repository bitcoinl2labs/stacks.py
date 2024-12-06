import unittest
from stacks.bitcoin import Transaction, pay_to_witness_public_key_hash
from stacks.utils import hex_to_bytes, bytes_to_hex, bytes_to_hex_reversed
from stacks.keys import get_verifying_key


class KeysTest(unittest.TestCase):

    def test_transaction_empty_txid(self):
        tx = Transaction()
        self.assertEqual(
            bytes_to_hex_reversed(tx.txid()),
            "bd6c245ca210e26c164f9ad412ffe3e6e83d405189cb1991bf047c323287ebdf",
        )

    def test_transaction_empty_with_locktime_txid(self):
        tx = Transaction(locktime=0xDEADBEEF)
        self.assertEqual(
            bytes_to_hex_reversed(tx.txid()),
            "f0354c104df6aec7d83c4c82326b783b47760694682f4b83f02778781907f2fd",
        )

    def test_transaction_coinbase(self):
        private_key = bytes(range(32))
        verifying_key = get_verifying_key(private_key)
        tx = Transaction()
        tx.add_input(
            previous_txid=bytes(32), previous_index=0xFFFFFFFF, witness=[bytes(32)]
        )
        tx.add_output(50, pay_to_witness_public_key_hash(verifying_key))
        print(tx.to_dict())
        self.assertEqual(
            bytes_to_hex_reversed(tx.txid()),
            "4ebd325a4b394cff8c57e8317ccf5a8d0e2bdf1b8526f8aad6c8e43d8240621a",
        )
