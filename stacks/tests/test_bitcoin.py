import unittest
from stacks.bitcoin import (
    Transaction,
    pay_to_witness_public_key_hash,
    witness_commitment,
)
from stacks.utils import hex_to_bytes, bytes_to_hex, bytes_to_hex_reversed
from stacks.keys import get_verifying_key


class TransactionTest(unittest.TestCase):

    def test_transaction_empty_txid(self):
        tx = Transaction()
        self.assertEqual(
            bytes_to_hex_reversed(tx.txid()),
            "4ebd325a4b394cff8c57e8317ccf5a8d0e2bdf1b8526f8aad6c8e43d8240621a",
        )

    def test_transaction_empty_with_locktime_txid(self):
        tx = Transaction(locktime=0xDEADBEEF)
        self.assertEqual(
            bytes_to_hex_reversed(tx.txid()),
            "cbff17f77110c418f4291a63a17dc0f277808111ef6b07419ecef334d9beb069",
        )

    def test_transaction_coinbase(self):
        private_key = bytes(range(32))
        verifying_key = get_verifying_key(private_key)
        tx = Transaction()
        tx.add_input(
            previous_txid=bytes(32), previous_index=0xFFFFFFFF, witness=[bytes(32)]
        )
        tx.add_output(50, pay_to_witness_public_key_hash(verifying_key))
        tx.add_output(0, witness_commitment([]))
        self.assertEqual(
            bytes_to_hex_reversed(tx.txid()),
            "896e2de629d8acee0e3c30aa7a9ae48e57c28fa05866267be1cc4040c4c5351e",
        )
