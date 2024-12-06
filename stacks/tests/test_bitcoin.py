import unittest
from stacks.bitcoin import Transaction
from stacks.utils import hex_to_bytes, bytes_to_hex, bytes_to_hex_reversed


class KeysTest(unittest.TestCase):

    def test_transaction_empty_txid(self):
        tx = Transaction()
        self.assertEqual(
            bytes_to_hex_reversed(tx.txid()),
            "4ebd325a4b394cff8c57e8317ccf5a8d0e2bdf1b8526f8aad6c8e43d8240621a",
        )

    def test_transaction_with_locktime_txid(self):
        tx = Transaction(locktime=0xDEADBEEF)
        self.assertEqual(
            bytes_to_hex_reversed(tx.txid()),
            "cbff17f77110c418f4291a63a17dc0f277808111ef6b07419ecef334d9beb069",
        )
