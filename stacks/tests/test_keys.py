import unittest
from stacks.keys import generate_signing_and_verify_key, get_verifying_key, sign, verify
from stacks.utils import hex_to_bytes, bytes_to_hex


class KeysTest(unittest.TestCase):

    def test_generation(self):
        private, public = generate_signing_and_verify_key()
        self.assertEqual(len(private), 32)
        self.assertEqual(len(public), 64)

    def test_verifying_key(self):
        private = bytes(range(32))
        self.assertEqual(
            get_verifying_key(private),
            hex_to_bytes(
                "6d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2487e6222a6664e079c8edf7518defd562dbeda1e7593dfd7f0be285880a24dab"
            ),
        )

    def test_sign(self):
        private = bytes(range(32))
        self.assertEqual(
            bytes_to_hex(sign(b"hello world", private)),
            "d457a61187f24e19e96dd277d624dfbf7b028db0d38abe20dd66948e11f42a8312eef09807e38bbe881ce99bc83529e1d00c9a5f86760a75fbc6a0dfd668879a",
        )

    def test_verify(self):
        self.assertTrue(
            verify(
                b"hello world",
                hex_to_bytes(
                    "7db1d6a0578a0fce21848d8c065ebed9cf93ecedd05d1803e1c79929e9564ba481165c8c3b3f3d70bf977db6c08e3d09df89149db7d15c9cf0fa9442f9b4c84f"
                ),
                hex_to_bytes(
                    "6d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2487e6222a6664e079c8edf7518defd562dbeda1e7593dfd7f0be285880a24dab"
                ),
            )
        )
