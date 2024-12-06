import unittest
from stacks.stream import Stream, StreamError


class StreamTest(unittest.TestCase):

    def test_empty(self):
        s = Stream()
        self.assertEqual(s.data, b"")
        self.assertEqual(s.pos, 0)

    def test_not_empty(self):
        s = Stream(b"\xaa")
        self.assertSequenceEqual(s.data, b"\xaa")
        self.assertEqual(s.pos, 0)

    def test_read_u8(self):
        s = Stream(b"\x00\x01")
        self.assertEqual(s.read_u8(), 0)
        self.assertEqual(s.read_u8(), 1)
        self.assertEqual(s.pos, 2)
        self.assertRaises(StreamError, s.read_u8)

    def test_write_u8(self):
        s = Stream(b"\x00")
        s.write_u8(1)
        s.write_u8(2)
        self.assertSequenceEqual(s.data, b"\x01\x02\x00")
        self.assertEqual(s.pos, 2)

    def test_write_u8_from_empty(self):
        s = Stream()
        s.write_u8(1)
        s.write_u8(2)
        self.assertSequenceEqual(s.data, b"\x01\x02")
        self.assertEqual(s.pos, 2)

    def test_read_u16_le(self):
        s = Stream(b"\x01\x00\xaa\xbb")
        self.assertEqual(s.read_u16_le(), 1)
        self.assertEqual(s.read_u16_le(), 0xBBAA)
        self.assertEqual(s.pos, 4)
        self.assertRaises(StreamError, s.read_u16_le)

    def test_write_u16_le(self):
        s = Stream(b"\x00")
        s.write_u16_le(1)
        s.write_u16_le(2)
        self.assertSequenceEqual(s.data, b"\x01\x00\x02\x00\x00")
        self.assertEqual(s.pos, 4)

    def test_write_u16_le_from_empty(self):
        s = Stream()
        s.write_u16_le(1)
        s.write_u16_le(2)
        self.assertSequenceEqual(s.data, b"\x01\x00\x02\x00")
        self.assertEqual(s.pos, 4)

    def test_write_u16_le_from_bigger(self):
        s = Stream(b"\xde\xad\xbe\xef")
        s.write_u16_le(1)
        s.write_u16_le(2)
        self.assertSequenceEqual(s.data, b"\x01\x00\x02\x00\xde\xad\xbe\xef")
        self.assertEqual(s.pos, 4)

    def test_write_u16_be(self):
        s = Stream(b"\x00")
        s.write_u16_be(1)
        s.write_u16_be(2)
        self.assertSequenceEqual(s.data, b"\x00\x01\x00\x02\x00")
        self.assertEqual(s.pos, 4)

    def test_write_u16_be_from_empty(self):
        s = Stream()
        s.write_u16_be(1)
        s.write_u16_be(2)
        self.assertSequenceEqual(s.data, b"\x00\x01\x00\x02")
        self.assertEqual(s.pos, 4)

    def test_write_u16_le_from_bigger(self):
        s = Stream(b"\xde\xad\xbe\xef")
        s.write_u16_be(1)
        s.write_u16_be(2)
        self.assertSequenceEqual(s.data, b"\x00\x01\x00\x02\xde\xad\xbe\xef")
        self.assertEqual(s.pos, 4)

    def test_read_u32_le(self):
        s = Stream(b"\x01\x00\xaa\xbb")
        self.assertEqual(s.read_u32_le(), 0xBBAA0001)
        self.assertEqual(s.pos, 4)
        self.assertRaises(StreamError, s.read_u32_le)

    def test_write_u32_le(self):
        s = Stream(b"\x00")
        s.write_u32_le(1)
        self.assertSequenceEqual(s.data, b"\x01\x00\x00\x00\x00")
        self.assertEqual(s.pos, 4)

    def test_write_u32_le_from_empty(self):
        s = Stream()
        s.write_u32_le(1)
        s.write_u32_le(2)
        self.assertSequenceEqual(s.data, b"\x01\x00\x00\x00\x02\x00\x00\x00")
        self.assertEqual(s.pos, 8)

    def test_write_u32_le_from_bigger(self):
        s = Stream(b"\xde\xad\xbe\xef")
        s.write_u32_le(1)
        s.write_u32_le(2)
        self.assertSequenceEqual(
            s.data, b"\x01\x00\x00\x02\x00\x00\x00\xde\xad\xbe\xef"
        )
        self.assertEqual(s.pos, 4)

    def test_write_u32_be(self):
        s = Stream(b"\x00")
        s.write_u32_be(1)
        s.write_u32_be(2)
        self.assertSequenceEqual(s.data, b"\x00\x00\x00\x01\x00\x00\x00\x02\x00")
        self.assertEqual(s.pos, 8)

    def test_write_u32_be_from_empty(self):
        s = Stream()
        s.write_u32_be(1)
        s.write_u32_be(2)
        self.assertSequenceEqual(s.data, b"\x00\x00\x00\x01\x00\x00\x00\x02")
        self.assertEqual(s.pos, 8)

    def test_write_u32_le_from_bigger(self):
        s = Stream(b"\xde\xad\xbe\xef")
        s.write_u32_be(1)
        s.write_u32_be(2)
        self.assertSequenceEqual(
            s.data, b"\x00\x00\x00\x01\x00\x00\x00\x02\xde\xad\xbe\xef"
        )
        self.assertEqual(s.pos, 8)
