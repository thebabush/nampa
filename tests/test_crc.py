from builtins import range
import unittest
import random
from nampa import crc


class TestCRC(unittest.TestCase):
    def test_empty(self):
        self.assertTrue(crc.crc16([]) == crc.crc16slow([]))
        self.assertTrue(crc.crc16([], 0) == crc.crc16slow([], 0))


    def test_empty_start_value(self):
        for i in range(0x100):
            i = bytearray([i])
            self.assertTrue(crc.crc16(i, 0) == crc.crc16slow(i, 0))


    def test_random_values(self):
        for _ in range(100):
            n = random.randint(0, 100)
            values = [random.randint(0, 0xFF) for _ in range(n)]
            for v in values:
                self.assertTrue(check_random_value(v))

def check_random_value(bb):
    bb = bytearray(bb)
    return crc.crc16(bb) == crc.crc16slow(bb)

if __name__ == '__main__':
    unittest.main()
