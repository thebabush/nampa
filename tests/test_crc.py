from builtins import range
import random
from nampa import crc


def test_empty():
    assert crc.crc16([]) == crc.crc16slow([])
    assert crc.crc16([], 0) == crc.crc16slow([], 0)


def test_empty_start_value():
    for i in range(0x100):
        i = bytearray([i])
        assert crc.crc16(i, 0) == crc.crc16slow(i, 0)


def test_random_values():
    for i in range(100):
        n = random.randint(0, 100)
        values = [random.randint(0, 0xFF) for _ in range(n)]
        yield check_random_value, values


def check_random_value(bb):
    bb = bytearray(bb)
    assert crc.crc16(bb) == crc.crc16slow(bb)
