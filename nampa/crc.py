from __future__ import print_function

from builtins import range

POLY = 0x1021
_crc_table = []


def _rev8(n):
    return int('{:08b}'.format(n)[::-1], 2)


def _rev16(n):
    return int('{:016b}'.format(n)[::-1], 2)

_poly_rev = _rev16(POLY)


def _init_table():
    for i in range(256):
        i = _rev8(i)

        crc = 0
        c = (i << 8) & 0xFFFF

        for j in range(8):
            if (crc ^ c) & 0x8000:
                crc = (crc << 1) ^ POLY
            else:
                crc = (crc << 1)

            crc &= 0xFFFF
            c = (c << 1) & 0xFFFF

        crc = _rev16(crc)
        _crc_table.append(crc)
_init_table()


def crc16(data, start_value=0xFFFF):
    """
    Perform CRC16 X.25

    :param data: a list of bytes or a bytearray
    :param start_value: the start value for the CRC. Should be a 16-bits value.
                        Should be left to the default value.
    :return: the CRC16-X.25 of the given bytes
    """
    out = start_value

    for b in data:
        tmp = (out ^ b) & 0xFF
        out = (out >> 8) ^ _crc_table[tmp]

    out ^= 0xFFFF
    out = ((out & 0xFF) << 8) | ((out >> 8) & 0xff)
    return out


def crc16slow(data, start_value=0xFFFF):
    out = start_value

    for b in data:
        for i in range(8):
            if (out ^ b) & 1 == 1:
                out = (out >> 1) ^ _poly_rev
            else:
                out >>= 1
            b >>= 1

    out = (~out) & 0xFFFF
    out = ((out & 0xFF) << 8) | ((out >> 8) & 0xff)
    return out
