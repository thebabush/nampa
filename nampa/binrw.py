import struct


def read_x(fmt, f, l):
    return struct.unpack(fmt, f.read(l))[0]


def read_u8(f):
    return read_x('B', f, 1)


def read_u16be(f):
    return read_x('>H', f, 2)


def read_u24be(f):
    return read_u8(f) << 16 | read_u16be(f)


def read_u32be(f):
    return read_x('>L', f, 4)


def read_u16le(f):
    return read_x('<H', f, 2)


def read_u32le(f):
    return read_x('<L', f, 4)
