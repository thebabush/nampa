#!/usr/bin/env python

from __future__ import print_function
from builtins import range
import os
import sys

import nampa


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def iprint(indent, *args, **kwargs):
    kwargs['sep'] = ''
    print("  " * indent, *args, **kwargs)


def format_functions(ff):
    out = []
    for f in ff:
        out.append('{}{:04X}:{}'.format('(l)' if f.is_local else '', f.offset, f.name))
    return ' '.join(out)


def format_tail_bytes(bb):
    out = []
    for b in bb:
        out.append('({:04X}: {:02X})'.format(b.offset, b.value))
    return ' '.join(out)


def format_refs(rr):
    out = []
    for r in rr:
        out.append('(REF {:04X}: {})'.format(r.offset, r.name))
    return 'XXX'.join(out)


def print_modules(node, level):
    for i, m in enumerate(node.modules):
        fmt = '{}. {:02X} {:04X} '
        if m.length < 0x10000:
            fmt += '{:04X} '
        else:
            fmt += '{:08X} '
        iprint(
            level,
            fmt.format(i, m.crc_length, m.crc16, m.length),
            format_functions(m.public_functions),
            ' ' + format_tail_bytes(m.tail_bytes) if len(m.tail_bytes) > 0 else '',
            ' ' + format_refs(m.referenced_functions) if len(m.referenced_functions) > 0 else ''
        )


def recurse(node, level):
    iprint(level, nampa.pattern2string(node.pattern, node.variant_mask), ':')
    if node.is_leaf:
        print_modules(node, level + 1)
    else:
        for child in node.children:
            recurse(child, level + 1)


def main(fpath):
    sig = nampa.parse_flirt_file(open(fpath, 'rb'))
    for child in sig.root.children:
        recurse(child, level=0)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: {} input_file.sig".format(sys.argv[0]))
        exit()

    main(sys.argv[1])
