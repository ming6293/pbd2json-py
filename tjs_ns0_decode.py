#!/usr/bin/env python3
"""TJS/ns0 (.pbd) decoder / encoder.
Usage:
  python3 tjs_ns0_decode.py in.pbd out.json              # decode -> JSON
  python3 tjs_ns0_decode.py in.pbd out.tjs --tjs         # decode -> TJS literal
  python3 tjs_ns0_decode.py in.pbd out.pbd -e in.json    # encode JSON -> .pbd
"""

import json
import struct
import sys


class ByteChecker:
    def __init__(self, seed: int):
        self.seed = seed & 0xFFFFFFFF

    @staticmethod
    def _round(b):
        a = (b[0] ^ ((b[0] * 2) & 0xFF)) & 0xFF
        v = (a >> 2) & 0xFF
        v ^= b[2]
        v = (v >> 3) & 0xFF
        v ^= b[2]
        v ^= a
        b[0], b[1], b[2] = b[1], b[2], v & 0xFF

    def get_seed(self, type_code: int) -> int:
        b = list(struct.pack('<I', self.seed))
        if type_code == 0:
            return b[2]
        self._round(b)
        self.seed = struct.unpack('<I', bytes(b))[0]
        return b[2]

    def final_check(self) -> int:
        b = list(struct.pack('<I', self.seed))
        for _ in range(3):
            self._round(b)
        b[0], b[2] = b[2], b[0]
        return struct.unpack('<I', bytes(b))[0]


class Reader:
    def __init__(self, data: bytes, pos: int = 0):
        self.d = data
        self.p = pos

    def u16(self):
        v = struct.unpack_from('<H', self.d, self.p)[0]
        self.p += 2
        return v

    def u32(self):
        v = struct.unpack_from('<I', self.d, self.p)[0]
        self.p += 4
        return v

    def i64(self):
        v = struct.unpack_from('<q', self.d, self.p)[0]
        self.p += 8
        return v

    def f64(self):
        v = struct.unpack_from('<d', self.d, self.p)[0]
        self.p += 8
        return v

    def string(self):
        n = self.u32()
        raw = self.d[self.p:self.p + n * 2]
        self.p += n * 2
        return raw.decode('utf-16le', 'replace')


def read_header(data: bytes):
    magic, check = data[:4], data[4:8]
    seed, crypt, iv_len = struct.unpack_from('<IHH', data, 8)
    if magic != b'TJS/':
        raise ValueError('not a TJS/ns0 container: magic=%r' % magic)
    if check[1:4] != b's0\x00':
        raise ValueError('unexpected variant tag: %r' % check)
    if check[0] not in (ord('n'), ord('4')):
        raise ValueError('unknown filter stage: %r' % check)
    return dict(magic=magic, check=check, seed=seed, crypt=crypt, iv_len=iv_len)


def decode(path: str):
    data = open(path, 'rb').read()
    h = read_header(data)
    if h['crypt'] or h['iv_len']:
        raise ValueError('encrypted/IV ns0 (crypt=%d iv_len=%d) is not handled by this script'
                         % (h['crypt'], h['iv_len']))
    if h['check'][0] != ord('n'):
        raise ValueError('TJS/4s0 (crypt + LZ4) variant is not handled by this script')

    r = Reader(data, 16)
    checker = ByteChecker(h['seed'])

    def value():
        typ = r.u16()
        type_byte, check_byte = typ & 0xFF, typ >> 8
        expect = checker.get_seed(type_byte)
        if check_byte != expect:
            raise ValueError('byte-check failed at 0x%x: type=%02x got=%02x want=%02x'
                             % (r.p - 2, type_byte, check_byte, expect))
        if type_byte == 0x00:
            return None
        if type_byte == 0x02:
            return r.string()
        if type_byte == 0x04:
            return r.i64()
        if type_byte == 0x05:
            return r.f64()
        if type_byte == 0x81:
            return [value() for _ in range(r.u32())]
        if type_byte == 0xC1:
            n = r.u32()
            d = {}
            for _ in range(n):
                k = r.string()
                d[k] = value()
            return d
        raise ValueError('unknown type byte 0x%02x at 0x%x' % (type_byte, r.p - 2))

    root = value()
    want, got = checker.final_check(), r.u32()
    sys.stderr.write('# header %r seed=0x%08X crypt=%d iv_len=%d\n'
                     % (h['check'], h['seed'], h['crypt'], h['iv_len']))
    sys.stderr.write('# checksum expect=0x%08X got=0x%08X %s; consumed %d/%d bytes\n'
                     % (want, got, 'OK' if want == got else 'MISMATCH', r.p, len(data)))
    if want != got:
        raise ValueError('checksum mismatch')
    return root


def encode(obj, seed: int) -> bytearray:
    checker = ByteChecker(seed)
    out = bytearray(struct.pack('<4s4sIHH', b'TJS/', b'ns0\x00', seed, 0, 0))

    def put(o):
        if o is None:
            tb = 0x00
        elif isinstance(o, str):
            tb = 0x02
        elif isinstance(o, bool):
            raise TypeError('bool is not a TJS/ns0 type; use 0/1')
        elif isinstance(o, float):
            tb = 0x05
        elif isinstance(o, int):
            tb = 0x04
        elif isinstance(o, list):
            tb = 0x81
        elif isinstance(o, dict):
            tb = 0xC1
        else:
            raise TypeError('unsupported value: %r' % type(o))
        out.extend(struct.pack('<H', (checker.get_seed(tb) << 8) | tb))
        if tb == 0x02:
            raw = o.encode('utf-16le')
            out.extend(struct.pack('<I', len(raw) // 2))
            out.extend(raw)
        elif tb == 0x04:
            out.extend(struct.pack('<q', o))
        elif tb == 0x05:
            out.extend(struct.pack('<d', o))
        elif tb == 0x81:
            out.extend(struct.pack('<I', len(o)))
            for i in o:
                put(i)
        elif tb == 0xC1:
            out.extend(struct.pack('<I', len(o)))
            for k, v in o.items():
                raw = k.encode('utf-16le')
                out.extend(struct.pack('<I', len(raw) // 2))
                out.extend(raw)
                put(v)

    put(obj)
    out.extend(struct.pack('<I', checker.final_check()))
    return out


def _tjs_str(s: str) -> str:
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


def to_tjs(o, indent=0) -> str:
    pad = '    ' * indent
    if o is None:
        return 'void'
    if isinstance(o, str):
        return _tjs_str(o)
    if isinstance(o, bool):
        return '1' if o else '0'
    if isinstance(o, (int, float)):
        return str(o)
    if isinstance(o, list):
        items = [to_tjs(i, indent + 1) for i in o]
        return '[\n' + ',\n'.join('    ' * (indent + 1) + i for i in items) + '\n' + pad + ']'
    if isinstance(o, dict):
        items = ['%s => %s' % (_tjs_str(k), to_tjs(v, indent + 1)) for k, v in o.items()]
        return '%[\n' + ',\n'.join('    ' * (indent + 1) + i for i in items) + '\n' + pad + ']'
    raise TypeError(type(o))


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    src = args[0]
    out = args[1] if len(args) > 1 and not args[1].startswith('-') else None
    as_tjs = '--tjs' in args
    json_in = None
    if '-e' in args:
        json_in = args[args.index('-e') + 1]

    if json_in:
        obj = json.load(open(json_in, encoding='utf-8'))
        seed = read_header(open(src, 'rb').read())['seed']
        blob = encode(obj, seed)
        (open(out, 'wb').write(blob) if out else sys.stdout.buffer.write(blob))
        sys.stderr.write('# encoded %d bytes\n' % len(blob))
        return

    obj = decode(src)
    text = to_tjs(obj) + '\n' if as_tjs else json.dumps(obj, ensure_ascii=False, indent=2) + '\n'
    if out:
        open(out, 'w', encoding='utf-8').write(text)
        sys.stderr.write('# wrote %s\n' % out)
    else:
        print(text)


if __name__ == '__main__':
    main()
