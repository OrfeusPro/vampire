"""Extract native enum name/value arrays from the shipping PE, read only.

Accepts only contiguous 16-byte (image pointer, signed value) rows whose
name pointers all resolve to strings of the same enum in mapped PE sections.
"""
import hashlib
import json
import mmap
import os
import re
import struct
from collections import defaultdict
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
INSTALL = Path(os.environ.get('PHONEEXIT_VAMPIR_INSTALL', 'C:/Program Files/Netmarble/Netmarble Game/VAMPIR'))


class PE:
    def __init__(self, data):
        self.data = data
        if data[:2] != b'MZ':
            raise ValueError('Not PE')
        pe = struct.unpack_from('<I', data, 60)[0]
        if data[pe:pe + 4] != b'PE\0\0':
            raise ValueError('Invalid PE header')
        count, optional_size = struct.unpack_from('<H', data, pe + 6)[0], struct.unpack_from('<H', data, pe + 20)[0]
        opt = pe + 24
        if struct.unpack_from('<H', data, opt)[0] != 0x20b:
            raise ValueError('Expected PE32+')
        self.base = struct.unpack_from('<Q', data, opt + 24)[0]
        self.sections = []
        for i in range(count):
            start = opt + optional_size + i * 40
            size, rva, raw_size, raw = struct.unpack_from('<IIII', data, start + 8)
            if raw + raw_size > len(data):
                raise ValueError('Invalid PE section')
            self.sections.append(dict(name=data[start:start + 8].rstrip(b'\0').decode(), rva=rva, size=size, raw=raw, raw_size=raw_size))

    def address(self, offset):
        for section in self.sections:
            if section['raw'] <= offset < section['raw'] + section['raw_size']:
                return self.base + section['rva'] + offset - section['raw']
        return None


def extract(data):
    pe = PE(data)
    names, groups = {}, defaultdict(list)
    for match in re.finditer(rb'\b(E[A-Za-z0-9_]+)::([A-Za-z0-9_]+)\x00', data):
        name = match.group()[:-1].decode()
        prefix = match.group(1).decode()
        address = pe.address(match.start())
        if address:
            names[address] = dict(name=name, enum=prefix, offset=match.start())
            groups[prefix].append(address)
    # These UE constants have unqualified names. Keep their family explicit;
    # do not invent a qualified C++ enum name from a string prefix.
    for match in re.finditer(rb'(?<![A-Za-z0-9_])((?:HAlign|VAlign)_[A-Za-z0-9_]+)\x00', data):
        name = match.group(1).decode()
        address = pe.address(match.start())
        if address:
            names[address] = dict(name=name, enum='unqualified:' + name.split('_')[0], offset=match.start())
    pointers = defaultdict(list)
    for section in pe.sections:
        if section['name'] not in ('.rdata', '.data'):
            continue
        start, end = section['raw'], section['raw'] + section['raw_size']
        for offset in range(start, end - 15, 8):
            pointer = struct.unpack_from('<Q', data, offset)[0]
            if pointer in names:
                value = struct.unpack_from('<q', data, offset + 8)[0]
                if -(2 ** 31) <= value < 2 ** 31:
                    pointers[names[pointer]['enum']].append(offset)
    result, rejected = {}, []
    for prefix, offsets in pointers.items():
        candidates, visited = [], set()
        for offset in offsets:
            if offset in visited:
                continue
            start = offset
            while start >= 16:
                pointer, value = struct.unpack_from('<Qq', data, start - 16)
                if pointer not in names or names[pointer]['enum'] != prefix or not -(2 ** 31) <= value < 2 ** 31:
                    break
                start -= 16
            rows, cursor = [], start
            while cursor + 16 <= len(data) and len(rows) < 4096:
                pointer, value = struct.unpack_from('<Qq', data, cursor)
                if pointer not in names or names[pointer]['enum'] != prefix or not -(2 ** 31) <= value < 2 ** 31:
                    break
                rows.append(dict(name=names[pointer]['name'], value=value, name_offset=names[pointer]['offset'], descriptor_offset=cursor))
                visited.add(cursor)
                cursor += 16
            if len(rows) >= 2:
                candidates.append(rows)
        if len(candidates) == 1:
            result[prefix] = candidates[0]
        elif candidates:
            rejected.append(dict(enum=prefix, reason='multiple native arrays', candidates=len(candidates)))
    return result, rejected


def main():
    source = INSTALL / 'ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe'
    with source.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        result, rejected = extract(data)
        digest = hashlib.sha256(data).hexdigest()
    dest = ROOT / 'code-clues/native-enums.json'
    dest.write_text(json.dumps(dict(source=str(source), sha256=digest, enums=result, rejected=rejected,
        evidence='Contiguous PE name-pointer/int64 descriptor rows; not guessed from string order'), ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(dict(enums=len(result), members=sum(len(r) for r in result.values()), rejected=len(rejected))))
    for name, rows in result.items():
        if re.search(r'quest|tutorial|contents|lock|condition|shop', name, re.I):
            print(name, [(r['name'].split('::')[-1], r['value']) for r in rows][:40])


if __name__ == '__main__':
    main()
