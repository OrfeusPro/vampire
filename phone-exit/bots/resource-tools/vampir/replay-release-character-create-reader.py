"""Whole current ID 103 reader with bounded native string and appearance readers."""
import importlib.util
import itertools
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def run():
    spec = importlib.util.spec_from_file_location('create_reader_extensions', HERE / 'replay-release-character-extensions.py')
    extensions = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(extensions)
    h = extensions.make_harness(extra_addresses=(0x1456d8120, 0x1456b83a0, 0x145789090),
        extra_leaves=(0x145784790,))
    uc = h.uc
    packet = h.scratch + 0x15000
    data, appearance = packet + 0x10, packet + 0x30
    # Check exact constructor bindings in the current image, not a name hint.
    for table, reader in ((0x14992a3a8, 0x1456b83a0), (0x14992a360, 0x145789090),
                          (0x149921fb0, 0x145788d00)):
        offset = h.image.offset(table - h.image.pe.base)
        if struct.unpack_from('<Q', h.raw, offset + 0x20)[0] != reader:
            raise ValueError('Create reader table binding changed')
    def number(address, width):
        return int.from_bytes(uc.mem_read(address, width), 'little')
    def text(address):
        pointer, units, capacity = struct.unpack('<QII', bytes(uc.mem_read(address, 16)))
        if not 0 <= units <= capacity <= 128:
            raise ValueError('Create FString output bound')
        return bytes(uc.mem_read(pointer, (units - 1) * 2)).decode('utf-16le') if units else ''
    def read(body):
        h.string_heap[0] = h.scratch + 0x20000
        h.list_before_read()
        uc.mem_write(packet - 16, b'\xa5' * 0xa0)
        if h.call(0x1456d8120, packet) != packet:
            raise ValueError('Create constructor return changed')
        if (number(packet, 8), number(data, 8), number(appearance, 8)) != (
                0x14992a3a8, 0x14992a360, 0x149921fb0):
            raise ValueError('Create constructor object bindings changed')
        h.call(h.ctor, h.obj)
        uc.mem_write(h.buffer, body + bytes(512 - len(body)))
        uc.mem_write(h.obj + 0x20, struct.pack('<QI', h.buffer, len(body)))
        uc.mem_write(h.obj + 0x30, struct.pack('<Q', h.buffer))
        accepted = h.call(0x1456b83a0, packet, h.obj, budget=200000) & 255
        consumed = number(h.obj + 0x30, 8) - h.buffer
        if bytes(uc.mem_read(packet - 16, 16)) != b'\xa5' * 16 or bytes(uc.mem_read(packet + 0x70, 32)) != b'\xa5' * 32:
            raise ValueError('Create packet canary changed')
        if not accepted:
            return dict(accepted=0, consumed=consumed)
        pointer, count, capacity = struct.unpack('<QII', bytes(uc.mem_read(appearance + 0x30, 16)))
        if not 0 <= count <= capacity <= 8:
            raise ValueError('Create appearance item bound')
        items = [(number(pointer + index * 16 + 8, 4), number(pointer + index * 16 + 12, 1),
                  number(pointer + index * 16 + 14, 2)) for index in range(count)]
        return dict(accepted=1, consumed=consumed, raw_class=number(data + 8, 4), name=text(data + 0x10),
            appearance=list(uc.mem_read(appearance + 8, 10)), appearance_text=text(appearance + 0x18),
            flags=[number(appearance + 0x28, 1), number(appearance + 0x29, 1)], items=items)
    def wire_text(value):
        encoded = value.encode('utf-8')
        return struct.pack('<H', len(encoded)) + encoded
    cases, prefixes = [], []
    for raw_class, name, appearance_text, variant in itertools.product(
            (0, 0x12345678, 0xffffffff), ('', 'NightRaven', 'Ж界🙂'), ('', '{"x":1}'), (0, 1)):
        values = [0] * 10 if not variant else [255, 1, 2, 3, 4, 5, 6, 7, 8, 255]
        items = [] if not variant else [(0x12345678, 255, 0xffff), (0, 0, 1)]
        flag, byte = (0, 0) if not variant else (255, 255)
        body = (struct.pack('<I', raw_class) + wire_text(name) + bytes(values) + wire_text(appearance_text)
            + bytes((flag, byte)) + struct.pack('<H', len(items))
            + b''.join(struct.pack('<IBH', *item) for item in items))
        expected = dict(accepted=1, consumed=len(body), raw_class=raw_class, name=name,
            appearance=[min(values[0], 2), *values[1:]], appearance_text=appearance_text,
            flags=[int(bool(flag)), byte], items=[(a, min(b, 45), c) for a, b, c in items])
        actual = read(body)
        if actual != expected:
            raise ValueError('Whole create reader differs: ' + repr((actual, expected)))
        cases.append(dict(body_bytes=len(body), **actual))
        for size in range(len(body)):
            short = read(body[:size])
            if short['accepted'] or not 0 <= short['consumed'] <= size:
                raise ValueError('Create reader accepted a short prefix or crossed its input')
            prefixes.append(dict(body_bytes=len(body), available=size, **short))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        native_execution=True, network_used=False, cases=cases, short_prefixes=prefixes,
        constructor_leaf=next(leaf for leaf in h.leaves if leaf['address'] == '0x145784790'),
        limits=['Whole ID 103 constructor, reader, CreateData and appearance readers execute.',
            'Input archive buffer, bounded storage/copy/cleanup and allocation are fixtures.',
            'Raw class integers, names, appearance bytes/text and items are synthetic, not valid game choices.',
            'No writer, producer/JSON generator, server name policy, result ID 104 or live creation is proven.'])
    path = h.audit.save_snapshot(h.native.ROOT / 'code-clues/release-character-create-reader', report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), cases=len(report['cases']), short_prefixes=len(report['short_prefixes']))))
