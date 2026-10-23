"""Whole current ID 104 constructor/reader versus bounded portable decoder."""
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
from vampir_core.character_create_result import decode_character_create_result


def run():
    def load(name, filename):
        spec = importlib.util.spec_from_file_location(name, HERE / filename)
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        return tool
    extensions = load('create_result_extensions', 'replay-release-character-extensions.py')
    wire = load('create_result_wire', 'replay-character-list-extensions.py')
    h = extensions.make_harness(extra_addresses=(0x1456d8150, 0x1456b8a30))
    uc = h.uc
    packet = h.scratch + 0x16000
    record = packet + 0x18
    table = 0x14992a468
    for slot, target in ((0x20, 0x1456b8a30),):
        if struct.unpack_from('<Q', h.raw, h.image.offset(table - h.image.pe.base) + slot)[0] != target:
            raise ValueError('Create result reader table changed')
    def number(address, width): return int.from_bytes(uc.mem_read(address, width), 'little')
    def text(address):
        pointer, units, capacity = struct.unpack('<QII', bytes(uc.mem_read(address, 16)))
        if not 0 <= units <= capacity <= 2048: raise ValueError('Create result string bound')
        return bytes(uc.mem_read(pointer, (units - 1) * 2)).decode('utf-16le') if units else ''
    def read(body):
        if len(body) > 4096: raise ValueError('Create result input bound')
        h.string_heap[0] = h.scratch + 0x20000
        h.list_before_read()
        uc.mem_write(packet - 16, b'\xa5' * 0x1b0)
        if h.call(0x1456d8150, packet) != packet or number(packet, 8) != table:
            raise ValueError('Create result constructor binding changed')
        uc.mem_write(h.buffer, body + bytes(4096 - len(body)))
        h.call(h.ctor, h.obj)
        uc.mem_write(h.obj + 0x20, struct.pack('<QI', h.buffer, len(body)))
        uc.mem_write(h.obj + 0x30, struct.pack('<Q', h.buffer))
        accepted = h.call(0x1456b8a30, packet, h.obj, budget=2000000) & 255
        consumed = number(h.obj + 0x30, 8) - h.buffer
        if (bytes(uc.mem_read(packet - 16, 16)) != b'\xa5' * 16
                or bytes(uc.mem_read(packet + 0x188, 24)) != b'\xa5' * 24):
            raise ValueError('Create result packet canary changed')
        if not accepted: return dict(accepted=0, consumed=consumed)
        pointer, count, capacity = struct.unpack('<QII', bytes(uc.mem_read(record + 0xe0, 16)))
        if not 0 <= count <= capacity <= 8: raise ValueError('Create result item bound')
        fields = dict(strings=tuple(text(record + n) for n in (0x18, 0x50, 0xc8)),
            u32=tuple(number(record + n, 4) for n in (0x10, 0x30)),
            u16=tuple(number(record + n, 2) for n in (0x70, 0x72, 0x74, 0x76)),
            u64=tuple(number(record + n, 8) for n in (8, 0x28, 0x40, 0x48, 0x80, 0x88, 0x98, 0xa0, 0xa8, 0xf0, 0xf8, 0x100)),
            enum60=number(record + 0x60, 1), appearance=tuple(uc.mem_read(record + 0xb8, 10)),
            appearance_flags=tuple(uc.mem_read(record + 0xd8, 2)), flag108=bool(number(record + 0x108, 1)),
            appearance_items=tuple((number(pointer + i * 16 + 8, 4), number(pointer + i * 16 + 12, 1),
                number(pointer + i * 16 + 14, 2)) for i in range(count)),
            optional_items=h.optional_snapshot(record + 0x120) if number(record + 0x118, 1) else None)
        return dict(accepted=1, consumed=consumed, result_code=number(packet + 0x10, 4), fields=fields)
    records = [wire.base.record_bytes('', 0, 0, 0, 0), wire.base.record_bytes('NightRaven', 1, 1, 1, 1),
        wire.record_bytes(((0xffffffff, 255, 65535), (1, 2, 3))),
        wire.record_bytes(((1, 2, 3),), wire.optional_bytes(((1, 255, 2, 3, 4, 5), (9, 2, 3, 4, 5, 6), (1, 1, 7, 8, 9, 10)), 255))]
    cases, short = [], []
    for code in (0, 1, 58, 0xffffffff):
        for body_record in records:
            body = struct.pack('<I', code) + body_record
            actual = read(body)
            portable = decode_character_create_result(body, source_sha256=h.sha, max_payload_size=4096, max_extension_items=128)
            if (actual['accepted'] != 1 or actual['consumed'] != len(body) or actual['result_code'] != portable.result_code
                    or any(value != getattr(portable.record, key) for key, value in actual['fields'].items())):
                raise ValueError('Whole create result differs from portable record decoder')
            cases.append(dict(code=code, body_bytes=len(body), all_record_fields_match=True))
    for body_record in records:
        body = struct.pack('<I', 0) + body_record
        for size in range(len(body)):
            actual = read(body[:size])
            if actual['accepted'] or not 0 <= actual['consumed'] <= size:
                raise ValueError('Create result accepted a short prefix or crossed the input')
            try:
                decode_character_create_result(body[:size], source_sha256=h.sha, max_payload_size=4096, max_extension_items=128)
            except ValueError: pass
            else: raise ValueError('Portable create result accepted short input')
            short.append(dict(available=size, consumed=actual['consumed']))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)), cases=cases,
        short=short, native_execution=True, network_used=False,
        limits=['Whole constructor/reader ID 104 and nested record readers execute.',
            'Storage/copy/allocation/cleanup and input buffer are bounded fixtures.',
            'Nonzero result code still requires a full record structurally; no name_taken meaning inferred.',
            'No handler, actual response capture, producer, network, account or character creation.'])
    path = h.audit.save_snapshot(h.native.ROOT / 'code-clues/release-character-create-result', report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), cases=len(report['cases']), short=len(report['short']))))
