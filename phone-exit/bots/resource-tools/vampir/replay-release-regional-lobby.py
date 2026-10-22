"""Execute the current regional lobby setter with bounded FString fixtures."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def run():
    spec = importlib.util.spec_from_file_location('regional_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(archive)
    assign = 0x141441e40
    fixtures = {assign: None}
    h = archive.make_harness(extra_addresses=(0x14563a8f0,), fixtures=fixtures)
    evidence = h.comparison / 'details/run-93dc853f4d98/details.json'
    if h.audit.sha256(evidence) != '7b6da77bc68b3633340a1935a37e6447ff40468d1169ca26acadcf86f5b58da0':
        raise ValueError('Regional setter export changed')
    uc, x = h.uc, h.x
    context, global_string, enabled = h.scratch + 0x10000, 0x14b595040, 0x14b59502c
    fields = {0xd0: 'base.invalid', 0xe0: 'na00.invalid', 0xf0: 'eu00.invalid', 0x100: 'sg00.invalid'}

    def put(address, text, index):
        pointer = h.scratch + 0x12000 + index * 256
        if text is None:
            uc.mem_write(address, bytes(16))
        else:
            raw = (text + '\0').encode('utf-16le')
            uc.mem_write(pointer, raw)
            uc.mem_write(address, struct.pack('<QII', pointer, len(raw) // 2, len(raw) // 2))

    def text(address):
        pointer, count, capacity = struct.unpack('<QII', uc.mem_read(address, 16))
        if count == 0:
            return ''
        if not 1 <= count <= 64 or not h.scratch <= pointer < h.scratch + 0x40000 - count * 2:
            raise ValueError('Regional FString fixture bounds')
        return bytes(uc.mem_read(pointer, (count - 1) * 2)).decode('utf-16le')

    def copy(machine):
        destination, source = machine.reg_read(x.UC_X86_REG_RCX), machine.reg_read(x.UC_X86_REG_RDX)
        if destination != global_string or source not in {context + offset for offset in fields}:
            raise ValueError('Unexpected regional assignment')
        machine.mem_write(destination, bytes(machine.mem_read(source, 16)))
        sp = machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RAX, destination)
        machine.reg_write(x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(x.UC_X86_REG_RSP, sp + 8)

    fixtures[assign] = copy
    cases = []
    for region in (*range(9), 255):
        offset = {5: 0x100, 6: 0xe0, 7: 0xf0}.get(region, 0xd0)
        for regional in (None, '', fields[offset]):
            for base in (None, '', fields[0xd0]):
                for previous in ('', 'old0.invalid', regional or base or ''):
                    for flag in (0, 1):
                        uc.mem_write(context, b'\xa5' * 512)
                        for index, (field, value) in enumerate(fields.items()):
                            put(context + field, value, index)
                        put(context + 0xd0, base, 0)
                        if offset != 0xd0:
                            put(context + offset, regional, 4)
                        put(global_string, previous, 5)
                        uc.mem_write(enabled, bytes([flag]))
                        before = bytes(uc.mem_read(context, 512))
                        selected = (regional if offset != 0xd0 and regional else base) or ''
                        expected = selected if flag and selected else previous
                        changed = h.call(0x14563a8f0, context, region) & 255
                        if text(global_string) != expected or changed != int(expected != previous):
                            raise ValueError('Regional native selector differs')
                        if bytes(uc.mem_read(context, 512)) != before:
                            raise ValueError('Regional selector changed source config')
                        cases.append(dict(region=region, enabled=bool(flag), regional=regional,
                            base=base, previous=previous, selected=expected, changed=bool(changed)))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        native_execution=True, network_used=False, cases=cases,
        limits=['Whole 14563a8f0 executed; config strings, enabled guard and previous global are fixtures.',
            'FString assignment is a bounded descriptor-copy fixture; no allocator or real application globals.',
            'SetServerList field loading and UI region selection inspected statically, not executed here.',
            'No SDK, authentication, sockets, server selection or character creation.'])
    path = h.audit.save_snapshot(h.native.ROOT / 'code-clues/release-regional-lobby-replay', report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), cases=len(report['cases']))))
