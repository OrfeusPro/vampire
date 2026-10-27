"""Execute a whole declared packet writer against bounded archive fixtures.

This checks field projection and failure propagation, not UTF-8 or wire bytes.
"""
import hashlib
from pathlib import Path
import re
import struct

from importlib.util import spec_from_file_location, module_from_spec

HERE = Path(__file__).resolve().parent


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE/(name+'.py'))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify(context, root):
    sha = context['source_sha256']
    if not isinstance(sha, str) or not re.fullmatch('[0-9a-f]{64}', sha):
        raise ValueError('Full writer source SHA required')
    source = root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'
    if Path(context['source']).resolve() != source.resolve():
        raise ValueError('Writer source outside snapshot library')
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != sha:
        raise ValueError('Writer source SHA changed')
    native = load('build-native-entry-code')
    image = native.Image(raw)
    bindings = context['bindings']['bindings']
    writer, ctor, string = [int(bindings[k], 16) for k in ('writer', 'constructor', 'string-writer')]
    spec = context['contract'].get('writer_check_by_source', {}).get(sha, context['contract']['writer_check'])
    size, fields = spec['object_size'], spec['fields']
    widths = {'string': 16, 'u32': 4, 'u8': 1, 'u64': 8, 'bool': 1}
    if type(size) is not int or not 16 <= size <= 512 or not 1 <= len(fields) <= 32:
        raise ValueError('Writer fixture budget differs')
    occupied = set()
    for kind, offset in fields:
        if kind not in widths or type(offset) is not int or not 8 <= offset <= size-widths[kind]:
            raise ValueError('Writer fixture field differs')
        locations = set(range(offset, offset+widths[kind]))
        if locations & occupied:
            raise ValueError('Overlapping writer fixture fields')
        occupied.update(locations)
    table_spec = context['contract']['data_dependencies'][sha]['packet-table']
    table = int(table_spec['address'], 16)
    if table_spec['kind'] != 'vtable':
        raise ValueError('Writer packet table kind differs')
    rows = load('update-bindings').rows
    ctor_rows = rows(native, image, ctor)
    table_loads = [r for r in ctor_rows if r['mnemonic'] == 'lea' and
                   r['operands'].startswith('rax, [rip') and r['rip_references'] == [table]]
    if len(table_loads) != 1:
        raise ValueError('Writer constructor table link differs')
    table_offset = image.offset(table-image.pe.base)
    if struct.unpack_from('<Q', raw, table_offset+0x10)[0] != writer:
        raise ValueError('Writer table slot differs')
    body = rows(native, image, writer)
    calls = [r for r in body if r['call']]
    if len(calls) != len(fields) or any(r['direct_target'] not in (None, string) for r in calls):
        raise ValueError('Unreviewed writer call set')
    if string in {r['address'] for r in body}:
        raise ValueError('Writer helper overlaps body')
    exports = {}
    for item in context['exports']:
        if item.get('address') != hex(writer):
            continue
        if item.get('state') != 'ready':
            raise ValueError('Writer export is not ready')
        for artifact in item['artifacts']:
            path = Path(artifact['path']).resolve()
            if not path.is_relative_to((root/'ghidra/request-exports'/sha).resolve()) or path.name != 'details.json':
                raise ValueError('Writer export outside source library')
            exports[path.parent.name] = artifact['sha256']
    h = load('update-native-harness').make_harness(
        dict(context, helpers={'memcpy': spec['memcpy']},
             verify_whole_exports=spec.get('verify_whole_exports', False)), exports, {writer}, root=root)
    packet, archive, archive_table, text = [h.scratch+n for n in (0x1000, 0x2000, 0x3000, 0x4000)]
    fixture_base = h.scratch+0x5000
    slots = {'u32': 0xc8, 'u8': 0xe0, 'u64': 0xb8, 'bool': 0xf0}
    state = {}

    def intercept(kind):
        def handler(machine):
            a, b = [machine.reg_read(r) for r in (h.x.UC_X86_REG_RCX, h.x.UC_X86_REG_RDX)]
            number = len(state['seen'])
            if a != archive or number >= len(fields):
                raise ValueError('Unexpected writer archive call')
            expected_kind, offset = fields[number]
            expected = packet+offset if kind == 'string' else state['values'][number]
            if kind != expected_kind or b != expected:
                raise ValueError('Writer field order or argument differs')
            state['seen'].append([kind, offset])
            h.finish(0 if number == state['fail_at'] else 1)
        return handler

    h.add_fixture(string, intercept('string'))
    for number, (kind, slot) in enumerate(slots.items()):
        target = fixture_base+number*0x10
        h.uc.mem_write(archive_table+slot, struct.pack('<Q', target))
        h.add_fixture(target, intercept(kind))
    cases = []
    for poison in (0, 0x55, 0xaa, 0xff):
        contents = bytearray([poison]*size)
        struct.pack_into('<Q', contents, 0, table)
        values = []
        for number, (kind, offset) in enumerate(fields):
            value = ((0xfedcba9876543210+number) if kind == 'u64' else
                     (0x89abcdef+number) if kind == 'u32' else
                     (0x80+number) & 255)
            if kind == 'string':
                # The string helper is a fixture; only its descriptor address is tested.
                data = ('field-'+str(number)+'-Ж').encode('utf-16le')+b'\0\0'
                pointer = text+number*0x80
                h.uc.mem_write(pointer, data)
                struct.pack_into('<QII', contents, offset, pointer, len(data)//2, len(data)//2)
            else:
                contents[offset:offset+widths[kind]] = value.to_bytes(widths[kind], 'little')
            values.append(value)
        for fail_at in range(-1, len(fields)):
            h.uc.mem_write(packet-16, b'\xa5'*16+bytes(contents)+b'\x5a'*16)
            archive_bytes = struct.pack('<Q', archive_table)+b'\xa6'*248
            h.uc.mem_write(archive-16, b'\xa5'*16+archive_bytes+b'\x5a'*16)
            state.update(seen=[], values=values, fail_at=fail_at)
            h.uc.reg_write(h.x.UC_X86_REG_RDX, archive)
            h.uc.reg_write(h.x.UC_X86_REG_RBX, 0x123456789abcdef0)
            h.uc.reg_write(h.x.UC_X86_REG_RDI, 0xfedcba9876543210)
            result = h.call(writer, packet, budget=4096) & 255
            expected = fields if fail_at < 0 else fields[:fail_at+1]
            if state['seen'] != expected or result != int(fail_at < 0):
                raise ValueError('Writer failure propagation differs')
            if bytes(h.uc.mem_read(packet-16, size+32)) != b'\xa5'*16+bytes(contents)+b'\x5a'*16:
                raise ValueError('Writer packet or canaries changed')
            if bytes(h.uc.mem_read(archive-16, 288)) != b'\xa5'*16+archive_bytes+b'\x5a'*16:
                raise ValueError('Writer archive or canaries changed')
            if (h.uc.reg_read(h.x.UC_X86_REG_RBX), h.uc.reg_read(h.x.UC_X86_REG_RDI),
                    h.uc.reg_read(h.x.UC_X86_REG_RSP)) != (
                    0x123456789abcdef0, 0xfedcba9876543210, h.scratch+0x38008):
                raise ValueError('Writer ABI preservation differs')
            cases.append(dict(poison=poison, fail_at=fail_at, calls=len(expected), result=result, guards=True))
    return dict(schema=1, source_sha256=sha, method='bounded_native',
        binding=dict(writer=hex(writer), constructor=hex(ctor), packet_table=hex(table),
                     table_slot=0x10, string_helper=hex(string)),
        fields=fields, cases=cases, evidence=h.evidence,
        network_used=False, profile_activated=False,
        limits=['Whole writer executed; archive scalar methods and string helper are bounded fixtures.',
                'Does not execute UTF-8 conversion, archive encoding, send framing, preparation or result reader.',
                'Boolean helper inputs are checked as raw bytes; wire normalization is not established.'])
