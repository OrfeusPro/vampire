"""Execute current NID extension branches with explicit converter/map fixtures."""
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT, BEGIN, END = 0x1450e3c80, 0x1450e43d3, 0x1450e48aa
EXPORTS = {'run-988ec3bf8f0a': 'ac636f8488eb37a37646b4213878b4db9bb4c7567e5eddb2569195e346c0f6fd'}
AUTH_TYPES = {0: 'signin', 1: 'linkidp', 2: 'withdraw', 3: 'agreements', 4: 'signin', 5: 'linkidp'}
# Six short cleanup tails are absent from Ghidra's instruction list despite
# completed decompilation. Explicit bytes/boundaries are pinned to this SHA.
TAILS = {0x1450e463f: '488b8d40010000e955020000',
    0x1450e46b8: '488b8d70010000e9dc010000',
    0x1450e4731: '488b8da0010000e963010000',
    0x1450e47aa: '488b8dd0010000e9ea000000',
    0x1450e4823: '488b8d00020000eb74', 0x1450e4899: '488b8d30020000'}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def replay(root=None):
    harness = load('nid_extensions_harness', HERE/'native-request-harness-11316.py')
    h = harness.make_harness(EXPORTS, {ROOT}, leaves=TAILS, root=root)
    rbp, owner, vtable, obj = [h.scratch+n for n in (0x10000, 0x18000, 0x19000, 0x19100)]
    virtual = h.scratch+0x3e000
    heap, options, pairs, events = [0], {}, [], []
    table = 0x1450e4e14
    page = table & ~4095
    # The switch table is data, never executable code. Validate all six entries.
    off = h.image.offset(table-h.image.pe.base)
    targets = struct.unpack_from('<6I', h.raw, off)
    if targets != (0x50e45d2, 0x50e464b, 0x50e46c4, 0x50e473d, 0x50e47b6, 0x50e482c):
        raise ValueError('NID authType jump table differs')
    try: h.uc.mem_read(table, 24)
    except Exception:
        h.uc.mem_map(page, 4096)
        start = h.image.offset(page-h.image.pe.base)
        h.uc.mem_write(page, h.raw[start:start+4096])

    def put(destination, value):
        if not h.scratch <= destination <= h.scratch+0x40000-16:
            raise ValueError('NID extension destination bound')
        data = (value+'\0').encode('utf-16le')
        if len(data) > 256 or heap[0]+len(data) >= h.scratch+0x2e000:
            raise ValueError('NID extension heap bound')
        pointer = heap[0]; heap[0] += (len(data)+15)&~15
        h.uc.mem_write(pointer, data)
        h.uc.mem_write(destination, struct.pack('<QII', pointer, len(data)//2, len(data)//2))

    def text(address):
        if not h.scratch <= address <= h.scratch+0x40000-16:
            raise ValueError('NID extension object bound')
        pointer, count, capacity = struct.unpack('<QII', bytes(h.uc.mem_read(address, 16)))
        if not 1 <= count <= capacity <= 128 or not h.scratch <= pointer <= h.scratch+0x40000-count*2:
            raise ValueError('NID extension string bound')
        data = bytes(h.uc.mem_read(pointer, count*2))
        if data[-2:] != bytes(2): raise ValueError('NID extension terminator differs')
        return data[:-2].decode('utf-16le')

    def fixture(machine):
        at = machine.reg_read(h.x.UC_X86_REG_RIP)
        a, b, c, d = [machine.reg_read(r) for r in
            (h.x.UC_X86_REG_RCX, h.x.UC_X86_REG_RDX, h.x.UC_X86_REG_R8, h.x.UC_X86_REG_R9)]
        result = 0
        if at in (0x141426950, 0x141426b30):
            width = 1 if at == 0x141426950 else 2
            offset = h.image.offset(b-h.image.pe.base)
            raw = h.raw[offset:offset+256]
            end = next((i for i in range(0, 256-width+1, width) if raw[i:i+width] == bytes(width)), None)
            if end is None: raise ValueError('NID extension literal bound')
            put(a, raw[:end].decode('ascii' if width == 1 else 'utf-16le')); result = a
        elif at == 0x1450ed350:
            # This converter is deliberately opaque: capture byte, use a tagged value.
            events.append(['converter', b & 255]); put(a, 'fixture-web-'+str(b & 255)); result = a
        elif at == 0x1414632f0:
            if a != rbp+0x450 or d != 0: raise ValueError('NID extension map binding differs')
            key, value = struct.unpack('<QQ', bytes(machine.mem_read(c, 16)))
            pairs.append([text(key), text(value)])
        elif at == 0x1450e9720:
            if b != 0x1234 or c & 255 != options['web']: raise ValueError('NID optional getter binding differs')
            machine.mem_write(a, struct.pack('<QQ', obj if options['optional'] else 0, 0))
            events.append(['optional', c & 255]); result = a
        elif at == virtual:
            if a != obj or b != rbp+0x410: raise ValueError('NID virtual receiver differs')
            result = b; events.append(['virtual'])
        elif at == 0x144488e50:
            if a != rbp+0x410 or b != rbp+0x360 or c & 255 != 1:
                raise ValueError('NID optional serializer binding differs')
            put(b, 'fixture-extra'); result = b
        elif at == 0x144476300:
            if a != rbp+0x410: raise ValueError('NID optional cleanup binding differs')
        elif at == 0x141483080:
            if not h.scratch+0x20000 <= a < heap[0]: raise ValueError('NID free fixture bound')
        else: raise ValueError('Unreviewed NID extension fixture')
        h.finish(result)

    for at in (0x141426950, 0x141426b30, 0x1450ed350, 0x1414632f0,
               0x1450e9720, virtual, 0x144488e50, 0x144476300, 0x141483080):
        h.add_fixture(at, fixture)
    cases = []
    for poison, mode, web, optional in itertools.product((0, 0x55, 0xaa, 0xff),
            (0, 1, 2, 3, 4, 5, 6, 0xffffffff), (0, 1, 2, 255), (False, True)):
        heap[0] = h.scratch+0x20000; pairs.clear(); events.clear()
        options.update(web=web, optional=optional)
        h.uc.mem_write(rbp-0x200, bytes([poison])*0xa00)
        h.uc.mem_write(owner+0x150, struct.pack('<I', mode))
        h.uc.mem_write(owner+0x28, struct.pack('<Q', 0x1234))
        h.uc.mem_write(0x14b5d5268, bytes([web]))
        h.uc.mem_write(obj, struct.pack('<Q', vtable))
        h.uc.mem_write(vtable+8, struct.pack('<Q', virtual))
        for reg, value in ((h.x.UC_X86_REG_RSP, rbp-0x100),
                (h.x.UC_X86_REG_RBP, rbp), (h.x.UC_X86_REG_R13, owner)):
            h.uc.reg_write(reg, value)
        h.uc.emu_start(BEGIN, END, count=10000)
        if h.uc.reg_read(h.x.UC_X86_REG_RIP) != END: raise ValueError('NID extension instruction budget')
        special = mode in (4, 5)
        expected = [['webViewType', 'fixture-web-'+str(web if special else 0)]]
        if special and optional: expected.append(['credential', 'fixture-extra'])
        if mode in AUTH_TYPES: expected.append(['authType', AUTH_TYPES[mode]])
        if pairs != expected: raise ValueError('NID extension pairs differ: '+repr((mode, pairs, expected)))
        expected_events = [['converter', web if special else 0]]
        if special:
            expected_events.append(['optional', web])
            if optional: expected_events.append(['virtual'])
        if events != expected_events: raise ValueError('NID extension call gates differ')
        if bytes(h.uc.mem_read(rbp-0x200, 16)) != bytes([poison])*16 or bytes(h.uc.mem_read(rbp+0x7f0, 16)) != bytes([poison])*16:
            raise ValueError('NID extension canaries changed')
        cases.append(dict(mode=mode, web=web, optional=optional, poison=poison,
                          pairs=pairs.copy(), events=events.copy(), canaries_unchanged=True))
    return dict(schema=1, source=str(h.source), source_sha256=h.sha, evidence=h.evidence,
        start=hex(BEGIN), stop=hex(END), cases=cases, native_execution=True, network_ready=False,
        dependencies={n: hashlib.sha256((HERE/n).read_bytes()).hexdigest() for n in
            ('replay-nid-extensions-11316.py', 'native-request-harness-11316.py', 'build-native-entry-code.py',
             'extract-native-enums.py', 'build-object-zero-init-code.py')},
        limits=['Native extension dispatch and authType literals execute; map insertion is a capture fixture.',
            'webV converter, optional getter/virtual object/serializer/cleanup and FString storage/free are fixtures.',
            'The optional shared pointer has no reference controller; destructor branches are not exercised.',
            'Earlier gates, final query encoding, browser and authentication are not executed.'])


if __name__ == '__main__':
    report = replay()
    native = load('nid_extensions_root', HERE/'build-native-entry-code.py')
    audit = load('nid_extensions_snapshot', HERE/'audit-client-release.py')
    path = audit.save_snapshot(native.ROOT/'code-clues/nid-extensions-11316', report)
    print(json.dumps(dict(report=str(path), cases=len(report['cases']))))
