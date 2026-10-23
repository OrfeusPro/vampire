"""Execute preset initializer, context push and the complete constructor chain."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def run(*, completion=False):
    spec = importlib.util.spec_from_file_location('preset_initializer_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec); spec.loader.exec_module(archive)
    hooks = dict.fromkeys((0x141483610, 0x1417d69b0, 0x14174cb20, 0x14154ad50, 0x1487eac40))
    completion_roots = ()
    if completion:
        hooks.update(dict.fromkeys((0x141640fc0, 0x1416212b0, 0x141630980,
            0x1416314d0, 0x141404a00, 0x1416267a0, 0x141421c50)))
        completion_roots = (0x1417cbe90, 0x141638a20, 0x141633290)
    h = archive.make_harness(extra_addresses=(0x1417ca780, 0x1417d2880, 0x1454d6800,
        0x143b5fa80, 0x1417cbc10, 0x1417dd530, 0x1417dda00,
        0x14174fce0, 0x14174ba30, 0x14174cc70, *completion_roots), fixtures=hooks)
    uc, x = h.uc, h.x
    def at(address, count):
        offset = h.image.offset(address - h.image.pe.base)
        return h.raw[offset:offset + count]
    def map_source(address):
        page = address & ~4095
        if not any(a <= page <= b for a, b, _ in uc.mem_regions()):
            uc.mem_map(page, 4096); uc.mem_write(page, at(page, 4096))
    exports = {}
    for name, expected in (
        ('run-e2336a990daa', '00237aa7f19cede98a282985961c256788cbc889adb7082f7d8bcb7e4a23ddaa'),
        ('run-086e862edcea', '6ebabc3c6c14098f757245210c336b7ed1bd64607ab76e8e29f1f8473e5e9131'),
        ('run-fbf8f7b13fe2', '4cb90c2fe07dda625a360e2098c31d157caa132c255b6d4495aa008397daa103'),
        ('run-d156ab446138', '269c2a6b770cbc23877e87eef0c307f437bacefc5546a6fe7d432dedf95730f9'),
        ('run-29d6ad1c7c55', '4310f3e2818acc70b48594790eea46aa9f996529ceaf782fce06ba36cd60d2e2'),
        ('run-c1cdaeaa2d5d', '91313b2e519a3672685d7895ec3525cf7c61dd5b0446c38733ba8dbf817b4941'),
        ('run-2e4ce3671ec8', '227beefd32196b24cbf89f2d81e6195bac686005d67f6fff97e77c2ecc0998cf')):
        path = h.comparison / 'details' / name / 'details.json'
        if h.audit.sha256(path) != expected: raise ValueError('Preset initializer export changed')
        exports[str(path)] = expected
    if completion:
        path = h.comparison / 'details/run-0fc58b2f30f3/details.json'
        expected = '5866927a72e3deed60490ccc12bebc63dffc47a4fad916dca4fc6ae65c84c844'
        if h.audit.sha256(path) != expected: raise ValueError('Completion export changed')
        exports[str(path)] = expected
    noop = 0x141403c50
    if at(noop, 3) != bytes.fromhex('c20000'): raise ValueError('Empty virtual method changed')
    map_source(noop); h.ranges.append((noop, noop + 3))
    for address, code in ((0x14140e3d0, '488d4108c3'), (0x14142a6c0, '48ff21'),
                          (0x141632690, '448b4108f7d28bc24123c0413bc07404f0215108c3')):
        expected = bytes.fromhex(code)
        if at(address, len(expected)) != expected: raise ValueError('Reviewed postconstruct leaf changed')
        map_source(address); h.ranges.append((address, address + len(expected)))
    map_source(0x1489e6448)
    if completion:
        address, code = 0x1417d7090, bytes.fromhex('488b01488b4010c3')
        if at(address, len(code)) != code: raise ValueError('Initializer object-class leaf changed')
        map_source(address); h.ranges.append((address, address + len(code)))
    bindings = []
    for table, offset, expected in ((0x1498514e8, 0x50, 0x1417dda00),
        (0x1498514e8, 0x58, noop), (0x1498514e8, 0x60, noop),
        (0x148a4c688, 0x388, noop), (0x148a4c688, 0x3a0, noop), (0x148a4c688, 0x3b8, noop)):
        if struct.unpack('<Q', at(table + offset, 8))[0] != expected:
            raise ValueError('Preset/UClass virtual binding changed')
        map_source(table + offset)
        bindings.append(dict(table=hex(table), offset=offset, target=hex(expected)))
    obj, init, cls, context, entries, defaults = [h.scratch + n for n in
        (0x10000, 0x11000, 0x12000, 0x13000, 0x14000, 0x15000)]
    gs = 0x30000000
    uc.mem_map(gs, 0x110000); uc.reg_write(x.UC_X86_REG_GS_BASE, gs)
    uc.mem_write(gs + 0x58, struct.pack('<Q', gs + 0x1000))
    uc.mem_write(gs + 0x1000, struct.pack('<Q', gs + 0x2000))
    # Resolve the TLS index operand from the reviewed whole function, not an OS
    # address guessed from another build.
    details = json.loads((h.comparison / 'details/run-e2336a990daa/details.json').read_text())
    rows = details['functions'][0]['instructions']
    # The exact operand below is verified against the source instruction bytes
    # via the structured export and the full EXE SHA.
    tls_operand = next(r for r in rows if r['text'].startswith('MOV ECX,dword ptr [') and r['references'])
    tls_address = int(tls_operand['references'][0], 16)
    uc.mem_write(tls_address, bytes(4))
    uc.mem_write(gs + 0x2000 + 0x101184, struct.pack('<i', 1))
    uc.mem_write(0x14b3e1b28, struct.pack('<i', 1))
    uc.mem_write(0x14b3cf484, struct.pack('<i', 1))
    uc.mem_write(0x14b3ce8c0, bytes(1))  # Explicit object-registration feature flag fixture.
    if completion: uc.mem_write(0x14b3c6b5c, struct.pack('<i', 1))
    queue_context, queued, parent = [h.scratch + n for n in (0x19000, 0x1a000, 0x1b000)]
    events = []
    def fixture(machine):
        address = machine.reg_read(x.UC_X86_REG_RIP)
        events.append(hex(address))
        result = context if address == 0x141483610 else init if address == 0x1417d69b0 else 0
        if completion:
            a, b, c = [machine.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
            if address == 0x141483610 and b in (0x14b0ce58c, 0x14b0ce588): result = queue_context + 0x108
            elif address == 0x141640fc0: result = int(flags != 0)
            elif address == 0x1416314d0:
                if a != queue_context or b != defaults or c != init: raise ValueError('Deferred queue inputs differ')
                machine.mem_write(queued, bytes(machine.mem_read(init, 0x220))); result = queued
            elif address == 0x141404a00:
                if a or b: raise ValueError('Unexpected completion delegate array cleanup')
            elif address == 0x1416267a0:
                if a != init + 0x20 or b: raise ValueError('Unexpected initializer member cleanup')
            elif address == 0x141421c50:
                if a != init + 0x1f0: raise ValueError('Unexpected empty completion delegate cleanup')
        machine.reg_write(x.UC_X86_REG_RAX, result)
        sp = machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(x.UC_X86_REG_RSP, sp + 8)
    for address in hooks: hooks[address] = fixture
    cases, post_cases = [], []
    for poison in (0, 0xa5, 0xff):
        for callback in (False, True):
            for flags in (0, 1, 2, 3):
                input_flags = 0 if completion else flags
                events.clear()
                uc.mem_write(obj - 16, bytes((poison,)) * (0x78 + 32))
                uc.mem_write(obj + 0x10, struct.pack('<Q', cls))
                uc.mem_write(cls, bytes(0x400)); uc.mem_write(cls, struct.pack('<Q', 0x148a4c688))
                uc.mem_write(init - 16, b'\xa5' * (0x220 + 32))
                uc.mem_write(context, bytes(0x40))
                uc.mem_write(context + 0x10, struct.pack('<QII', entries, 0, 8))
                uc.mem_write(context + 0x30, struct.pack('<Q', defaults))
                uc.mem_write(entries, bytes(64))
                uc.mem_write(0x14b3e1b25, bytes((int(callback),)))
                # Fifth Windows x64 argument follows return address and shadow space.
                uc.mem_write(h.stack + 0x28, bytes(8))
                if h.call(0x1417ca780, init, obj, defaults, input_flags, budget=100000) != init:
                    raise ValueError('Initializer return differs')
                if bytes(uc.mem_read(init + 0x10, 4)) != bytes((input_flags & 1, (input_flags >> 1) & 1, 1, 0)):
                    raise ValueError('Initializer flags differ')
                if struct.unpack('<Q', bytes(uc.mem_read(context + 0x30, 8)))[0] != obj:
                    raise ValueError('Context did not push object')
                if struct.unpack('<Q', bytes(uc.mem_read(entries, 8)))[0] != init:
                    raise ValueError('Context did not push initializer')
                h.call(0x1454d6800, init, budget=100000)
                if bytes(uc.mem_read(obj + 0x30, 36)) != bytes((poison,)) * 36:
                    raise ValueError('Constructor chain changed preset integer fields')
                if struct.unpack('<7f', bytes(uc.mem_read(obj + 0x54, 28))) != (0.5,) * 7:
                    raise ValueError('Preset float constructor defaults differ')
                if bytes(uc.mem_read(obj + 0x70, 1)) != b'\0' or bytes(uc.mem_read(init + 0x12, 1)) != b'\0':
                    raise ValueError('Voice or native base initializer completion differs')
                for address in (obj - 16, obj + 0x78):
                    if bytes(uc.mem_read(address, 16)) != bytes((poison,)) * 16: raise ValueError('Preset guard changed')
                if bytes(uc.mem_read(init - 16, 16)) != b'\xa5' * 16 or bytes(uc.mem_read(init + 0x220, 16)) != b'\xa5' * 16:
                    raise ValueError('Initializer guard changed')
                if events != ['0x141483610', '0x1417d69b0', '0x14174cb20']:
                    raise ValueError('Unexpected constructor fixture calls')
                cases.append(dict(poison=poison, callback_enabled=callback, flags=input_flags,
                    integer_fields_unchanged=True, floats=[0.5] * 7, voice=0,
                    initializer_base_complete=True, guards_unchanged=True))
                if flags == 0 or completion:
                    # Current native preset CDO: no config flag, no subobjects;
                    # source-bound vtables are used, not substituted callbacks.
                    uc.mem_write(cls + 0xd4, struct.pack('<I', 0x10000001))
                    uc.mem_write(cls + 0x110, struct.pack('<Q', obj))
                    uc.mem_write(obj + 8, struct.pack('<II', 0x231, 0))
                    chunks, chunk = h.scratch + 0x16000, h.scratch + 0x17000
                    uc.mem_write(chunks, struct.pack('<Q', chunk)); uc.mem_write(chunk, bytes(24))
                    uc.mem_write(0x14b3e1c30, struct.pack('<Q', chunks))
                    uc.mem_write(0x14b3e1c44, struct.pack('<I', 1))
                    if completion:
                        uc.mem_write(cls + 0x40, struct.pack('<Q', parent)); uc.mem_write(parent, bytes(0x78))
                        uc.mem_write(parent + 0xc, struct.pack('<I', 1))
                        uc.mem_write(0x14b3e1c44, struct.pack('<I', 2))
                        uc.mem_write(chunk + 24, bytes(24)); uc.mem_write(queued, bytes(0x220))
                        uc.mem_write(chunk + 8, struct.pack('<I', (1 << 31) | ((1 << 25) if flags == 2 else 0)))
                        uc.mem_write(0x14b3c6b58, bytes((int(flags == 1),)))
                    before = bytes(uc.mem_read(obj - 16, 0x78 + 32))
                    events.clear(); h.call(0x1417cbe90 if completion else 0x1417dd530, init, budget=200000)
                    deferred = completion and flags == 3
                    expected = bytearray(before)
                    if not deferred: struct.pack_into('<I', expected, 16 + 8, 0x31)
                    if bytes(uc.mem_read(obj - 16, len(expected))) != bytes(expected):
                        raise ValueError('Postconstruct changed preset fields or guards')
                    if bytes(uc.mem_read(init, 8)) != (struct.pack('<Q', obj) if deferred else bytes(8)):
                        raise ValueError('Completion object pointer differs')
                    if not completion and events != ['0x1487eac40', '0x14154ad50']:
                        raise ValueError('Unexpected postconstruct fixture calls')
                    if completion:
                        if bytes(uc.mem_read(context + 0x18, 4)) != bytes(4) or bytes(uc.mem_read(context + 0x28, 4)) != bytes(4):
                            raise ValueError('Completion did not pop context counts')
                        if struct.unpack('<Q', bytes(uc.mem_read(context + 0x30, 8)))[0] != defaults:
                            raise ValueError('Completion did not restore previous context object')
                        if int.from_bytes(uc.mem_read(chunk + 8, 4), 'little') & (1 << 31):
                            raise ValueError('Completion did not clear object-array internal flag')
                        if deferred and bytes(uc.mem_read(queued + 0x13, 1)) != b'\x01':
                            raise ValueError('Completion did not mark queued initializer')
                        if ('0x1416314d0' in events) != deferred:
                            raise ValueError('Unexpected deferred queue selection')
                    post_cases.append(dict(poison=poison, callback_enabled=callback,
                        flags_before=0x231, flags_after=0x231 if deferred else 0x31, integer_fields_unchanged=True,
                        all_other_object_bytes_unchanged=True, initializer_object_cleared=not deferred,
                        route={0: 'immediate_dependency_false', 1: 'immediate_setting',
                            2: 'immediate_class_ready', 3: 'deferred'}[flags] if completion else 'direct_postconstruct',
                        context_popped=completion, queued_initializer_marked=deferred, fixture_calls=events.copy()))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        native_execution=True, network_used=False, cases=cases, postconstruct_cases=post_cases, virtual_bindings=bindings,
        ghidra_exports=exports, tls_index_operand=hex(tls_address),
        dependencies={name: h.audit.sha256(HERE / name) for name in
            ('replay-release-archive-input.py', 'build-native-entry-code.py',
             'extract-native-enums.py', 'build-object-zero-init-code.py', 'requirements-native.txt')},
        limits=['Whole initializer/context push, preset constructor, DataAsset and UObject constructors execute.',
            'TLS/context lookup, current initializer lookup and UObject bookkeeping hook are fixtures; stack preallocated, TLS epoch cached.',
            'Both initializer feature callback states execute the source-bound empty UClass virtual method; object registration feature flag is disabled.',
            'Six flags=0 native CDO postconstruct cases execute whole 1417dd530, object post-init 1417dda00, config helper early return, validation, cached TLS helper and ClearFlags leaf.',
            'Native class flags/no config, empty subobjects, object-array/TLS metadata are fixtures; feature query and security-cookie check are fixtures. Dynamic config/subobject paths not covered.',
            'The wrapper 1417cbe90, full allocation/CDO creation and asset load are not executed.',
            'Zero-poison case starts with zero memory fixture, not native allocator; omitted serialized integers remain unresolved.',
            'No game, authorization or network.'])
    if completion:
        report['completion_entry_sha256'] = h.audit.sha256(HERE / 'replay-release-preset-completion.py')
        report['limits'] = [
            'Whole initializer/base constructors, completion wrapper, native completion selector, CDO readiness query and immediate postconstruct execute.',
            'Boolean dependency 141640fc0, TLS/context lookups, queue lookup/insertion, empty-container cleanup, UObject bookkeeping, feature query and security check are fixtures.',
            'Queue insertion copies the initializer fixture; native wrapper marks the returned copy deferred. Queue storage implementation and later deferred execution are not covered.',
            'Metadata/class flags/no config/empty subobjects are fixtures. Cached TLS only; cold initialization and other object kinds not covered.',
            'Allocation and asset deserialization remain outside this execution; omitted preset integers stay unresolved.',
            'No game, authorization or network.']
    path = h.audit.save_snapshot(h.native.ROOT / ('code-clues/release-preset-completion' if completion else 'code-clues/release-preset-initializer'), report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), cases=len(report['cases']))))
