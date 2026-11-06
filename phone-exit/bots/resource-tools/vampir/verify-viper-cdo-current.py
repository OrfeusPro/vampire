"""Current allocation/default-copy model with explicit engine metadata fixtures."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/viper-cdo-11322.json'
SHA = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def validate_whole_source(native, image, context, exported):
    """Exported roots and the declared tail-wrapper must cover exact whole ranges."""
    normalizer = load('audit-launcher-shape-11318')
    verified = []
    for key, encoded in context['functions'].items():
        at = int(encoded, 16)
        body = exported.get(encoded)
        if body is None: raise ValueError('Current CDO export root absent: ' + key)
        normalized = normalizer.normalize_function(native, image, body)
        verified.append(dict(role=key, address=encoded, instructions=len(normalized['shape']),
            calls=normalized['calls'], references=normalized['references'], provenance='whole_ghidra_export'))
    # Ghidra currently follows this tail into a no-unwind RET leaf and rejects
    # the decompiler block. Decode the entire PE root and require the exact full
    # byte vector here; this does not pretend the rejected export was admitted.
    wrapper = context['default_copy_wrapper']
    at = int(wrapper['address'], 16)
    part = image.containing(at)
    if part is None or image.pe.base + image.roots[part][0] != at:
        raise ValueError('Default wrapper must begin at whole unwind root')
    rows = [r for f in native.decode_ranges(image, {image.roots[part]}) for r in f['instructions']]
    actual = [dict(address=hex(r['address']), bytes=r['bytes']) for r in rows]
    if actual != wrapper['instructions']:
        raise ValueError('Current CDO wrapper whole source changed')
    if len(rows) != 16 or (rows[-1]['mnemonic'], rows[-1]['operands']) != ('jmp', '0x141403bd0'):
        raise ValueError('Default wrapper tail differs')
    verified.append(dict(role='default_copy_wrapper', address=hex(at), instructions=len(rows),
        tail='0x141403bd0', provenance='whole_pe_unwind_bytes', ghidra_export_admitted=False))
    return verified


def verify(context_path=CONTEXT, *, root=ROOT):
    context_path, root = Path(context_path).resolve(), Path(root).resolve()
    context = json.loads(context_path.read_bytes())
    if context.get('schema') != 1 or context.get('recipe') != 'viper-cdo-current-v1' or context.get('source_sha256') != SHA:
        raise ValueError('Current CDO context/source differs')
    expected_roles = {'ordinary', 'allocation', 'completion', 'postconstruct', 'init_properties', 'preset', 'data_asset', 'uobject'}
    if set(context['functions']) != expected_roles:
        raise ValueError('Current CDO roles differ')
    roles = {name: int(at, 16) for name, at in context['functions'].items()}
    wrapper = context['default_copy_wrapper']
    leaves = {int(at, 16): raw for at, raw in context['leaves'].items()}
    leaves[int(wrapper['address'], 16)] = ''.join(row['bytes'] for row in wrapper['instructions'])
    h = load('native-request-harness-11316').make_harness(context['exports'], set(roles.values()),
        leaves=leaves, root=root, source_sha256=SHA, copy_thunk=0x1487f8c99)
    native = load('build-native-entry-code')
    import unicorn
    inputs = {str(context_path): digest(context_path), str(Path(__file__).resolve()): digest(__file__), str(h.source.resolve()): SHA}
    exported = {}
    for run, expected in context['exports'].items():
        path = root / 'ghidra/request-exports' / SHA / run / 'details.json'
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected: raise ValueError('Current CDO export changed')
        doc = json.loads(raw)
        if doc.get('new_source_sha256') != SHA: raise ValueError('Current CDO export source differs')
        exported.update({f['address']: f for f in doc['functions']})
        inputs[str(path.resolve())] = expected
    verified = validate_whole_source(native, h.image, context, exported)
    for anchor in context['anchors']:
        at, raw = int(anchor['address'], 16), bytes.fromhex(anchor['bytes'])
        off = h.image.offset(at - h.image.pe.base)
        if h.raw[off:off + len(raw)] != raw: raise ValueError('Current CDO source anchor changed')
    ctor_path = HERE / 'knowledge/native-contexts/preset-defaults-11322.json'
    ctor = json.loads(ctor_path.read_bytes())
    if ctor['source_sha256'] != SHA or ctor['functions']['preset'] != context['functions']['preset']:
        raise ValueError('Current CDO constructor schema differs')
    fields = [row for row in ctor['descriptors'] if row['name'] != 'UnderlyingType']
    for row in fields:
        off = h.image.offset(int(row['descriptor'], 16) - h.image.pe.base)
        if h.raw[off:off + 56].hex() != row['bytes']: raise ValueError('Current CDO field descriptor changed')
    if len(fields) != 17 or [row['offset'] for row in fields] != list(range(0x30, 0x74, 4)):
        raise ValueError('Current CDO field layout differs')
    inputs[str(ctor_path.resolve())] = digest(ctor_path)
    # Named import identity, rather than a guessed zeroing helper.
    memset = int(context['memset'], 16)
    off = h.image.offset(memset - h.image.pe.base)
    if h.raw[off:off + 2] != b'\xff\x25': raise ValueError('Current memset thunk changed')
    iat = memset + 6 + struct.unpack_from('<i', h.raw, off + 2)[0]
    binding = load('build-object-zero-init-code').import_at(h.raw, h.image, iat)
    if (binding['dll'].lower(), binding['name']) != ('vcruntime140.dll', 'memset'):
        raise ValueError('Current zero branch is not named memset')
    uc, x = h.uc, h.x
    obj, source, cls, context_obj, entries, parameters, chunks, chunk, parent, properties, class_vtable = [
        h.scratch + n for n in (0x10000, 0x11000, 0x12000, 0x13000, 0x14000,
            0x16000, 0x17000, 0x18000, 0x19000, 0x1c000, 0x1a000)]
    gs = 0x30000000
    uc.mem_map(gs, 0x110000); uc.reg_write(x.UC_X86_REG_GS_BASE, gs)
    uc.mem_write(gs + 0x58, struct.pack('<Q', gs + 0x1000))
    uc.mem_write(gs + 0x1000, struct.pack('<Q', gs + 0x2000))
    for item in context['globals']:
        address, data = int(item['address'], 16), bytes.fromhex(item['value'])
        page = address & ~4095
        if not any(a <= page <= b for a, b, _ in uc.mem_regions()): uc.mem_map(page, 4096)
        uc.mem_write(address, data)
    hooks = {name: int(at, 16) for name, at in context['fixtures'].items()}
    calls, allocations, zeroes, initializer_events = [], [], [], []
    executed = {}
    entry_names = {at: name for name, at in roles.items()}
    entry_names[int(wrapper['address'], 16)] = 'default_copy_wrapper'
    def track_entry(machine, address, size, unused):
        if address in entry_names:
            name = entry_names[address]; executed[name] = executed.get(name, 0) + 1
    uc.hook_add(unicorn.UC_HOOK_CODE, track_entry)
    state = dict(size=0x78, mode='ordinary')
    def q(at): return int.from_bytes(uc.mem_read(at, 8), 'little')
    def u(at): return int.from_bytes(uc.mem_read(at, 4), 'little')

    def fixture(machine):
        at = machine.reg_read(x.UC_X86_REG_RIP)
        a, b, c, d = [machine.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        calls.append(hex(at))
        if at == hooks['name']:
            if (b, c, d) != (0, cls, 0): raise ValueError('Fresh allocation naming contract differs')
            machine.mem_write(a, struct.pack('<Q', 0x80000001)); h.finish(a)
        elif at == hooks['heap']:
            if (a, b) != (state['size'], 4): raise ValueError('Heap size/alignment differs')
            allocations.append(dict(size=a, alignment=b)); h.finish(obj)
        elif at == memset:
            if (a, b, c) != (obj, 0, state['size']): raise ValueError('Fresh zeroing bounds differ')
            machine.mem_write(obj, bytes(c)); zeroes.append(dict(destination=hex(a), count=c)); h.finish(obj)
        elif at == hooks['register']:
            if (a, b) != (obj, 0x80000001): raise ValueError('Object registration arguments differ')
            if q(obj + 0x10) != cls or q(obj + 0x20) != 0: raise ValueError('Fresh native header differs')
            machine.mem_write(obj + 0xc, bytes(4)); machine.mem_write(chunk, struct.pack('<QII', obj, 0, 0)); h.finish()
        elif at == hooks['set_flags']:
            if (a, b) != (chunk, 0x8400000): raise ValueError('Fresh registration flags differ')
            machine.mem_write(a + 8, struct.pack('<I', u(a + 8) | b)); h.finish()
        elif at == hooks['context']:
            h.finish(context_obj)
        elif at == hooks['push']:
            if q(a) != obj or u(context_obj + 0x18) != 0: raise ValueError('Ordinary initializer push differs')
            machine.mem_write(entries, struct.pack('<Q', a))
            machine.mem_write(context_obj + 0x18, struct.pack('<I', 1)); machine.mem_write(context_obj + 0x28, struct.pack('<I', 1))
            h.finish()
        elif at == hooks['initializer']:
            if u(context_obj + 0x18) != 1: raise ValueError('Constructor initializer ownership differs')
            init = q(entries)
            initializer_events.append(dict(object=q(init), source=q(init + 8), copy=machine.mem_read(init + 0x11, 1)[0]))
            h.finish(init)
        elif at == hooks['base_class']: h.finish(0)
        elif at == hooks['immediate']: h.finish(1)
        elif at == hooks['empty_delegates']:
            if a or b: raise ValueError('Nonempty delegates outside current model')
            h.finish()
        elif at == hooks['empty_container']:
            if b: raise ValueError('Nonempty initializer container outside current model')
            h.finish()
        elif at == hooks['uobject_service']: h.finish()
        elif at == hooks['bookkeeping']: h.finish()
        elif at == hooks['post_owner']:
            if (a, b) != (obj, 0): raise ValueError('Postconstruct owner notification differs')
            h.finish()
        elif at == hooks['clear_object_flag']:
            if (a, b) != (obj, 0x200): raise ValueError('Postconstruct final flags differ')
            machine.mem_write(a + 8, struct.pack('<I', u(a + 8) & ~b)); h.finish()
        elif at == hooks['security']: h.finish()
        else: raise ValueError('Unexpected current CDO service ' + hex(at))
    for at in set(hooks.values()) | {memset}: h.add_fixture(at, fixture)

    def prepare(poison=0xa5, size=0x78):
        for at, count in ((source, 0x78), (cls, 0x400), (parent, 0x180), (context_obj, 0x60),
                (entries, 0x40), (parameters, 0x88), (properties, 17 * 0x80), (class_vtable, 0x400)):
            uc.mem_write(at, bytes(count))
        # Class metadata/virtual providers are explicit fixtures. The wrapper
        # and POD copying execute native; these three engine methods are RET.
        for offset in (0x388, 0x398, 0x3b8): uc.mem_write(class_vtable + offset, struct.pack('<Q', 0x141403bd0))
        uc.mem_write(cls, struct.pack('<Q', class_vtable))
        for offset, value in ((0x40, parent), (0xb0, roles['preset']), (0x110, source)):
            uc.mem_write(cls + offset, struct.pack('<Q', value))
        uc.mem_write(cls + 0x58, struct.pack('<II', size, 4)); uc.mem_write(cls + 0xd4, struct.pack('<I', 0x10000001))
        uc.mem_write(chunks, struct.pack('<Q', chunk)); uc.mem_write(chunk, bytes(24))
        uc.mem_write(0x14b3e1ab0, struct.pack('<Q', chunks)); uc.mem_write(0x14b3e1ac4, struct.pack('<I', 1))
        uc.mem_write(context_obj + 0x10, struct.pack('<QII', entries, 0, 8))
        uc.mem_write(obj - 16, bytes([0x47]) * 16 + bytes([poison]) * 0x78 + bytes([0x83]) * 16)
        uc.mem_write(h.scratch + 0x38028, bytes(0x30))
        state['size'] = size; calls.clear(); allocations.clear(); zeroes.clear(); initializer_events.clear(); executed.clear()

    # Exercise the fresh branch itself, separately from the composed caller.
    allocation_cases = []
    for poison in (0, 0xa5, 0xff):
        for size in (0x30, 0x78):
            prepare(poison, size)
            reused = parameters + 0x80; uc.mem_write(reused, b'\xff')
            uc.reg_write(x.UC_X86_REG_RDX, 0); uc.reg_write(x.UC_X86_REG_R8, 0); uc.reg_write(x.UC_X86_REG_R9, 0xb)
            uc.mem_write(h.scratch + 0x38038, struct.pack('<Q', reused))
            result = h.call(roles['allocation'], cls, budget=120000)
            if result != obj or allocations != [dict(size=size, alignment=4)] or zeroes != [dict(destination=hex(obj), count=size)]:
                raise ValueError('Fresh allocator did not zero exactly once')
            if uc.mem_read(reused, 1) != b'\0' or u(obj + 8) != 0x20b: raise ValueError('Fresh reuse/header state differs')
            if bytes(uc.mem_read(obj + 0x28, size - 0x28)) != bytes(size - 0x28): raise ValueError('Fresh payload is not zero')
            if bytes(uc.mem_read(obj + size, 0x78 - size)) != bytes([poison]) * (0x78 - size): raise ValueError('Fresh allocation exceeded requested size')
            if bytes(uc.mem_read(obj - 16, 16)) != bytes([0x47]) * 16 or bytes(uc.mem_read(obj + 0x78, 16)) != bytes([0x83]) * 16:
                raise ValueError('Fresh allocation outer guard changed')
            if executed != dict(allocation=1): raise ValueError('Fresh allocation executed unexpected roots')
            allocation_cases.append(dict(poison=poison, size=size, zero_calls=1, reused=False, flags=0x20b, guards_unchanged=True))

    # The CDO source is deliberately synthetic. It is a zero-allocation model
    # followed by the already source-proven constructor vector, not live cache.
    ordinary_cases = []
    model = bytes(36) + struct.pack('<7fB', *([0.5] * 7), 0)
    for poison in (0, 0xa5, 0xff):
        for modified in (False, True):
            for mode in ('empty', 'all', 'alternate'):
                prepare(poison)
                uc.mem_write(source + 0x30, model)
                if modified:
                    for index, field in enumerate(fields):
                        fmt, value = ('<i', 100 + index) if index < 9 else ('<f', (index - 8) / 16) if index < 16 else ('<B', 3)
                        uc.mem_write(source + field['offset'], struct.pack(fmt, value))
                selected = [] if mode == 'empty' else list(range(17)) if mode == 'all' else list(range(0, 17, 2))
                for position, index in enumerate(selected):
                    prop = properties + index * 0x80; field = fields[index]
                    uc.mem_write(prop + 0x30, struct.pack('<iiQ', 1, 1 if index == 16 else 4, 1 << 30))
                    uc.mem_write(prop + 0x44, struct.pack('<i', field['offset']))
                    uc.mem_write(prop + 0x60, struct.pack('<Q', properties + selected[position + 1] * 0x80 if position + 1 < len(selected) else 0))
                uc.mem_write(cls + 0x88, struct.pack('<Q', properties + selected[0] * 0x80 if selected else 0))
                uc.mem_write(parameters, struct.pack('<QQQII', cls, 0, 0, 0xb, 0))
                uc.mem_write(parameters + 0x28, struct.pack('<Q', source))
                h.call(roles['ordinary'], parameters, budget=300000)
                expected = bytearray(model)
                for index in selected:
                    offset = fields[index]['offset']; width = 1 if index == 16 else 4
                    expected[offset - 0x30:offset - 0x30 + width] = uc.mem_read(source + offset, width)
                if bytes(uc.mem_read(obj + 0x30, len(expected))) != bytes(expected): raise ValueError('Current ordinary default transfer differs')
                if initializer_events != [dict(object=obj, source=source, copy=1)]: raise ValueError('Ordinary source/copy initializer differs')
                if allocations != [dict(size=0x78, alignment=4)] or len(zeroes) != 1 or u(obj + 8) != 0xb:
                    raise ValueError('Ordinary allocation/completion state differs')
                if u(context_obj + 0x18) or u(context_obj + 0x28): raise ValueError('Ordinary initializer counters not restored')
                if executed != dict.fromkeys((*roles, 'default_copy_wrapper'), 1):
                    raise ValueError('Whole ordinary composition did not execute each native root once')
                if bytes(uc.mem_read(obj - 16, 16)) != bytes([0x47]) * 16 or bytes(uc.mem_read(obj + 0x78, 16)) != bytes([0x83]) * 16:
                    raise ValueError('Ordinary outer guard changed')
                ordinary_cases.append(dict(poison=poison, modified_template=modified, link_mode=mode,
                    copied_fields=[fields[index]['name'] for index in selected], default_bytes=model.hex(),
                    output_bytes=bytes(expected).hex(), completed_flags=0xb, guards_unchanged=True, executed_roots=dict(executed)))
    for name in ('native-request-harness-11316', 'build-native-entry-code', 'audit-launcher-shape-11318',
                 'knowledge-index', 'audit-client-release', 'build-object-zero-init-code', 'extract-native-enums'):
        path = HERE / (name + '.py'); inputs[str(path.resolve())] = digest(path)
    if any(digest(path) != expected for path, expected in inputs.items()): raise ValueError('Current CDO proof inputs changed')
    report = dict(schema=1, recipe=context['recipe'], source_sha256=SHA, inputs=inputs, whole_source=verified,
        named_memset=binding, allocation_cases=allocation_cases, ordinary_cases=ordinary_cases,
        fields=fields, native_execution=True, network_used=False, runtime_admitted=False,
        complete_viper_payload_verified=False, loaded_preset_verified=False, source_CDO_is_fixture=True,
        limits=['Whole fresh-allocation, ordinary caller, current constructors, completion, postconstruct and InitProperties execute.',
            'Entire 16-instruction default-copy wrapper is PE-byte checked and executed; rejected Ghidra export is not admitted.',
            'Heap backend, object registration, naming, context push/lookup, flags/bookkeeping/security and bounded CRT memory effects are fixtures.',
            'Class/property metadata, virtual class providers, zeroed TLS, no config/subobjects/delegates and immediate completion are fixtures.',
            'Property POD flags/list membership and CDO source vector are synthetic. Empty list preserves constructor results; copying is selective.',
            'Fresh branch only; object reuse, special outer/CDO allocation, deferred completion, package deserialization and later overrides are unverified.',
            'Conditional integer-zero model is not live loaded Viper asset data. Create103/104, admission and server acceptance remain unverified.'])
    path = load('audit-client-release').save_snapshot(root / 'code-clues/viper-cdo-current-v1', report)
    return dict(report=str(path), sha256=digest(path), native_cases=len(allocation_cases) + len(ordinary_cases))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, default=CONTEXT)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    print(json.dumps(verify(args.context, root=args.root)))
