"""Native outer/entry/number-key pipeline with explicit numeric rules and JSON captures."""
import importlib.util
import itertools
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def run():
    archive = load('json_keys_archive', 'replay-release-archive-input.py')
    hooks = dict.fromkeys((0x14690a090, 0x141426780, 0x141426c10, 0x14566c5e0,
        0x145466740, 0x1414833f0, 0x141487bc0, 0x1414ae540, 0x141470310,
        0x1414367a0, 0x141429ef0, 0x141429d60, 0x141472920, 0x1414c38b0,
        0x1414c7db0, 0x141436fb0, 0x141483160, 0x1487eac40, 0x1415f2740,
        0x1415ea570, 0x1415e49b0, 0x1415e5fd0))
    h = archive.make_harness(extra_addresses=(0x146447e50, 0x14142e7d0, 0x1456746c0,
        0x1414b93c0, 0x1414a4280, 0x14148e740, 0x14148e8a0, 0x141478570,
        0x1414c3fa0, 0x1414d3120, 0x1414d64e0), fixtures=hooks)
    uc, x = h.uc, h.x
    def at(address, size):
        offset = h.image.offset(address - h.image.pe.base)
        return h.raw[offset:offset + size]
    def map_source(address):
        page = address & ~4095
        if not any(a <= page <= b for a, b, _ in uc.mem_regions()):
            uc.mem_map(page, 4096); uc.mem_write(page, at(page, 4096))
    for address, code in ((0x1414c3f00, '488d4110c3'), (0x1414457d0, '488bc1c3'),
        (0x140bb4a10, 'b001c3'), (0x1414c7c70, '48c702ffffffff488bc2c3')):
        code = bytes.fromhex(code)
        if at(address, len(code)) != code: raise ValueError('Text virtual leaf changed')
        map_source(address); h.ranges.append((address, address + len(code)))
    text_table = 0x1489ff9e0; map_source(text_table)
    for offset, target in ((0x28, 0x1414c3f00), (0x50, 0x1414457d0),
                           (0x60, 0x1414c7c70), (0xa8, 0x140bb4a10), (0x10, 0x1414d64e0)):
        if struct.unpack('<Q', at(text_table + offset, 8))[0] != target:
            raise ValueError('Number text virtual binding changed')
    exports = {}
    for run_name, expected in (
        ('run-dc5979512d24', '89478968108e418bd9e9c838152a2c70e00407e28a608338ee23ffa70a16d730'),
        ('run-7b99355a924a', '73635de588134c157424416285ef539e6689961ec7372e0f2b12423648a83d26'),
        ('run-f1248d98cd75', '38109ed10c25dc33b390f9e365d39de11f11b20dfbe53a0aa6272f0915c029fb'),
        ('run-d8e1fdc27ed5', 'd5288d671696447b7d1064f09df37e0967771cb7c2a272a890a049693cef11a2')):
        path = h.comparison / 'details' / run_name / 'details.json'
        if h.audit.sha256(path) != expected: raise ValueError('Number-key export changed')
        exports[str(path)] = expected
    resources = load('json_key_definitions', 'extract-release-appearance-resources.py')
    root = h.native.ROOT
    index = root / 'release-snapshots/2b9ee9bbb180f064ae5f399cc41f063784f4f7b98dcc6b659d0707ed4d4cee08/record-indexes/f64ec55098c97fa6bfd0d620e4c397a13b26119c76dde35abb0d9f6cebd5a714/3a313dbd09096213bd92cd033a06337beb4ed38f5ca3f0ee936f7cba055c0adc/manifest.json'
    directory = root / 'resource-config-snapshots/3c1151930e190baf7fb7093c976222e4c2e053bef816c077e689c8a4b1de44a3/manifest.json'
    resource_path, resource_report = resources.extract(index, root, directory)
    definitions = {1 if p['package'].endswith('F') else 0:
        {r['group_name']: r['id'] for r in p['groups']} for p in resource_report['packages']}
    expected_definitions = dict(zip(('Height', 'Chest', 'Pelvis', 'Shape', 'Waist', 'Thigh', 'Head'), range(1, 8)))
    if definitions != {0: expected_definitions, 1: expected_definitions}: raise ValueError('Current numeric key definitions differ')
    owner, entries, bits, definition, culture_context, culture, rules, affixes, output, shared, names = [
        h.scratch + n for n in (0x10000, 0x11000, 0x12000, 0x13000, 0x14000,
            0x15000, 0x16000, 0x17000, 0x18000, 0x19000, 0x1b000)]
    gs = 0x30000000; uc.mem_map(gs, 0x110000); uc.reg_write(x.UC_X86_REG_GS_BASE, gs)
    uc.mem_write(gs + 0x58, struct.pack('<Q', gs + 0x1000)); uc.mem_write(gs + 0x1000, struct.pack('<Q', gs + 0x2000))
    uc.mem_write(gs + 0x2000 + 0x101184, struct.pack('<i', 1))
    uc.mem_write(0x14b6a7c20, bytes(4))
    for address in (0x14b2c5f28, 0x14b2c5f40, 0x14b2c5f58, 0x14b2c5f70):
        uc.mem_write(address, struct.pack('<i', 1))
    uc.mem_write(culture_context, bytes(0x50)); uc.mem_write(culture_context + 0x38, struct.pack('<Q', culture))
    state = {}
    def allocate(size):
        if not 0 <= size <= 8192 or state['heap'] + max(size, 16) > h.scratch + 0x3f000:
            raise ValueError('JSON-key fixture storage bound')
        p = state['heap']; state['heap'] += (max(size, 1) + 15) & ~15
        uc.mem_write(p, bytes(max(size, 1))); return p
    def header(address):
        p, count, capacity = struct.unpack('<QII', bytes(uc.mem_read(address, 16)))
        if not 0 <= count <= capacity <= 2048: raise ValueError('JSON-key FString bound')
        return p, count, capacity
    def text(address):
        p, count, _ = header(address)
        return bytes(uc.mem_read(p, max(0, count - 1) * 2)).decode('utf-16le') if count else ''
    def put_text(address, value):
        data = value.encode('utf-16le') + b'\0\0' if value else b''
        p = allocate(len(data)) if data else 0
        if data: uc.mem_write(p, data)
        uc.mem_write(address, struct.pack('<QII', p, len(data) // 2, len(data) // 2))
    def append(address, data):
        if not data: return
        p, count, capacity = header(address); old = bytes(uc.mem_read(p, (count - 1) * 2)) if count else b''
        new = old + data + b'\0\0'; count = len(new) // 2
        if count > capacity: p = allocate(len(new)); capacity = count
        uc.mem_write(p, new); uc.mem_write(address, struct.pack('<QII', p, count, capacity))
    def finish(result=None):
        if result is not None: uc.reg_write(x.UC_X86_REG_RAX, result)
        sp = uc.reg_read(x.UC_X86_REG_RSP)
        uc.reg_write(x.UC_X86_REG_RIP, int.from_bytes(uc.mem_read(sp, 8), 'little')); uc.reg_write(x.UC_X86_REG_RSP, sp + 8)
    def fixture(machine):
        current = machine.reg_read(x.UC_X86_REG_RIP)
        a, b, c, d = [machine.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        result = None
        if current == 0x14690a090: result = allocate(a)
        elif current == 0x141426780:
            state['group'] = text(b); put_text(a, state['group']); result = a
        elif current == 0x141426c10:
            raw = bytearray()
            for i in range(128):
                pair = bytes(uc.mem_read(b + i * 2, 2))
                if pair == bytes(2): break
                raw.extend(pair)
            else: raise ValueError('JSON-key literal bound')
            put_text(a, raw.decode('utf-16le')); result = a
        elif current == 0x14566c5e0:
            state['mode'] = b & 255; uc.mem_write(a, bytes(16)); result = a
        elif current == 0x145466740:
            identifier = definitions[state['mode']].get(state['group'])
            if identifier is not None: uc.mem_write(definition + 0x10, struct.pack('<i', identifier))
            result = definition if identifier is not None else 0
        elif current == 0x1414833f0: result = culture_context
        elif current == 0x141487bc0:
            if a != culture: raise ValueError('Numeric culture input differs')
            result = rules
        elif current == 0x1414ae540:
            state['formatted_keys'].append(text(b))
            raw = bytes(uc.mem_read(b, 16)); uc.mem_write(b, bytes(16)); uc.mem_write(a, bytes(0x70))
            uc.mem_write(a, struct.pack('<Q', text_table)); uc.mem_write(a + 8, struct.pack('<I', 100))
            uc.mem_write(a + 0x10, raw); result = a
        elif current == 0x141470310:
            for i in range(4): put_text(affixes + i * 16, '-' if i == 0 else '')
            uc.mem_write(a, struct.pack('<4Q', *(affixes + i * 16 for i in range(4)))); result = a
        elif current == 0x1414367a0:
            p, count, _ = header(a); data = bytes(uc.mem_read(p, count * 2)) if count else b''
            if not 0 < b <= 2048: raise ValueError('Numeric reserve bound')
            p = allocate(b * 2)
            if data: uc.mem_write(p, data)
            uc.mem_write(a, struct.pack('<QII', p, count, b))
        elif current == 0x141429ef0:
            if not 0 <= c <= 2048: raise ValueError('Numeric append bound')
            append(a, bytes(uc.mem_read(b, c * 2)) if c else b''); result = a
        elif current == 0x141429d60: append(a, struct.pack('<H', b & 0xffff)); result = a
        elif current == 0x1414c38b0: result = culture_context
        elif current == 0x1414c7db0:
            uc.mem_write(c, bytes(2)); uc.mem_write(d, bytes(2))  # Unchanged cached culture revision.
        elif current == 0x141436fb0:
            if not 0 < b <= 2048: raise ValueError('FString storage bound')
            uc.mem_write(a, struct.pack('<QII', allocate(b * 2), b, b)); result = a
        elif current == 0x1415f2740:
            value = struct.unpack('<d', machine.reg_read(x.UC_X86_REG_XMM2).to_bytes(16, 'little')[:8])[0]
            if state['json_object'] not in (None, a): raise ValueError('Multiple JSON objects in one appearance')
            state['json_object'] = a; state['values'][text(b)] = value
        elif current == 0x1415ea570:
            if b != output or c: raise ValueError('JSON writer setup differs')
            uc.mem_write(a, struct.pack('<QQ', output, 0)); result = a
        elif current == 0x1415e49b0:
            control = int.from_bytes(uc.mem_read(a + 8, 8), 'little')
            uc.mem_write(control + 8, struct.pack('<ii', 100, 100))
            uc.mem_write(shared, struct.pack('<Qii', 0, 100, 100) + bytes(0x40)); result = shared
        elif current == 0x1415e5fd0:
            if int.from_bytes(uc.mem_read(a, 8), 'little') != shared + 16 or c != 1:
                raise ValueError('JSON writer finalize differs')
            put_text(output, json.dumps(state['values'], ensure_ascii=False, allow_nan=False, separators=(',', ':'))); result = 1
        finish(result)
    for address in hooks: hooks[address] = fixture
    cases = []
    groups = list(expected_definitions)
    for digits_name, gender, voice, sparse in itertools.product(('latin', 'arabic'), (0, 1), (0, 1, 255), ('empty', 'full', 'sparse')):
        state.update(heap=h.scratch + 0x21000, group='', mode=gender, values={}, json_object=None, formatted_keys=[])
        uc.mem_write(rules, bytes(0xc0)); uc.mem_write(rules + 0x70, ',.'.encode('utf-16le'))
        uc.mem_write(rules + 0x74, bytes((3, 3, 1)))
        digits = '0123456789' if digits_name == 'latin' else '٠١٢٣٤٥٦٧٨٩'
        uc.mem_write(rules + 0x78, digits.encode('utf-16le'))
        uc.mem_write(rules + 0x8c, struct.pack('<BB6xiiii', 0, 1, 1, 20, 0, 0))
        uc.mem_write(owner, bytes(0x90)); uc.mem_write(output, bytes(16))
        uc.mem_write(owner + 0x20, bytes((voice,))); uc.mem_write(owner + 0x28, bytes((gender,)))
        slots = 0 if sparse == 'empty' else 7 if sparse == 'full' else 35
        occupied = () if not slots else tuple(range(7)) if slots == 7 else (0, 3, 7, 8, 16, 31, 32, 34)
        uc.mem_write(owner + 0x30, struct.pack('<Q', entries)); uc.mem_write(owner + 0x58, struct.pack('<I', slots))
        words = [0, 0]; expected = {}
        for n, index in enumerate(occupied):
            words[index // 32] |= 1 << (index % 32)
            name = groups[n] if n < 7 else 'UnknownGroup'
            value = (0.4, 0.3, 0.5, -0.0, 0.125, -2.5, 1.0)[n] if n < 7 else float('nan')
            value = struct.unpack('<f', struct.pack('<f', value))[0]
            raw = name.encode('utf-16le') + bytes(2); p = names + index * 64; uc.mem_write(p, raw)
            uc.mem_write(entries + index * 0x30 + 0x10, struct.pack('<QII', p, len(raw) // 2, len(raw) // 2))
            uc.mem_write(entries + index * 0x30 + 0x20, struct.pack('<f', value))
            if n < 7: expected[digits[expected_definitions[name]]] = value
        expected['VoiceType'] = float(voice)
        if slots > 32:
            uc.mem_write(bits, struct.pack('<II', *words)); uc.mem_write(owner + 0x50, struct.pack('<Q', bits))
        else: uc.mem_write(owner + 0x40, struct.pack('<I', words[0]))
        h.call(0x146447e50, owner, output, budget=500000)
        actual = json.loads(text(output))
        if actual.keys() != expected.keys() or any(struct.pack('<d', actual[k]) != struct.pack('<d', v) for k, v in expected.items()):
            raise ValueError('Native JSON numeric key/value pipeline differs: ' + repr((digits_name, gender, voice, sparse, actual, expected, state['formatted_keys'])))
        if state['formatted_keys'] != [digits[i] for i in range(1, 8)] * bool(slots):
            raise ValueError('Native AsNumber keys differ')
        cases.append(dict(digits=digits_name, gender=gender, voice=voice, sparse=sparse,
            keys=list(actual), values_f64_hex={k: struct.pack('<d', v).hex() for k, v in actual.items()},
            formatted_keys=state['formatted_keys'].copy(), json_capture=text(output)))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)), native_execution=True,
        network_used=False, cases=cases, ghidra_exports=exports, definition_report=str(resource_path),
        definition_source_sha256=resource_report['source']['sha256'], definitions=definitions,
        dependencies={name: h.audit.sha256(HERE / name) for name in
            ('replay-release-archive-input.py', 'extract-release-appearance-resources.py',
             'build-native-entry-code.py', 'extract-native-enums.py',
             'build-object-zero-init-code.py', 'requirements-native.txt')},
        limits=['Whole outer/entry helpers, AsNumber wrappers/core, integer digit formatter, sign/parts join, ToString/refresh and sparse iterator execute.',
            'Culture/rules and unchanged revision, text history construction, high refcounts, definition lookup, FString storage/append/reserve/free and JSON setter/writer are fixtures/captures.',
            'Digits are explicit Latin or Arabic rule tables; live culture and culture-change rebuild are not checked. Current IDs 1–7 only.',
            'JSON is reconstructed from native numeric setter captures; native JSON bytes/number spelling are not claimed.',
            'Source definitions extracted from current PAK; case-insensitive lookup, ranges/default choices, handler, game/auth/network are not covered.'])
    path = h.audit.save_snapshot(root / 'code-clues/release-appearance-json-keys', report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), cases=len(report['cases']))))
