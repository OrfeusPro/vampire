"""Pure relocation and rejected source/data boundaries; no native execution or IO."""
import copy
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_vampir_update_contracts import load

RULES = load('version-string-transfer-rules')
NATIVE = load('build-native-entry-code')
QUANTIZE = bytes.fromhex('448bc2488bd1488b0d000000004885c97504488bc2c3488b0148ff6060cccccc')


def rows(raw, at):
    decoder = NATIVE.capstone.Cs(NATIVE.capstone.CS_ARCH_X86, NATIVE.capstone.CS_MODE_64)
    decoder.detail = True
    result = []
    for ins in decoder.disasm(raw, at):
        call = ins.group(NATIVE.capstone.CS_GRP_CALL)
        branch = ins.group(NATIVE.capstone.CS_GRP_JUMP)
        target = ins.operands[0].imm if (call or branch) and ins.operands and ins.operands[0].type == NATIVE.X86_OP_IMM else None
        result.append(dict(address=ins.address, bytes=ins.bytes.hex(), mnemonic=ins.mnemonic, operands=ins.op_str,
                           call=call, branch=branch, direct_target=target,
                           rip_references=[ins.address + ins.size + op.mem.disp for op in ins.operands
                                           if op.type == NATIVE.X86_OP_MEM and op.mem.base == NATIVE.X86_REG_RIP]))
    if sum(len(bytes.fromhex(row['bytes'])) for row in result) != len(raw):
        raise AssertionError('Incomplete synthetic instruction stream')
    return result


class Image:
    def __init__(self):
        self.memory, self.code, self.roots = {}, {}, {}
        self.pe = SimpleNamespace(base=0)

    def entry(self, at):
        self.roots[at] = (at, at + 0x100, 0)

    def containing(self, at):
        return at if at in self.roots else None

    def read(self, at, size):
        for origin, data in self.memory.items():
            if origin <= at and at + size <= origin + len(data):
                return bytes(data[at - origin:at - origin + size])
        raise ValueError('Synthetic image data missing')

    def function(self, at, raw):
        self.code[at] = rows(raw, at)
        self.entry(at)


def calls(at, targets):
    return b''.join(b'\xe8' + struct.pack('<i', target - (at + index * 5 + 5))
                    for index, target in enumerate(targets)) + b'\xc3'


class TransferTests(unittest.TestCase):
    def setUp(self):
        actual_load = RULES.load
        self.before, self.after = Image(), Image()
        self.bindings = SimpleNamespace(rows=lambda native, image, at: image.code[at])
        self.addCleanup(patch.stopall)
        patch.object(RULES, 'image_bytes', side_effect=lambda image, at, size: image.read(at, size)).start()
        patch.object(RULES, 'load', side_effect=lambda name: SimpleNamespace(
            data_input=lambda image, at, size: dict(storage='file', bytes=image.read(at, size).hex()))
            if name == 'update-native-version-prepare' else actual_load(name)).start()

    def combiner(self):
        source = dict(functions={name: hex(0x1000 + index * 0x200) for index, name in enumerate(RULES.COMBINERS)},
                      fixtures={name: hex(0x3000 + index * 0x100) for index, name in enumerate(sorted(RULES.COMBINER_FIXTURES))},
                      helpers=dict(memcpy='0x5000'), exports={'untouched': 'metadata'}, source_sha256='original')
        for image, shift in ((self.before, 0), (self.after, 0x10000)):
            f = {key: int(at, 16) + shift for key, at in source['functions'].items()}
            x = {key: int(at, 16) + shift for key, at in source['fixtures'].items()}
            cp = 0x5000 + shift
            edges = dict(first=[x['resize'], cp, f['append'], x['overflow']],
                         second=[f['copy'], f['grow'], f['append'], x['overflow']],
                         copy=[x['resize'], cp], append=[x['append_grow'], x['copy'], x['overflow']],
                         grow=[x['quantize'], x['allocator']])
            for name, at in f.items():
                image.function(at, calls(at, edges[name]))
            for name, at in x.items():
                if name not in ('copy', 'quantize'):
                    image.entry(at)
            at = x['copy']
            image.memory[at] = bytearray(b'\xe9' + struct.pack('<i', cp - at - 5) + b'\xcc' * 11)
            at = x['quantize']
            raw = bytearray(QUANTIZE)
            struct.pack_into('<i', raw, 9, 0x6000 + shift - at - 13)
            image.memory[at] = raw
            image.memory[0x6000 + shift] = bytearray(8)
        source['call_sites'] = RULES.call_sites(NATIVE, self.bindings, self.before, RULES.functions('version-combiner', source))
        seed = {int(source['functions'][name], 16): int(source['functions'][name], 16) + 0x10000 for name in ('first', 'second')}
        seed[0x5000] = 0x15000
        return source, seed

    def platform(self):
        source = dict(selector='0x1000', store='0x1200', lookup='0x1400', cache='0x5000', factory='0x6000', descriptor='0x5100',
                      helpers=dict(memcpy='0x7000'),
                      fixtures={name: hex(0x3000 + index * 0x100) for index, name in enumerate(sorted(RULES.PLATFORM_FIXTURES))})
        for image, shift in ((self.before, 0), (self.after, 0x10000)):
            x = {key: int(at, 16) + shift for key, at in source['fixtures'].items()}
            at = 0x1000 + shift
            code = bytearray(b'\x90' * 147)
            for offset, name in ((0, 'platform_text'), (6, 'name_ctor'), (12, 'free'), (40, 'equals')):
                code[offset:offset + 5] = b'\xe8' + struct.pack('<i', x[name] - at - offset - 5)
            for index, (offset, text) in enumerate(((25, '\0'), (68, 'Android\0'), (96, 'IOS\0'), (124, 'Windows\0'))):
                pointer = 0x5200 + index * 0x100 + shift
                code[offset:offset + 7] = b'\x48\x8d\x15' + struct.pack('<i', pointer - at - offset - 7)
                image.memory[pointer] = bytearray(text.encode('utf-16le'))
            code[-1] = 0xc3
            image.function(at, code)
            at = 0x1200 + shift
            code = bytearray(b'\x90' * 55)
            for offset, prefix, pointer in ((4, b'\x48\x8b\x05', 0x5000 + shift),
                                            (24, b'\x4c\x8d\x05', 0x5100 + shift),
                                            (31, b'\x48\x8d\x0d', 0x6000 + shift),
                                            (43, b'\x48\x89\x05', 0x5000 + shift)):
                code[offset:offset + 7] = prefix + struct.pack('<i', pointer - at - offset - 7)
            for offset, name in ((16, 'store_type'), (38, 'store_resolve')):
                code[offset:offset + 5] = b'\xe8' + struct.pack('<i', x[name] - at - offset - 5)
            code[-1] = 0xc3
            image.function(at, code)
            at = 0x1400 + shift
            image.function(at, calls(at, [x['value_at']]))
            image.memory[0x5000 + shift] = bytearray(8)
            image.memory[0x5100 + shift] = bytearray('ENnOsType\0'.encode('utf-16le'))
            for pointer in list(x.values()) + [0x6000 + shift]:
                image.entry(pointer)
        source['call_sites'] = RULES.call_sites(NATIVE, self.bindings, self.before, RULES.functions('version-platform', source))
        seed = {int(source[key], 16): int(source[key], 16) + 0x10000 for key in RULES.PLATFORM}
        seed[0x7000] = 0x17000
        return source, seed

    def transfer(self, family, baseline, mapping):
        return RULES.transfer(family, NATIVE, self.bindings, self.before, self.after, baseline, mapping)

    def test_combiner_whole_call_closure_relocates_and_preserves_input_metadata(self):
        source, seed = self.combiner()
        original = copy.deepcopy(source)
        current, details = self.transfer('version-combiner', source, seed)
        self.assertEqual(source, original)
        self.assertEqual(len(RULES.roots('version-combiner', current)), 5)
        self.assertEqual(current['functions']['grow'], '0x11800')
        self.assertEqual(current['helpers']['memcpy'], '0x15000')
        self.assertEqual(current['exports'], source['exports'])
        self.assertEqual(current['source_sha256'], 'original')
        self.assertEqual(details['fixtures']['quantize']['manager'], '0x16000')
        self.assertEqual(seed[0x1800], 0x11800)

    def test_missing_independent_caller_anchor_is_not_guessed(self):
        source, seed = self.combiner()
        del seed[int(source['functions']['first'], 16)]
        with self.assertRaisesRegex(ValueError, 'independent caller'):
            self.transfer('version-combiner', source, seed)

    def test_changed_native_instruction_or_declared_call_role_is_rejected(self):
        source, seed = self.combiner()
        self.after.code[0x11000][-1] = rows(b'\x90', self.after.code[0x11000][-1]['address'])[0]
        with self.assertRaisesRegex(ValueError, 'instruction shape'):
            self.transfer('version-combiner', source, seed)
        source, seed = self.combiner()
        source['call_sites'][next(iter(source['call_sites']))] = '0xdead'
        with self.assertRaisesRegex(ValueError, 'call-site roles'):
            self.transfer('version-combiner', source, seed)

    def test_copy_fixture_tail_must_target_the_proved_memcpy(self):
        source, seed = self.combiner()
        at = int(source['fixtures']['copy'], 16) + 0x10000
        self.after.memory[at][1] ^= 1
        with self.assertRaisesRegex(ValueError, 'copy thunk'):
            self.transfer('version-combiner', source, seed)

    def test_quantize_dispatch_offset_and_its_global_input_are_pinned(self):
        source, seed = self.combiner()
        at = int(source['fixtures']['quantize'], 16) + 0x10000
        self.after.memory[at][28] = 0x68
        with self.assertRaisesRegex(ValueError, 'quantize dispatch'):
            self.transfer('version-combiner', source, seed)
        source, seed = self.combiner()
        self.after.memory[0x16000][0] = 1
        with self.assertRaisesRegex(ValueError, 'typed data changed'):
            self.transfer('version-combiner', source, seed)

    def test_fixture_boundaries_cannot_alias_roots_or_hide_a_mid_function_address(self):
        source, seed = self.combiner()
        source['fixtures']['resize'] = source['functions']['first']
        with self.assertRaisesRegex(ValueError, 'alias'):
            RULES.roots('version-combiner', source)
        source, seed = self.combiner()
        del self.after.roots[int(source['fixtures']['allocator'], 16) + 0x10000]
        with self.assertRaisesRegex(ValueError, 'unwind entry'):
            self.transfer('version-combiner', source, seed)

    def test_platform_transfers_only_typed_rip_roles_and_concrete_factory_argument(self):
        source, seed = self.platform()
        current, details = self.transfer('version-platform', source, seed)
        self.assertEqual(current['cache'], '0x15000')
        self.assertEqual(current['factory'], '0x16000')
        self.assertEqual(current['fixtures']['store_type'], hex(int(source['fixtures']['store_type'], 16) + 0x10000))
        self.assertEqual([item['role'] for item in details['typed_inputs']],
                         ['empty', 'android', 'ios', 'windows', 'cache', 'descriptor', 'factory'])

    def test_platform_literal_and_enum_name_cannot_change_under_rip_relocation(self):
        for address in (0x15300, 0x15100):
            source, seed = self.platform()
            self.after.memory[address][0] ^= 1
            with self.subTest(address=address), self.assertRaisesRegex(ValueError, 'literal changed|descriptor changed'):
                self.transfer('version-platform', source, seed)

    def test_platform_cache_source_and_factory_boundary_are_required(self):
        source, seed = self.platform()
        self.after.memory[0x15000][0] = 1
        with self.assertRaisesRegex(ValueError, 'typed data changed'):
            self.transfer('version-platform', source, seed)
        source, seed = self.platform()
        del self.after.roots[0x16000]
        with self.assertRaisesRegex(ValueError, 'factory argument'):
            self.transfer('version-platform', source, seed)

    def test_unknown_rip_dependency_and_aliased_fixture_roles_are_blockers(self):
        source, seed = self.platform()
        source['descriptor'] = source['cache']
        with self.assertRaisesRegex(ValueError, 'static role linkage'):
            self.transfer('version-platform', source, seed)
        source, seed = self.combiner()
        source['fixtures']['overflow'] = source['fixtures']['allocator']
        with self.assertRaisesRegex(ValueError, 'fixture roles alias'):
            RULES.roots('version-combiner', source)

    def test_unregistered_direct_call_cannot_hide_in_a_matching_shape(self):
        source, seed = self.combiner()
        for image, shift in ((self.before, 0), (self.after, 0x10000)):
            at = 0x1800 + shift
            targets = [int(source['fixtures'][role], 16) + shift for role in ('quantize', 'allocator')]
            image.function(at, calls(at, targets + [0x8000 + shift]))
        source['call_sites'] = RULES.call_sites(NATIVE, self.bindings, self.before, RULES.functions('version-combiner', source))
        with self.assertRaisesRegex(ValueError, 'call/fixture closure'):
            self.transfer('version-combiner', source, seed)


if __name__ == '__main__':
    unittest.main()
