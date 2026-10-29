"""Pure Login metadata role/data admission; no native, Ghidra or research writes."""
import copy
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_vampir_update_contracts import load

RULES = load('login-metadata-transfer-rules')
NATIVE = load('build-native-entry-code')


def instruction(raw, at):
    decoder = NATIVE.capstone.Cs(NATIVE.capstone.CS_ARCH_X86, NATIVE.capstone.CS_MODE_64)
    decoder.detail = True
    result = list(decoder.disasm(raw, at))
    if len(result) != 1 or result[0].size != len(raw):
        raise AssertionError('Incomplete synthetic instruction')
    ins = result[0]
    call, branch = ins.group(NATIVE.capstone.CS_GRP_CALL), ins.group(NATIVE.capstone.CS_GRP_JUMP)
    direct = ins.operands[0].imm if (call or branch) and ins.operands and ins.operands[0].type == NATIVE.X86_OP_IMM else None
    return dict(address=at, bytes=raw.hex(), mnemonic=ins.mnemonic, operands=ins.op_str, call=call,
                branch=branch, direct_target=direct, rip_references=[at + ins.size + op.mem.disp for op in ins.operands
                    if op.type == NATIVE.X86_OP_MEM and op.mem.base == NATIVE.X86_REG_RIP])


class Image:
    def __init__(self, shift):
        self.shift, self.memory, self.code, self.roots, self.imports = shift, {}, {}, {}, {}
        self.pe = SimpleNamespace(base=0, sections=[dict(name='.data', rva=0x900000 + shift, raw_size=0, size=0x1000)])

    def entry(self, at):
        self.roots[at] = (at, at + 0x100, 0)

    def containing(self, at):
        return at if at in self.roots else None

    def read(self, at, size):
        for origin, raw in self.memory.items():
            if origin <= at and at + size <= origin + len(raw):
                return bytes(raw[at - origin:at - origin + size])
        raise ValueError('Synthetic data missing')


class MetadataTransferTests(unittest.TestCase):
    def setUp(self):
        self.utility = load('version-system-transfer-rules')
        original = RULES.load
        self.before, self.after = Image(0), Image(0x1000000)
        self.bindings = SimpleNamespace(rows=lambda native, image, at: image.code[at])
        self.addCleanup(patch.stopall)
        patch.object(RULES, 'load', side_effect=lambda name: self.utility if name == 'version-system-transfer-rules' else original(name)).start()
        patch.object(self.utility, 'image_bytes', side_effect=lambda image, at, size: image.read(at, size)).start()
        patch.object(self.utility, 'named_import', side_effect=self.named_import).start()

    def named_import(self, image, slot, name, dll):
        if image.imports.get(slot) != (name, dll.lower()):
            raise ValueError('Synthetic named import identity differs')
        return dict(slot=hex(slot), name=name, dll=dll.lower())

    def fixture(self):
        functions = {role: 0x10000 + number * 0x10000 for number, role in enumerate(RULES.FUNCTIONS)}
        fixtures = {role: 0x100000 + number * 0x1000 for number, role in enumerate(sorted(RULES.FIXTURES - set(RULES.SYNTHETIC)))}
        fixtures.update(RULES.SYNTHETIC)
        globals_ = dict(optional_manager=0x900000, log_level=0x900100, log_enabled=0x800100, cookie=0x800000)
        c = dict(schema=1, functions={key: hex(at) for key, at in functions.items()},
                 helpers=dict(memcpy='0x180000'), fixtures={key: hex(at) for key, at in fixtures.items()},
                 globals={key: hex(at) for key, at in globals_.items()}, collector_order=list(RULES.ORDER),
                 call_sites={}, verify_whole_exports=True, exports={'parent-owned': 'unchanged'}, source_sha256='parent-owned')
        for image in (self.before, self.after):
            shift = image.shift
            image.memory[globals_['log_enabled'] + shift] = bytearray(b'\1')
            image.memory[globals_['cookie'] + shift] = bytearray.fromhex('32a2df2d992b0000')
            literal_number = 0
            for role, origin in functions.items():
                at = origin + shift
                image.entry(at)
                selected = []
                for name, offsets in RULES.CALL_GROUPS[role].items():
                    for offset in offsets:
                        where = at + offset
                        if name.startswith('qword ptr '):
                            raw = b'\xff\x10' if name == 'qword ptr [rax]' else b'\xff\x50\x08'
                        else:
                            target = functions[name[5:]] if name.startswith('root:') else fixtures[name]
                            raw = b'\xe8' + struct.pack('<i', target + shift - where - 5)
                        selected.append(instruction(raw, where))
                for offset, raw in RULES.LITERALS[role].items():
                    pointer = 0x300000 + literal_number * 0x1000 + shift
                    literal_number += 1
                    image.memory[pointer] = bytearray(raw)
                    selected.append(instruction(b'\x48\x8d\x15' + struct.pack('<i', pointer - at - offset - 7), at + offset))
                for offset, name in RULES.GLOBAL_RIPS[role].items():
                    pointer = globals_[name] + shift
                    selected.append(instruction(b'\x48\x8b\x05' + struct.pack('<i', pointer - at - offset - 7), at + offset))
                end = max(row['address'] + len(bytes.fromhex(row['bytes'])) for row in selected)
                selected.append(instruction(b'\xc3', end))
                image.code[at] = sorted(selected, key=lambda row: row['address'])
            for role, at in fixtures.items():
                if role in RULES.SYNTHETIC:
                    continue
                if role in RULES.LEAF_BYTES:
                    image.memory[at + shift] = bytearray(RULES.LEAF_BYTES[role])
                elif role != 'memset':
                    image.entry(at + shift)
            for at, slot, name in ((0x180000, 0x820000, 'memcpy'), (fixtures['memset'], 0x820100, 'memset')):
                image.memory[at + shift] = bytearray(b'\xff\x25' + struct.pack('<i', slot - at - 6))
                image.imports[slot + shift] = (name, 'vcruntime140.dll')
        c['call_sites'] = RULES.call_sites({role: self.before.code[at] for role, at in functions.items()})
        seed = {functions['collector']: functions['collector'] + self.after.shift, 0x180000: 0x180000 + self.after.shift}
        return c, seed

    def transfer(self, c, seed):
        return RULES.transfer(NATIVE, self.bindings, self.before, self.after, c, seed)

    def test_six_roots_follow_actual_call_closure_and_metadata_is_parent_owned(self):
        c, seed = self.fixture()
        original = copy.deepcopy(c)
        result, detail = self.transfer(c, seed)
        self.assertEqual(c, original)
        self.assertEqual(set(result), RULES.FIELDS)
        self.assertEqual(len(RULES.roots(result)), 6)
        self.assertEqual(result['functions']['move'], '0x1060000')
        self.assertEqual(result['helpers']['memcpy'], '0x1180000')
        self.assertEqual(detail['userinfo_bytes'], 0x250)
        self.assertEqual(detail['userinfo_fields'], list(range(0, 0x250, 16)))
        self.assertEqual(detail['collector_order'].count('I_World'), 2)
        self.assertEqual(detail['fixtures']['optional_resolve']['size'], 10)
        self.assertEqual(seed[int(c['functions']['move'], 16)], int(result['functions']['move'], 16))
        self.assertNotIn('source_sha256', result)

    def test_optional_native_scope_and_unknown_function_or_fixture_are_rejected(self):
        for mutation in (lambda c: c.update(native_sdk={}), lambda c: c.update(function_budget=32),
                         lambda c: c['functions'].update(other='0x123'), lambda c: c['fixtures'].update(other='0x123')):
            c, seed = self.fixture()
            mutation(c)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.transfer(c, seed)

    def test_collector_must_have_independently_proved_caller_edge(self):
        c, seed = self.fixture()
        del seed[int(c['functions']['collector'], 16)]
        with self.assertRaisesRegex(ValueError, 'caller constraint'):
            self.transfer(c, seed)

    def test_roots_fixture_and_memcpy_aliases_fail_closed(self):
        for group, key, other in (('functions', 'loader', 'root'), ('fixtures', 'free', 'root'),
                                  ('fixtures', 'free', 'fixture'), ('helpers', 'memcpy', 'root'),
                                  ('helpers', 'memcpy', 'fixture')):
            c, _ = self.fixture()
            c[group][key] = c['functions']['collector'] if other == 'root' else c['fixtures']['append']
            with self.subTest(group=group, key=key, other=other), self.assertRaisesRegex(ValueError, 'alias'):
                RULES.roots(c)

    def test_synthetic_destructor_hooks_are_fixed_not_relocated_code(self):
        c, seed = self.fixture()
        result, detail = self.transfer(c, seed)
        for role, at in RULES.SYNTHETIC.items():
            self.assertEqual(result['fixtures'][role], hex(at))
            self.assertEqual(detail['fixtures'][role]['kind'], 'synthetic-hook')
        c['fixtures']['weak_destroy'] = '0x2800e020'
        with self.assertRaisesRegex(ValueError, 'synthetic destructor'):
            RULES.roots(c)

    def test_whole_instruction_and_call_site_changes_are_not_a_relocation(self):
        c, seed = self.fixture()
        at = int(c['functions']['collector'], 16) + self.after.shift
        self.after.code[at][-1] = instruction(b'\x90', self.after.code[at][-1]['address'])
        with self.assertRaisesRegex(ValueError, 'instruction shape'):
            self.transfer(c, seed)
        c, seed = self.fixture()
        c['call_sites'][next(iter(c['call_sites']))] = dict(target='0xdead')
        with self.assertRaisesRegex(ValueError, 'baseline call sites'):
            self.transfer(c, seed)

    def test_direct_callee_role_cannot_be_reclassified_in_baseline(self):
        c, seed = self.fixture()
        c['fixtures']['marketing'], c['fixtures']['backend'] = c['fixtures']['backend'], c['fixtures']['marketing']
        with self.assertRaisesRegex(ValueError, 'callee role'):
            self.transfer(c, seed)

    def test_virtual_destructor_slot_is_exact_and_rip_dispatch_cannot_replace_it(self):
        c, seed = self.fixture()
        all_rows = {role: copy.deepcopy(self.before.code[int(at, 16)]) for role, at in c['functions'].items()}
        row = next(row for row in all_rows['loader'] if row['address'] == int(c['functions']['loader'], 16) + 166)
        row['operands'] = 'qword ptr [rax + 0x10]'
        with self.assertRaisesRegex(ValueError, 'virtual destructor'):
            RULES.call_roles(c, all_rows)

    def test_exact_literal_keys_formats_and_diagnostic_text_are_pinned(self):
        for role, offset in (('collector', 255), ('collector', 1627), ('selector', 201), ('writer', 66), ('writer', 397)):
            c, seed = self.fixture()
            row = next(row for row in self.after.code[int(c['functions'][role], 16) + self.after.shift]
                       if row['address'] == int(c['functions'][role], 16) + self.after.shift + offset)
            self.after.memory[row['rip_references'][0]][0] ^= 1
            with self.subTest(role=role, offset=offset), self.assertRaisesRegex(ValueError, 'compiled literal'):
                self.transfer(c, seed)

    def test_unknown_rip_and_global_role_substitution_are_rejected(self):
        c, seed = self.fixture()
        at = int(c['functions']['move'], 16)
        for image in (self.before, self.after):
            where = at + image.shift + 5000
            pointer = int(c['globals']['cookie'], 16) + image.shift
            image.code[at + image.shift].append(instruction(b'\x48\x8d\x15' + struct.pack('<i', pointer - where - 7), where))
        with self.assertRaisesRegex(ValueError, 'RIP role layout'):
            self.transfer(c, seed)
        c, seed = self.fixture()
        c['globals']['optional_manager'] = c['globals']['log_level']
        with self.assertRaisesRegex(ValueError, 'global input linkage'):
            self.transfer(c, seed)

    def test_static_global_values_and_storage_kind_are_required(self):
        c, seed = self.fixture()
        self.after.memory[int(c['globals']['log_enabled'], 16) + self.after.shift][0] = 0
        with self.assertRaisesRegex(ValueError, 'typed global input'):
            self.transfer(c, seed)
        c, seed = self.fixture()
        self.after.memory[int(c['globals']['optional_manager'], 16) + self.after.shift] = bytearray(8)
        with self.assertRaisesRegex(ValueError, 'typed global input'):
            self.transfer(c, seed)

    def test_all_four_non_unwind_fixture_bodies_are_pinned(self):
        for role in RULES.LEAF_BYTES:
            c, seed = self.fixture()
            self.after.memory[int(c['fixtures'][role], 16) + self.after.shift][-1] ^= 1
            with self.subTest(role=role), self.assertRaisesRegex(ValueError, 'bounded fixture leaf'):
                self.transfer(c, seed)

    def test_real_fixture_boundary_and_import_identity_are_required(self):
        c, seed = self.fixture()
        del self.after.roots[int(c['fixtures']['marketing'], 16) + self.after.shift]
        with self.assertRaisesRegex(ValueError, 'concrete unwind'):
            self.transfer(c, seed)
        c, seed = self.fixture()
        self.after.imports[0x820100 + self.after.shift] = ('memcpy', 'vcruntime140.dll')
        with self.assertRaisesRegex(ValueError, 'import identity'):
            self.transfer(c, seed)

    def test_duplicate_collector_key_is_required_in_its_original_order(self):
        c, seed = self.fixture()
        c['collector_order'] = list(dict.fromkeys(c['collector_order']))
        with self.assertRaisesRegex(ValueError, 'collector order'):
            self.transfer(c, seed)

    def test_global_intervals_are_disjoint_in_both_sources(self):
        c, seed = self.fixture()
        all_rows = {role: self.before.code[int(at, 16)] for role, at in c['functions'].items()}
        common = load('update-native-archive-wire')
        for role, old in c['functions'].items():
            at = int(old, 16)
            common.pair_rows(NATIVE, self.before.code[at], self.after.code[at + self.after.shift], seed)
        # Two zero-filled globals may carry valid bytes and still overlap.
        c['globals']['log_level'] = hex(int(c['globals']['optional_manager'], 16) + 4)
        for row in all_rows['writer']:
            if row['address'] - int(c['functions']['writer'], 16) in (45, 118):
                row['rip_references'] = [int(c['globals']['log_level'], 16)]
        seed[int(c['globals']['log_level'], 16)] = int(c['globals']['log_level'], 16) + self.after.shift
        with self.assertRaisesRegex(ValueError, 'roles overlap'):
            RULES.typed_inputs(self.before, self.after, c, seed, all_rows)


if __name__ == '__main__':
    unittest.main()
