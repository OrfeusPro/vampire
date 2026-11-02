"""Exact lifecycle source scope, dispatch flow and opaque relocation guards."""
import copy
import hashlib
import json
from pathlib import Path
import struct
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from test_vampir_update_contracts import load


def pointer(name): return dict(path=name, sha256=hashlib.sha256(name.encode()).hexdigest())


def fixture(rules, shift=0):
    functions = {role: hex(0x10000 + i * 0x1000 + shift) for i, role in enumerate(rules.SHAPES)}
    fixtures = {role: hex(0x80000 + i * 0x100 + shift) for i, role in enumerate(sorted(rules.FIXTURES))}
    tables = {role: hex(0x100000 + i * 0x100 + shift) for i, role in enumerate(sorted(rules.TABLE_ROLES))}
    source_tables = {at: '00' * 8 for role, at in tables.items() if role != 'callback_handler'}
    for role, width in (('service_base', 48), ('service_primary', 80), ('control', 16), ('backend_primary', 32)):
        source_tables[tables[role]] = '00' * width
    return dict(schema=1, family=rules.FAMILY, format=rules.REFERENCE, source='source.exe', source_sha256='a' * 64,
        functions=functions, fixtures=fixtures, leaves={hex(0x70000 + shift): rules.DISPATCH},
        call_sites={role: {} for role in functions}, table_roles=tables, source_tables=source_tables,
        source_globals={role: dict(address=hex(0x200000 + i * 8 + shift), size_bytes=8,
            storage='zero_fill', section=dict(name='.data')) for i, role in enumerate(('singleton', 'provider', 'invalid_parameter'))},
        opaque_entries=dict(allocate=dict(address=fixtures['allocate'], bytes=rules.ALLOC_PREFIX + '00000000'),
            sized_free=dict(address=fixtures['sized_free'], bytes='e900000000')),
        backend_context=pointer('backend'), backend_check=pointer('check'), verify_whole_exports=True, **rules.EXTENTS)


class ServiceLifecycleRulesTests(unittest.TestCase):
    def setUp(self): self.rules = load('service-lifecycle-rules')

    def test_twelve_whole_roots_and_virtual_dispatch_are_distinct_from_opaque_heap(self):
        c = fixture(self.rules)
        self.assertEqual(len(self.rules.roots(c)), 12)
        self.assertEqual(list(c['leaves'].values()), [self.rules.DISPATCH])
        self.assertEqual(len(bytes.fromhex(next(iter(c['leaves'].values())))), 21)
        self.assertEqual((c['service_bytes'], c['backend_bytes'], c['control_bytes']), (240, 800, 24))
        self.assertFalse(set(c['fixtures'].values()) & (set(c['functions'].values()) | set(c['leaves'])))
        self.assertNotIn('tails', c)
        self.assertNotIn('service_process_cleanup', c['functions'])

    def test_unknown_scope_extent_capsule_table_or_alias_is_rejected(self):
        for mode in ('extra-root', 'duplicate', 'heap-native', 'tail', 'budget', 'extent', 'bool',
                     'capsule', 'table-width', 'table-role', 'opaque', 'parent', 'global', 'fixture'):
            c = fixture(self.rules)
            if mode == 'extra-root': c['functions']['process.cleanup'] = '0x90000'
            if mode == 'duplicate': c['functions']['backend.reset'] = c['functions']['backend.destructor']
            if mode == 'heap-native': c['leaves'][c['fixtures']['sized_free']] = 'e900000000'
            if mode == 'tail': c['tails'] = {}
            if mode == 'budget': c['native_admission'] = True
            if mode == 'extent': c['backend_bytes'] = 784
            if mode == 'bool': c['control_bytes'] = True
            if mode == 'capsule': c['leaves'][next(iter(c['leaves']))] = 'c3'
            if mode == 'table-width': c['source_tables'][c['table_roles']['control']] = '00' * 8
            if mode == 'table-role': c['table_roles']['invented'] = '0x123'
            if mode == 'opaque': c['opaque_entries']['allocate']['bytes'] = '90' * 25
            if mode == 'parent': c['backend_check']['sha256'] = 'short'
            if mode == 'global': c['source_globals']['singleton'] = []
            if mode == 'fixture': c['fixtures']['allocate'] = c['fixtures']['sized_free']
            with self.subTest(mode=mode), self.assertRaises(ValueError): self.rules.roots(c)

    def test_dispatch_has_null_ret_and_exact_virtual_arm_without_unwind_or_calls(self):
        native = load('build-native-entry-code'); at = 0x1000
        raw = bytes.fromhex(self.rules.DISPATCH)
        image = SimpleNamespace(pe=SimpleNamespace(base=0), sections=[], containing=lambda at: None)
        with patch.object(self.rules, 'data', return_value=raw), \
                patch.object(self.rules, 'decode', wraps=self.rules.decode):
            # Use the real Capstone decoder while keeping this fixture PE-free.
            image.pe.sections = [dict(name='.text', rva=at, raw=0, raw_size=21, size=21)]
            image.data = raw; image.offset = lambda rva: rva - at
            rows = self.rules.dispatch_rows(native, image, at)
        self.assertEqual(rows[2]['direct_target'], at + 20)
        self.assertEqual((rows[5]['mnemonic'], rows[5]['operands'], rows[-1]['mnemonic']), ('jmp', 'qword ptr [rax]', 'ret'))
        with patch.object(self.rules, 'data', return_value=raw[:-1] + b'\x90'):
            with self.assertRaisesRegex(ValueError, 'capsule'): self.rules.dispatch_rows(native, image, at)
        image.containing = lambda at: (1, 2, 3)
        with self.assertRaisesRegex(ValueError, 'capsule'): self.rules.dispatch_rows(native, image, at)

    def test_decoded_dispatch_target_slot_and_instruction_position_are_checked(self):
        raw = bytes.fromhex(self.rules.DISPATCH); native = load('build-native-entry-code')
        image = SimpleNamespace(pe=SimpleNamespace(base=0, sections=[dict(name='.text', rva=0x1000, raw_size=21, raw=0, size=21)]),
            data=raw, containing=lambda at: None, offset=lambda at: at - 0x1000)
        rows = self.rules.dispatch_rows(native, image, 0x1000)
        for mode in ('conditional-target', 'virtual-slot', 'position', 'call', 'rip', 'count'):
            changed = copy.deepcopy(rows)
            if mode == 'conditional-target': changed[2]['direct_target'] += 1
            if mode == 'virtual-slot': changed[5]['operands'] = 'qword ptr [rax + 8]'
            if mode == 'position': changed[5]['address'] += 1
            if mode == 'call': changed[5]['call'] = True
            if mode == 'rip': changed[3]['rip_references'] = [0x1234]
            if mode == 'count': changed.pop()
            with self.subTest(mode=mode), patch.object(self.rules, 'decode', return_value=changed):
                with self.assertRaisesRegex(ValueError, 'decoded flow'): self.rules.dispatch_rows(native, image, 0x1000)

    def test_global_file_and_zero_fill_bounds_are_pinned(self):
        section = dict(name='.data', rva=0x1000, raw_size=16, size=32, raw=0)
        image = SimpleNamespace(pe=SimpleNamespace(base=0x140000000, sections=[section]))
        with patch.object(self.rules, 'data', return_value=b'\xaa' * 8):
            span = self.rules.global_span(image, 0x140001000)
            self.assertEqual((span['storage'], span['bytes']), ('file', 'aa' * 8))
            span = self.rules.global_span(image, 0x140001010)
            self.assertEqual(span['storage'], 'zero_fill'); self.assertNotIn('bytes', span)
            for at in (0x14000100c, 0x14000101c):
                with self.assertRaises(ValueError): self.rules.global_span(image, at)

    def test_supplied_parent_and_publisher_must_match_checked_publication(self):
        c = fixture(self.rules); parent = dict(source=c['source'], source_sha256=c['source_sha256'],
            functions=dict(publisher=c['functions']['service.publisher']))
        bindings = SimpleNamespace(rows=Mock())
        with patch.object(self.rules, 'parents', return_value=dict(parent, altered=True)):
            with self.assertRaisesRegex(ValueError, 'supplied backend'):
                self.rules.project(None, None, bindings, None, parent, c['backend_context'], c['backend_check'], c['functions'])
        bindings.rows.assert_not_called()
        functions = dict(c['functions'], **{'service.publisher': '0x9999'})
        with patch.object(self.rules, 'parents', return_value=parent):
            with self.assertRaisesRegex(ValueError, 'publisher parent'):
                self.rules.project(None, None, bindings, None, parent, c['backend_context'], c['backend_check'], functions)

    def test_transfer_only_discovers_eleven_roots_and_preserves_exact_dispatch(self):
        baseline, current = fixture(self.rules), fixture(self.rules, 0x300000)
        common = load('update-native-archive-wire'); pairing = SimpleNamespace(pair_rows=Mock())
        utility = SimpleNamespace(unique_root=Mock(side_effect=lambda n, b, x, y, at: at + 0x300000), add_link=common.add_link)
        old = {role: [dict(address=int(at, 16))] for role, at in baseline['functions'].items()}
        new = {role: [dict(address=int(at, 16))] for role, at in current['functions'].items()}
        parent = dict(functions=dict(publisher=current['functions']['service.publisher']))
        original = self.rules.load
        def decoded(n, im, at, size): return [dict(address=at, direct_target=at + 0x40)]
        def dispatch(n, im, at): return [dict(address=at + off) for off in (0, 4, 7, 9, 12, 17, 20)]
        with patch.object(self.rules, 'validate_static', return_value=old), \
                patch.object(self.rules, 'project', return_value=(current, new)) as project, \
                patch.object(self.rules, 'decode', side_effect=decoded), patch.object(self.rules, 'dispatch_rows', side_effect=dispatch), \
                patch.object(self.rules, 'load', side_effect=lambda name: utility if name == 'update-native-archive-wire'
                    else pairing if name == 'login-backend-wire-rules' else original(name)):
            mapping = {}; value, detail = self.rules.transfer(None, None, None, 'before', 'after', baseline, mapping, parent,
                backend_pointer=pointer('target'), backend_check=pointer('target-check'))
        self.assertIs(value, current); self.assertEqual(utility.unique_root.call_count, 11)
        self.assertEqual(project.call_args.args[7], current['functions'])
        self.assertEqual(pairing.pair_rows.call_count, 14)  # Twelve whole plus two opaque entries, not native capsule tails.
        self.assertEqual(mapping[int(next(iter(baseline['leaves'])), 16) + 17], int(next(iter(current['leaves'])), 16) + 17)
        self.assertEqual((detail['whole_roots'], detail['control_dispatch_capsules'], detail['opaque_native_capsules']), (12, 1, 0))

    def test_tool_closure_includes_every_used_decoder_and_parent_api(self):
        tools = {Path(path).name for path in self.rules.tools()}
        self.assertTrue({'service-lifecycle-rules.py', 'update-native-login-backend-wire.py', 'update-native-archive-wire.py',
            'login-dispatch-rules.py', 'login-state-flow-rules.py', 'login-handler-transfer-rules.py',
            'version-system-transfer-rules.py', 'update-bindings.py', 'update-native-contexts.py',
            'login-backend-wire-rules.py', 'login-backend-wire-source.py', 'build-object-zero-init-code.py',
            'audit-launcher-shape-11318.py', 'knowledge-index.py', 'extract-native-enums.py'} <= tools)

    def test_exports_require_all_twelve_exact_bodies_and_complete_metadata(self):
        c = fixture(self.rules)
        rows = {role: [dict(address=int(at, 16), bytes='c3')] for role, at in c['functions'].items()}
        functions = [dict(address=at, instructions=[dict(address=at, bytes='c3')],
            decompilation_completed=True, block_coverage_complete=True, direct_flow_coverage_complete=True)
            for at in c['functions'].values()]
        original = self.rules.load
        with TemporaryDirectory() as folder:
            root = Path(folder); path = root/'ghidra/request-exports'/c['source_sha256']/'run-test'/'details.json'
            path.parent.mkdir(parents=True)
            for mode in ('valid', 'missing-root', 'prefix', 'duplicate', 'block', 'direct-flow', 'source', 'hash'):
                selected = copy.deepcopy(functions)
                if mode == 'missing-root': selected.pop()
                if mode == 'prefix': selected[0]['instructions'] = []
                if mode == 'duplicate': selected[0]['instructions'] *= 2
                if mode == 'block': selected[0]['block_coverage_complete'] = False
                if mode == 'direct-flow': selected[0]['direct_flow_coverage_complete'] = False
                path.write_text(json.dumps(dict(new_source_sha256='b' * 64 if mode == 'source' else c['source_sha256'],
                    functions=selected)), encoding='utf-8')
                c['exports'] = {'run-test': 'f' * 64 if mode == 'hash' else hashlib.sha256(path.read_bytes()).hexdigest()}
                with self.subTest(mode=mode), patch.object(self.rules, 'validate_static', return_value=rows), \
                        patch.object(self.rules, 'load', side_effect=lambda name: SimpleNamespace(normalize_function=Mock())
                            if name == 'audit-launcher-shape-11318' else original(name)):
                    if mode == 'valid': self.rules.export_coverage(root, c, None, None, None)
                    else:
                        with self.assertRaises(ValueError): self.rules.export_coverage(root, c, None, None, None)


if __name__ == '__main__': unittest.main()
