"""Typed scope, relocated helper edges and complete export rejection; no replay."""
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


def pointer(name): return dict(path=name, sha256='a' * 64)


def context(shift=0):
    roles = ('archive.raw', 'vector.resize', 'vector.grow', 'queue.append', 'transport')
    functions = {role: hex(0x1000 + i * 0x100 + shift) for i, role in enumerate(roles)}
    helpers = {role: hex(0x8000 + i * 0x100 + shift) for i, role in enumerate(('allocate', 'free', 'memcpy', 'memmove', 'memset'))}
    table = [0x20000 + i * 16 + shift for i in range(31)]
    table[17] = int(functions['archive.raw'], 16)
    return dict(schema=1, family='buffer-transport', format='reference-buffer-transport',
        source='source.exe', source_sha256=('a' if shift == 0 else 'b') * 64,
        functions=functions, helpers=helpers, leaves={hex(0x7000 + shift): '895108c3'},
        call_sites={role: {} for role in roles}, wire_context=pointer('wire'), wire_check=pointer('check'),
        source_inputs=dict(archive_table=dict(address=hex(0x30000 + shift), bytes=struct.pack('<31Q', *table).hex()),
            allocation_entry=dict(address=helpers['allocate'], bytes='4885c9b801000000ba10000000480f45c1488bc8e900000000'),
            free_entry=dict(address=helpers['free'], bytes='e900000000')),
        vector_bytes=24, queue_bytes=32, archive_bytes=64, transport_bytes=400, verify_whole_exports=True)


class BufferTransportRulesTests(unittest.TestCase):
    def setUp(self): self.rules = load('buffer-transport-rules')

    def test_exact_inventory_and_extents_do_not_admit_allocator_or_tail(self):
        c = context()
        self.assertEqual(self.rules.roots(c), {int(at, 16) for at in c['functions'].values()})
        self.assertEqual((len(c['functions']), list(c['leaves'].values())), (5, ['895108c3']))
        self.assertFalse(set(c['functions'].values()) & set(c['helpers'].values()))
        value = self.rules.functional(c); value['helpers']['free'] = '0x1'
        self.assertNotEqual(c['helpers']['free'], '0x1')

    def test_added_scope_aliases_bad_prefix_and_malformed_parent_are_rejected(self):
        for mode in ('tail', 'budget', 'extra-root', 'duplicate', 'helper-alias', 'helper-key',
                     'leaf', 'extent', 'bool', 'parent', 'input', 'allocation', 'free', 'source'):
            c = context()
            if mode == 'tail': c['tails'] = {'0x1': 'e900000000'}
            if mode == 'budget': c['function_budget'] = 64
            if mode == 'extra-root': c['functions']['backend'] = '0x9000'
            if mode == 'duplicate': c['functions']['transport'] = c['functions']['vector.grow']
            if mode == 'helper-alias': c['helpers']['free'] = c['functions']['transport']
            if mode == 'helper-key': c['helpers']['socket'] = '0x9000'
            if mode == 'leaf': c['leaves']['0x7000'] = 'c3'
            if mode == 'extent': c['transport_bytes'] = 800
            if mode == 'bool': c['vector_bytes'] = True
            if mode == 'parent': c['wire_check']['sha256'] = 'short'
            if mode == 'input': c['source_inputs']['free_entry']['extra'] = True
            if mode == 'allocation': c['source_inputs']['allocation_entry']['bytes'] = '90' * 25
            if mode == 'free': c['source_inputs']['free_entry']['bytes'] = 'e900000000c3'
            if mode == 'source': c['source_sha256'] = 'a' * 63
            with self.subTest(mode=mode), self.assertRaises(ValueError): self.rules.roots(c)

    def test_direct_anchors_require_actual_five_byte_call_or_declared_tail(self):
        row = dict(address=0x1000, bytes='e800000000', mnemonic='call', call=True,
                   branch=False, direct_target=0x1005)
        self.assertEqual(self.rules.direct([row], 0), '0x1005')
        for key, value in (('bytes', 'ffd0'), ('mnemonic', 'jmp'), ('call', False),
                           ('branch', True), ('direct_target', None)):
            changed = dict(row, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError): self.rules.direct([changed], 0)
        tail = dict(row, bytes='e900000000', mnemonic='jmp', call=False, branch=True)
        self.assertEqual(self.rules.direct([tail], 0, jump=True), '0x1005')
        with self.assertRaises(ValueError): self.rules.direct([tail], 0)

    def test_crt_import_identity_uses_pe_name_and_dll_not_just_ff25(self):
        utility = SimpleNamespace(import_at=Mock(return_value=dict(dll='VCRUNTIME140.dll', name='memmove')))
        image = SimpleNamespace(data=b'pe')
        with patch.object(self.rules, 'data', return_value=bytes.fromhex('ff250a000000')), \
                patch.object(self.rules, 'load', return_value=utility):
            self.rules.import_identity(image, 0x1000, 'memmove')
            self.assertEqual(utility.import_at.call_args.args[2], 0x1010)
            utility.import_at.return_value['name'] = 'memcpy'
            with self.assertRaisesRegex(ValueError, 'named CRT'): self.rules.import_identity(image, 0x1000, 'memmove')
            utility.import_at.return_value = dict(dll='foreign.dll', name='memmove')
            with self.assertRaisesRegex(ValueError, 'named CRT'): self.rules.import_identity(image, 0x1000, 'memmove')
        with patch.object(self.rules, 'data', return_value=b'\x90' * 6):
            with self.assertRaisesRegex(ValueError, 'import thunk'): self.rules.import_identity(image, 0x1000, 'memmove')

    def test_parent_source_and_report_are_checked_without_parent_replay(self):
        c = context(); wire = dict(family='archive-wire', source=c['source'], source_sha256=c['source_sha256'], transfer_proof=pointer('proof'))
        check = {'accepted': True}; api = SimpleNamespace(report_valid=Mock())
        core = SimpleNamespace(checked=lambda root, ptr, category: wire if category == 'generated-native-contexts' else check)
        with patch.object(self.rules, 'load', side_effect={'portable-native-family': core, 'update-native-archive-wire': api}.__getitem__):
            self.assertIs(self.rules.parents(None, c), wire)
            api.report_valid.assert_called_once_with(check, wire, c['wire_context']['sha256'])
            wire['source_sha256'] = 'b' * 64
            with self.assertRaisesRegex(ValueError, 'same-source'): self.rules.parents(None, c)

    def test_project_rejects_a_supplied_parent_that_does_not_match_checked_pointer(self):
        c = context(); wire = dict(source=c['source'], source_sha256=c['source_sha256'],
            archive=dict(raw=c['functions']['archive.raw'], growth=c['functions']['vector.resize']))
        bindings = SimpleNamespace(rows=Mock())
        with patch.object(self.rules, 'parents', return_value=dict(wire, altered=True)):
            with self.assertRaisesRegex(ValueError, 'supplied wire'):
                self.rules.project(None, None, bindings, None, wire, c['wire_context'], c['wire_check'], c['functions'])
        bindings.rows.assert_not_called()

    def test_tool_closure_pins_source_decoders_parent_api_and_export_utilities(self):
        names = {Path(path).name for path in self.rules.tools()}
        self.assertTrue({'buffer-transport-rules.py', 'update-native-archive-wire.py',
            'login-dispatch-rules.py', 'login-handler-transfer-rules.py', 'version-system-transfer-rules.py',
            'login-backend-wire-source.py', 'login-backend-wire-rules.py', 'portable-native-family.py',
            'build-object-zero-init-code.py', 'extract-native-enums.py', 'update-bindings.py',
            'update-native-contexts.py', 'audit-launcher-shape-11318.py', 'knowledge-index.py'} <= names)

    def test_transfer_discovers_only_four_new_roots_and_preserves_resize_tail(self):
        before, after, baseline, current = object(), object(), context(), context(0x100000)
        common = load('update-native-archive-wire'); pairing = SimpleNamespace(pair_rows=Mock())
        selected = SimpleNamespace(unique_root=Mock(side_effect=lambda n, b, x, y, at: at + 0x100000), add_link=common.add_link)
        old = {role: [dict(address=int(at, 16))] for role, at in baseline['functions'].items()}
        new = {role: [dict(address=int(at, 16))] for role, at in current['functions'].items()}
        wire = dict(archive=dict(raw=current['functions']['archive.raw']))
        def decoded(native, image, at, size): return [dict(address=at, direct_target=at + 0x40)]
        original = self.rules.load
        with patch.object(self.rules, 'validate_static', return_value=old), \
                patch.object(self.rules, 'project', return_value=(current, new)) as project, \
                patch.object(self.rules, 'decode', side_effect=decoded), \
                patch.object(self.rules, 'load', side_effect=lambda name: selected if name == 'update-native-archive-wire'
                    else pairing if name == 'login-backend-wire-rules' else original(name)):
            mapping = {}; value, detail = self.rules.transfer(None, None, None, before, after, baseline, mapping, wire,
                wire_pointer=pointer('target-wire'), wire_check=pointer('target-check'))
        self.assertIs(value, current)
        self.assertEqual(selected.unique_root.call_count, 4)
        functions = project.call_args.args[7]
        self.assertEqual(functions, current['functions'])
        pairs = pairing.pair_rows.call_args_list
        self.assertEqual(len(pairs), 8)  # Five whole, one returning leaf, two opaque entries.
        for call in pairs[:5]:
            role = next(role for role in old if call.args[1] is old[role])
            self.assertEqual(call.kwargs['declared_tails'], {int(baseline['functions']['vector.grow'], 16)}
                if role == 'vector.resize' else ())
        self.assertEqual((detail['whole_roots'], detail['returning_leaves'], detail['tail_fragments']), (5, 1, 0))
        self.assertIs(detail['native_allocator'], False)

    def test_export_prefix_or_missing_block_coverage_cannot_admit_a_whole_root(self):
        c = context(); rows = {role: [dict(address=int(at, 16), bytes='c3')] for role, at in c['functions'].items()}
        with TemporaryDirectory() as folder:
            root = Path(folder); run = 'run-test'; path = root/'ghidra/request-exports'/c['source_sha256']/run/'details.json'
            path.parent.mkdir(parents=True)
            functions = [dict(address=at, instructions=[dict(address=at, bytes='c3')],
                decompilation_completed=True, block_coverage_complete=True, direct_flow_coverage_complete=True)
                for at in c['functions'].values()]
            original = self.rules.load
            for mode in ('prefix', 'block', 'duplicate', 'missing'):
                export = copy.deepcopy(functions)
                if mode == 'prefix': export[0]['instructions'] = []
                if mode == 'block': export[0]['block_coverage_complete'] = False
                if mode == 'duplicate': export[0]['instructions'] *= 2
                if mode == 'missing': export.pop()
                path.write_text(json.dumps(dict(new_source_sha256=c['source_sha256'], functions=export)), encoding='utf-8')
                c['exports'] = {run: hashlib.sha256(path.read_bytes()).hexdigest()}
                with self.subTest(mode=mode), patch.object(self.rules, 'validate_static', return_value=rows), \
                        patch.object(self.rules, 'load', side_effect=lambda name: SimpleNamespace(normalize_function=Mock())
                            if name == 'audit-launcher-shape-11318' else original(name)):
                    with self.assertRaises(ValueError): self.rules.export_coverage(root, c, None, None, None)


if __name__ == '__main__': unittest.main()
