"""Shared source/roles/aliases must close before any reader-handler execution."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from test_vampir_update_contracts import load

RULE = load('login-composition-rules')


def components():
    names = sorted(RULE.PACKET)
    reader = dict(family='login-strings-buffer', source_sha256='a' * 64, source=str(Path('fixture.exe').resolve()),
        native_strings=True, layout=dict(packet_bytes=352), helpers=dict(memcpy='0x5000'), packet_table='0x6000',
        id_getter='0x4000', functions={name: hex(0x1000 + i*16) for i, name in enumerate(names)},
        leaves={'0x4000':'b804000000c3', **{hex(0x4010+i*16):'c3' for i in range(5)}}, string_constructor='0x7000',
        input=dict(source_sha256='a' * 64, functions={name:hex(0x2000+i*16) for i,name in enumerate(sorted(RULE.INPUT))},
            string_fixtures={name:hex(0x7100+i*16) for i,name in enumerate(('growth','utf16_allocate','assign','free','cpp_free','security'))}),
        exports={'run-input':'b' * 64})
    handler = dict(family='login-full-handler', source_sha256=reader['source_sha256'], source=reader['source'],
        format='login-full-handler-v1', packet_bytes=352, helpers=copy.deepcopy(reader['helpers']),
        packet_table=reader['packet_table'], id_getter=reader['id_getter'], functions=dict(handler='0x3000',gate='0x3100'),
        leaves={'0x4000':'b804000000c3'}, fixtures=dict(free=reader['input']['string_fixtures']['free'],
            unsupported_141426950=reader['string_constructor'], state='0x8000'), exports={'run-handler':'c' * 64},
        gate_context=dict(path='gate',sha256='d'*64))
    return reader, handler, dict(path='reader',sha256='e'*64), dict(path='handler',sha256='f'*64)


class CompositionRulesTests(unittest.TestCase):
    def test_projection_has_exact_22_roots_six_leaves_and_json_stable_data(self):
        args=components();c=RULE.compose(*args)
        self.assertEqual(len(RULE.roots(c)),22);self.assertEqual(len(c['leaves']),6)
        self.assertEqual(set(c['functions']),RULE.NAMES)
        self.assertEqual(c,json.loads(json.dumps(c)))
        self.assertEqual(c['exports'],dict(args[0]['exports'],**args[1]['exports']))

    def test_component_source_table_helper_and_id_disagreements_are_blockers(self):
        for key,value in (('source_sha256','1'*64),('source','different.exe'),('packet_table','0x6008'),
                ('id_getter','0x4008'),('helpers',dict(memcpy='0x5010'))):
            with self.subTest(key=key):
                args=list(components());args[1][key]=value
                with self.assertRaises(ValueError):RULE.compose(*args)

    def test_wrong_component_family_layout_or_native_strings_cannot_widen_scope(self):
        for index,key,value in ((0,'family','login-nested'),(1,'family','foreign'),(0,'native_strings',False),
                (0,'layout',dict(packet_bytes=320)),(1,'packet_bytes',320),(1,'format','legacy-reviewed-handler')):
            with self.subTest(key=key,value=value):
                args=list(components());args[index][key]=value
                with self.assertRaises(ValueError):RULE.compose(*args)

    def test_inner_input_source_and_fixture_role_changes_are_rejected(self):
        for change in (dict(source_sha256='1'*64),dict(source='other.exe'),dict(string_fixtures={})):
            args=list(components());args[0]['input'].update(change)
            with self.assertRaises(ValueError):RULE.compose(*args)

    def test_native_root_and_leaf_shadowing_is_rejected(self):
        for kind in ('root','leaf','copy'):
            args=list(components())
            args[1]['functions']['handler']=dict(root=next(iter(args[0]['functions'].values())),leaf='0x4000',copy='0x5000')[kind]
            with self.assertRaises(ValueError):RULE.compose(*args)

    def test_shared_id_bytes_conflict_is_rejected_before_mapping(self):
        args=list(components());args[1]['leaves']['0x4000']='c3'
        with self.assertRaisesRegex(ValueError,'shared leaf'):RULE.compose(*args)

    def test_shared_fixture_aliases_are_explicit_and_phase_safe(self):
        for name in ('free','unsupported_141426950'):
            args=list(components());args[1]['fixtures'][name]='0x9000'
            with self.assertRaisesRegex(ValueError,'shared storage'):RULE.compose(*args)
        for at in ('0x1000','0x4000','0x5000',components()[0]['input']['string_fixtures']['growth']):
            args=list(components());args[1]['fixtures']['new']=at
            with self.assertRaisesRegex(ValueError,'fixture aliases'):RULE.compose(*args)

    def test_extra_or_missing_root_roles_are_rejected(self):
        for which in ('packet','input','handler'):
            args=list(components());target=args[0]['functions'] if which=='packet' else args[0]['input']['functions'] if which=='input' else args[1]['functions']
            target['unreviewed']='0x9990'
            with self.assertRaises(ValueError):RULE.compose(*args)

    def test_context_cannot_add_budget_scope_or_native_capability_flags(self):
        c=RULE.compose(*components())
        for field in ('function_budget','budget_scope','native_reader','native_handler','native_admission'):
            with self.assertRaises(ValueError):RULE.roots(dict(c,**{field:True}))
        with self.assertRaises(ValueError):RULE.roots(dict(c,packet_bytes=True))

    def test_pointers_must_be_distinct_and_have_full_sha(self):
        args=list(components())
        for bad in (dict(path='reader',sha256='short'),dict(path='',sha256='a'*64),dict(path='reader',sha256='a'*64,extra=True)):
            args[2]=bad
            with self.assertRaises(ValueError):RULE.compose(*args)
        args=list(components());args[3]=args[2]
        with self.assertRaisesRegex(ValueError,'pointers alias'):RULE.compose(*args)

    def test_component_exports_cannot_conflict(self):
        args=list(components());args[1]['exports']={'run-input':'9'*64}
        with self.assertRaisesRegex(ValueError,'export hashes conflict'):RULE.compose(*args)

    def test_changed_checked_component_projection_blocks_before_export_access(self):
        reader,handler,rp,hp=components();c=RULE.compose(reader,handler,rp,hp);c['packet_table']='0x6008'
        core=SimpleNamespace(checked=Mock(side_effect=[reader,handler]))
        with patch.object(RULE,'load',return_value=core):
            with self.assertRaisesRegex(ValueError,'projection differs'):
                RULE.export_coverage(None,c,None,None,None)
        self.assertEqual(core.checked.call_count,2)

    def export_fixture(self, directory):
        reader,handler,rp,hp=components();c=RULE.compose(reader,handler,rp,hp)
        wanted={at:[dict(address=at,bytes='c3')] for at in RULE.roots(c)}
        functions=[dict(address=hex(at),decompilation_completed=True,block_coverage_complete=True,
            direct_flow_coverage_complete=True,instructions=[dict(address=hex(at),bytes='c3')]) for at in sorted(wanted)]
        report=dict(new_source_sha256=c['source_sha256'],functions=functions)
        path=Path(directory)/'ghidra/request-exports'/c['source_sha256']/'run-fixture/details.json'
        path.parent.mkdir(parents=True);path.write_text(json.dumps(report))
        c['exports']={'run-fixture':hashlib.sha256(path.read_bytes()).hexdigest()}
        checked=lambda root,pointer,category: reader if pointer==rp else handler if pointer==hp else dict(function=handler['functions']['gate'])
        core=SimpleNamespace(checked=checked,digest=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest())
        child=SimpleNamespace(export_coverage=Mock());normalize=Mock()
        modules={'portable-native-family':core,'update-native-login-input':SimpleNamespace(select=lambda _:child),
            'update-native-login-full':SimpleNamespace(select=lambda:child),
            'result-gate-transfer-rules':SimpleNamespace(rows=lambda native,image,gate:wanted[int(gate['function'],16)]),
            'audit-launcher-shape-11318':SimpleNamespace(normalize_function=normalize)}
        bindings=SimpleNamespace(rows=lambda native,image,at:wanted[at])
        return c,path,report,modules,bindings,child,normalize

    def test_outer_exact_exports_delegate_children_and_separate_gate_inline_data(self):
        with tempfile.TemporaryDirectory() as directory:
            c,path,report,modules,bindings,child,normalize=self.export_fixture(directory)
            with patch.object(RULE,'load',side_effect=lambda name:modules[name]):
                RULE.export_coverage(directory,c,None,bindings,None)
            self.assertEqual(child.export_coverage.call_count,2)
            self.assertEqual(normalize.call_count,21)

    def test_outer_exports_reject_missing_roots_extra_code_duplicates_flags_or_source(self):
        for change in ('missing','extra_code','duplicate','coverage','source','hash'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as directory:
                c,path,report,modules,bindings,child,normalize=self.export_fixture(directory)
                if change=='missing':report['functions'].pop()
                elif change=='extra_code':report['functions'][0]['instructions'].append(dict(address='0x1001',bytes='90'))
                elif change=='duplicate':report['functions'][0]['instructions']*=2
                elif change=='coverage':report['functions'][0]['direct_flow_coverage_complete']=False
                elif change=='source':report['new_source_sha256']='1'*64
                path.write_text(json.dumps(report))
                if change!='hash':c['exports']['run-fixture']=hashlib.sha256(path.read_bytes()).hexdigest()
                else:c['exports']['run-fixture']='9'*64
                with patch.object(RULE,'load',side_effect=lambda name:modules[name]):
                    with self.assertRaises(ValueError):RULE.export_coverage(directory,c,None,bindings,None)


if __name__=='__main__':unittest.main()
