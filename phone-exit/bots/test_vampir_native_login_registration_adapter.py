"""Registration admission preserves the distinction between a helper and delivery."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from test_vampir_update_contracts import load

TOOL = load('update-native-login-registration')


def context():
    return json.loads((TOOL.HERE/'knowledge/native-contexts/login-registration-11318.json').read_text('utf-8'))


class RegistrationAdapterTests(unittest.TestCase):
    def test_helper_scope_preserves_allocation_vs_reference_storage_and_no_delivery(self):
        api = TOOL.select()
        self.assertEqual(len(api.roots(context())), 1)
        self.assertEqual((api.layout['packet_bytes'],api.layout['packet_allocation_bytes']), (352,344))
        self.assertIs(api.layout['native_id'], True)
        for key in ('native_owner','native_packet_constructor','native_handler','native_insert','native_dispatch','real_services','session_executed'):
            self.assertIs(api.layout[key], False)
        for family in ('dispatch','../custom',None):
            with self.assertRaises(ValueError): TOOL.select(family)

    def test_dependency_roles_are_closed_before_loading_modules(self):
        with patch.object(TOOL,'load',side_effect=AssertionError('No arbitrary module')):
            with self.assertRaises(ValueError): TOOL.dependency(None,'native_dispatch','a'*64)

    def test_source_dependencies_need_proofs_and_semantic_reports(self):
        args = SimpleNamespace(root=Path('root'),knowledge=Path('defs')); tool = Mock()
        tool.at.return_value = (Path('child'),{})
        with patch.object(TOOL,'load',return_value=SimpleNamespace(select=lambda _:tool)):
            with self.assertRaisesRegex(ValueError,'target proof'): TOOL.dependency(args,'nested','a'*64)
        tool.at.return_value = (Path('child'),dict(transfer_proof=dict(path='proof',sha256='b'*64)));tool.index='generated-child'
        def module(name):
            return SimpleNamespace(select=lambda _:tool) if name=='update-native-login-input' else SimpleNamespace(read=lambda _: {})
        with patch.object(TOOL,'load',side_effect=module), patch.object(TOOL.core,'pointer',return_value=dict(path='child',sha256='c'*64)), \
                patch.object(Path,'read_text',return_value=json.dumps(dict(contexts=[]))):
            with self.assertRaisesRegex(ValueError,'semantic report'): TOOL.dependency(args,'nested','a'*64)

    def test_static_window_report_cannot_replace_native_helper_evidence(self):
        api=TOOL.select();c=context();c['transfer_proof']=dict(path='proof',sha256='b'*64)
        r=dict(source_sha256=c['source_sha256'],scope=api.scope,method='static',proof=c['transfer_proof'],context_sha256='c'*64,
            network_used=False,profile_activated=False,runtime_activated=False)
        with patch.object(api,'validate_report',side_effect=AssertionError('Native provenance required first')):
            with self.assertRaisesRegex(ValueError,'provenance or scope'):api.report_valid(r,c,'c'*64)

    def test_changed_component_report_changes_plan_without_replaying_native(self):
        api=TOOL.select();args=SimpleNamespace(root=Path('root'),knowledge=Path('defs'))
        dep={'nested_check':dict(path='report',sha256='b'*64)}
        with patch.object(api,'baseline_context',return_value=(Path('baseline'),{})), \
                patch.object(api,'dependencies',side_effect=lambda *a:copy.deepcopy(dep)), \
                patch.object(api,'input_materials',return_value={}),patch.object(api,'tools',return_value={}), \
                patch.object(TOOL.core,'pointer',return_value=dict(path='baseline',sha256='c'*64)), \
                patch.object(TOOL.core,'lineage_inputs',return_value={}),patch.object(TOOL.core,'digest',return_value='d'*64):
            old=api.plan_inputs(None,args,'a'*64);dep['nested_check']['sha256']='e'*64
            self.assertNotEqual(old,api.plan_inputs(None,args,'a'*64))

    def test_rule_interface_receives_both_checked_dependencies_and_frozen_images(self):
        api=TOOL.select();c=context();args=SimpleNamespace(root=Path('root'),source_store=Mock())
        tools={role:Mock() for role in TOOL.CHILDREN}
        children={role:dict(source_sha256='a'*64,role=role) for role in tools}
        pointers={role:dict(path=role,sha256='b'*64) for role in tools}
        captured={}
        def transfer(native,bindings,before,after,baseline,mapping,nested,handler,*,nested_pointer,handler_pointer):
            captured.update(nested=nested,handler=handler,nested_pointer=nested_pointer,handler_pointer=handler_pointer)
            return dict(c),dict(rule='checked')
        rules=SimpleNamespace(transfer=transfer);original=TOOL.load
        def child(args,role,sha):return tools[role],Path(role),children[role],{'semantic':role}
        with patch.object(api,'roots'),patch.object(TOOL,'dependency',side_effect=child), \
                patch.object(TOOL.core,'pointer',side_effect=lambda p:pointers[str(p)]), \
                patch.object(TOOL,'load',side_effect=lambda n:rules if n=='login-registration-rules' else original(n)):
            result,relation=api.transfer(None,args,c,'a'*64)
        self.assertEqual(captured,dict(nested=children['nested'],handler=children['full_handler'],
            nested_pointer=pointers['nested'],handler_pointer=pointers['full_handler']))
        for tool in tools.values():tool.validate.assert_called_once()
        self.assertEqual(result['layout'],api.layout);self.assertNotIn('exports',result)
        self.assertEqual(relation['details'],dict(rule='checked'))


if __name__=='__main__':unittest.main()
