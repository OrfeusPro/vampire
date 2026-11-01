"""Publication preference and role-complete memo isolation for backend composition."""
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from test_vampir_update_contracts import load

adapter=load('update-native-login-backend-wire')


class BackendWireAdapterTests(unittest.TestCase):
    def test_native_scope_and_fixture_boundaries(self):
        a=adapter.select();self.assertEqual((a.layout['executed_roots'],a.layout['leaves'],a.layout['tail_fragments']),(29,13,3))
        for key in ('native_publisher','native_service_thunk','native_backend','native_writer','native_wire','native_append','native_archive_cleanup'):
            self.assertIs(a.layout[key],True)
        for key in ('native_checksum','native_transform','native_transport','native_backend_assignment','native_pending_insert','native_delegate','real_services','session_executed','synthetic_service_vtable'):
            self.assertIs(a.layout[key],False)
        with self.assertRaises(ValueError):adapter.select('other')

    def test_published_current_role_replaces_bootstrap_seed(self):
        a=adapter.select();ref=(Path('reference'),dict(source_sha256='a'*64),22)
        proved=(Path('published'),dict(source_sha256='a'*64,transfer_proof={'sha256':'b'*64}),22)
        newer=(Path('new-reference'),dict(source_sha256='c'*64),24)
        with patch.object(adapter.core.Family,'contexts',return_value=[ref,proved,newer]):
            self.assertEqual(a.contexts(None),[proved,newer]);self.assertEqual(a.baseline_context(None),proved[:2])

    def make(self):
        calls=[];tools={'tool':'v1'}
        api=SimpleNamespace(tools=lambda:dict(tools),validate=lambda i,a,c:calls.append((a,c)))
        args=SimpleNamespace(root=Path('root'),knowledge=Path('knowledge'),source_store=SimpleNamespace(),_login_input_seed='foreign')
        selected={role:(api,Path(role),dict(source_sha256='a'*64),dict(path=role+'-report',sha256='b'*64)) for role in ('handoff','wire')}
        return args,selected,calls,tools

    def test_parent_memo_is_role_bound_frozen_store_local_and_tools_sensitive(self):
        args,selected,calls,tools=self.make()
        with patch.object(adapter.core,'lineage_inputs',return_value={'one':'a'*64}),patch.object(adapter.core,'pointer',side_effect=lambda p:dict(path=str(p),sha256='b'*64)):
            adapter.validate_parents(None,args,selected);adapter.validate_parents(None,args,selected)
            self.assertEqual(len(calls),2)
            self.assertTrue(all(a.source_store is args.source_store and not hasattr(a,'_login_input_seed') for a,_ in calls))
            adapter.validate_parents(None,args,dict(handoff=selected['wire'],wire=selected['handoff']));self.assertEqual(len(calls),4)
            tools['tool']='v2';adapter.validate_parents(None,args,selected);self.assertEqual(len(calls),6)
            args.source_store=SimpleNamespace();adapter.validate_parents(None,args,selected);self.assertEqual(len(calls),8)

    def test_lineage_is_checked_before_memo_hit(self):
        args,selected,calls,_=self.make()
        with patch.object(adapter.core,'pointer',side_effect=lambda p:dict(path=str(p),sha256='b'*64)):
            with patch.object(adapter.core,'lineage_inputs',return_value={'one':'a'*64}):adapter.validate_parents(None,args,selected)
            with patch.object(adapter.core,'lineage_inputs',side_effect=ValueError('damaged')):
                with self.assertRaisesRegex(ValueError,'damaged'):adapter.validate_parents(None,args,selected)
        self.assertEqual(len(calls),2)


if __name__=='__main__':unittest.main()
