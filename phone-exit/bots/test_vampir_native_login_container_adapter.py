"""Directional, source-store-local validation reuse and published-role selection."""
import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent/'resource-tools/vampir'
s=importlib.util.spec_from_file_location('container_adapter',HERE/'update-native-login-container.py')
adapter=importlib.util.module_from_spec(s);s.loader.exec_module(adapter)


class ContainerAdapterTests(unittest.TestCase):
    def test_family_layout_and_scope_do_not_admit_dispatch_or_owner(self):
        a=adapter.select();self.assertEqual(a.scope,'bounded_native_login_container_and_name')
        self.assertEqual(a.layout['executed_roots'],5)
        self.assertEqual((a.layout['owner_bytes'],a.layout['packet_allocation_bytes']),(72,344))
        for key in ('native_owner','native_packet_constructor','native_handler','native_dispatch','real_services','session_executed'):
            self.assertIs(a.layout[key],False)
        with self.assertRaises(ValueError):adapter.select('other')

    def test_published_role_replaces_same_sha_seed_and_newer_unproved_reference(self):
        a=adapter.select();seed=(Path('z-seed'),dict(source_sha256='a'*64),22)
        proved=(Path('a-proved'),dict(source_sha256='a'*64,transfer_proof={'sha256':'b'*64}),22)
        newer=(Path('new-reference'),dict(source_sha256='c'*64),24)
        with patch.object(adapter.core.Family,'contexts',return_value=[seed,proved,newer]):
            self.assertEqual(a.contexts(None),[proved,newer])
            self.assertEqual(a.baseline_context(None),proved[:2])

    def _parent(self):
        calls=[];tools={'recipe':'v1'}
        api=SimpleNamespace(tools=lambda:dict(tools),validate=lambda index,args,c:calls.append(args))
        c=dict(source_sha256='a'*64);selected=(api,Path('context'),c,dict(path='report',sha256='b'*64))
        args=SimpleNamespace(root=Path('root'),knowledge=Path('knowledge'),source_store=SimpleNamespace(),_login_input_seed='foreign-direction')
        return args,selected,calls,tools

    def test_validation_is_reused_only_in_one_source_store_and_isolates_directional_memo(self):
        args,selected,calls,_=self._parent()
        with patch.object(adapter.core,'lineage_inputs',return_value={'artifact':'c'*64}),patch.object(adapter.core,'pointer',return_value={'path':'context','sha256':'a'*64}):
            adapter.validate_parent(None,args,selected);adapter.validate_parent(None,args,selected)
            self.assertEqual(len(calls),1);self.assertIs(calls[0].source_store,args.source_store)
            self.assertFalse(hasattr(calls[0],'_login_input_seed'));self.assertEqual(args._login_input_seed,'foreign-direction')
            self.assertEqual(args.source_store._login_container_parent_metrics,dict(validated=1,reused=1))
            previous=args.source_store;args.source_store=SimpleNamespace()
            adapter.validate_parent(None,args,selected);self.assertEqual(len(calls),2)
            self.assertIsNot(previous,args.source_store)

    def test_changed_tools_report_or_lineage_does_not_hit_validation_memo(self):
        args,selected,calls,tools=self._parent();materials={'artifact':'c'*64}
        with patch.object(adapter.core,'lineage_inputs',side_effect=lambda *_:dict(materials)),patch.object(adapter.core,'pointer',return_value={'path':'context','sha256':'a'*64}):
            adapter.validate_parent(None,args,selected)
            tools['recipe']='v2';adapter.validate_parent(None,args,selected)
            materials['artifact']='d'*64;adapter.validate_parent(None,args,selected)
            changed=(*selected[:3],dict(path='other-report',sha256='e'*64));adapter.validate_parent(None,args,changed)
        self.assertEqual(len(calls),4)

    def test_damaged_lineage_is_rejected_before_a_cached_hit(self):
        args,selected,calls,_=self._parent()
        with patch.object(adapter.core,'pointer',return_value={'path':'context','sha256':'a'*64}):
            with patch.object(adapter.core,'lineage_inputs',return_value={'artifact':'c'*64}):adapter.validate_parent(None,args,selected)
            with patch.object(adapter.core,'lineage_inputs',side_effect=ValueError('damaged evidence')):
                with self.assertRaises(ValueError):adapter.validate_parent(None,args,selected)
        self.assertEqual(len(calls),1)

    def test_same_material_union_cannot_swap_context_and_report_roles(self):
        args,selected,calls,_=self._parent()
        first=(selected[0],Path('first'),selected[2],dict(path='second',sha256='b'*64))
        second=(selected[0],Path('second'),selected[2],dict(path='first',sha256='a'*64))
        union={'first':'a'*64,'second':'b'*64}
        with patch.object(adapter.core,'lineage_inputs',return_value=union),patch.object(adapter.core,'pointer',side_effect=lambda path:dict(path=str(path),sha256=union[str(path)])):
            adapter.validate_parent(None,args,first);adapter.validate_parent(None,args,second)
        self.assertEqual(len(calls),2)


if __name__=='__main__':unittest.main()
