"""Only exact child roles and one frozen SourceStore may reuse validation."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent/'resource-tools/vampir'
s=importlib.util.spec_from_file_location('dispatch_adapter',HERE/'update-native-login-dispatch.py')
adapter=importlib.util.module_from_spec(s);s.loader.exec_module(adapter)


class DispatchAdapterTests(unittest.TestCase):
    def test_scope_distinguishes_native_tls_and_input_from_provider_and_diagnostic_effects(self):
        a=adapter.select();self.assertEqual(a.layout['executed_roots'],29);self.assertEqual(a.layout['leaves'],12)
        for key in ('native_dispatch','native_lookup','native_packet_constructor','native_handler','native_cleanup','native_input_utf8','native_tls_setter'):
            self.assertIs(a.layout[key],True)
        for key in ('os_tls_provider','native_diagnostic_utf8','native_owner','native_post_state','native_continuation','session_executed','real_services'):
            self.assertIs(a.layout[key],False)
        with self.assertRaises(ValueError):adapter.select('other')

    def test_proved_role_replaces_reference_and_is_preferred_as_next_baseline(self):
        a=adapter.select();ref=(Path('z-ref'),dict(source_sha256='a'*64),22)
        proved=(Path('a-proof'),dict(source_sha256='a'*64,transfer_proof={'sha256':'b'*64}),22)
        newer=(Path('new-reference'),dict(source_sha256='c'*64),24)
        with patch.object(adapter.core.Family,'contexts',return_value=[ref,proved,newer]):
            self.assertEqual(a.contexts(None),[proved,newer]);self.assertEqual(a.baseline_context(None),proved[:2])

    def make(self):
        calls=[];tools={'recipe':'v1'}
        api=SimpleNamespace(tools=lambda:dict(tools),validate=lambda i,a,c:calls.append((a,c)))
        args=SimpleNamespace(root=Path('root'),knowledge=Path('knowledge'),source_store=SimpleNamespace(),_login_input_seed='foreign')
        selected={role:(api,Path(role),dict(source_sha256='a'*64),dict(path=role+'-report',sha256='b'*64)) for role in ('composition','container')}
        return args,selected,calls,tools

    def test_complete_ordered_parent_tuple_is_reused_in_same_store_only(self):
        a,selected,calls,_=self.make()
        with patch.object(adapter.core,'lineage_inputs',return_value={'input':'a'*64}),patch.object(adapter.core,'pointer',side_effect=lambda p:dict(path=str(p),sha256='a'*64)):
            adapter.validate_parents(None,a,selected);adapter.validate_parents(None,a,selected)
            self.assertEqual(len(calls),2)
            self.assertTrue(all(pair[0].source_store is a.source_store and not hasattr(pair[0],'_login_input_seed') for pair in calls))
            self.assertEqual(a.source_store._login_dispatch_parent_metrics,dict(validated=1,reused=1))
            a.source_store=SimpleNamespace();adapter.validate_parents(None,a,selected);self.assertEqual(len(calls),4)

    def test_same_material_union_cannot_swap_parent_roles_or_change_tools(self):
        a,selected,calls,tools=self.make()
        with patch.object(adapter.core,'lineage_inputs',return_value={'one':'a'*64,'two':'b'*64}),patch.object(adapter.core,'pointer',side_effect=lambda p:dict(path=str(p),sha256='a'*64)):
            adapter.validate_parents(None,a,selected)
            swapped=dict(composition=selected['container'],container=selected['composition'])
            adapter.validate_parents(None,a,swapped);self.assertEqual(len(calls),4)
            tools['recipe']='v2';adapter.validate_parents(None,a,selected);self.assertEqual(len(calls),6)

    def test_damaged_lineage_is_checked_before_the_memo_hit(self):
        a,selected,calls,_=self.make()
        with patch.object(adapter.core,'pointer',side_effect=lambda p:dict(path=str(p),sha256='a'*64)):
            with patch.object(adapter.core,'lineage_inputs',return_value={'input':'a'*64}):adapter.validate_parents(None,a,selected)
            with patch.object(adapter.core,'lineage_inputs',side_effect=ValueError('damaged')):
                with self.assertRaises(ValueError):adapter.validate_parents(None,a,selected)
        self.assertEqual(len(calls),2)

    def test_proved_composition_publication_is_not_ambiguous_with_its_bootstrap_seed(self):
        with tempfile.TemporaryDirectory() as directory:
            args=SimpleNamespace(root=Path(directory),knowledge=Path(directory)/'repo-knowledge')
            pointer=dict(path='published',sha256='a'*64);check=dict(path='report',sha256='b'*64)
            c=dict(source_sha256='c'*64,transfer_proof={'sha256':'d'*64})
            api=SimpleNamespace(index='generated-composition',at=lambda *_:self.fail('Unfiltered seed lookup must not be used'),
                published_contexts=lambda *_:[(Path('published'),c,22)])
            p=args.root/'knowledge'/api.index/'index.json';p.parent.mkdir(parents=True)
            p.write_text(json.dumps(dict(contexts=[dict(context=pointer,check=check)])),encoding='utf-8')
            modules={'update-native-login-composition':SimpleNamespace(select=lambda _:api),
                'native-release-registry':SimpleNamespace(read=lambda _:None)}
            with patch.object(adapter,'load',side_effect=lambda n:modules[n]),patch.object(adapter.core,'pointer',return_value=pointer):
                self.assertEqual(adapter.dependency(args,'composition','c'*64),(api,Path('published'),c,check))
                with self.assertRaisesRegex(ValueError,'proved target publication'):adapter.dependency(args,'composition','f'*64)


if __name__=='__main__':unittest.main()
