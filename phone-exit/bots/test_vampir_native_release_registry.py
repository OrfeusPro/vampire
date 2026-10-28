"""Data-driven source history, typed graph projections and guarded suite adapters."""
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_vampir_update_bindings import BindingTests
from test_vampir_update_contracts import load,HERE


class NativeRegistryTests(unittest.TestCase):
    setUp=BindingTests.setUp
    image=BindingTests.image

    def registry(self,knowledge,old,new):
        value=dict(schema=1,releases=[dict(id='stable',order=4,source_sha256=old),
            dict(id='next.release',order=5,source_sha256=new)],family_aliases={},projections=[],suite_adapters=[])
        knowledge.mkdir(parents=True,exist_ok=True)
        (knowledge/'native-release-registry.json').write_text(json.dumps(value),encoding='utf-8')
        return value

    def context(self,knowledge,source):
        native,bindings=load('build-native-entry-code'),load('update-bindings')
        image=native.Image((self.root/'client-code-snapshots'/source/'ProjectRED-Win64-Shipping.exe').read_bytes())
        functions=[dict(address='0x140001040',instructions=[dict(address=hex(row['address']),bytes=row['bytes'])
            for row in bindings.rows(native,image,0x140001040)])]
        export=self.root/'ghidra/request-exports'/source/'run-fixture'/'details.json'
        export.parent.mkdir(parents=True);export.write_text(json.dumps(dict(new_source_sha256=source,functions=functions)))
        value=dict(schema=1,family='packet',release_id='stable',source_sha256=source,
            functions=dict(helper='0x140001040'),exports={'run-fixture':hashlib.sha256(export.read_bytes()).hexdigest()},
            arbitrary_fixture='0x140001000')
        path=knowledge/'native-contexts'/'no-numeric-version.json';path.parent.mkdir();path.write_text(json.dumps(value))
        return path,value

    def test_new_named_release_and_context_need_no_python_or_filename_version(self):
        old,new=self.image(0x1000),self.image(0x1020)
        knowledge=self.root/'knowledge-src';self.registry(knowledge,old,new);self.context(knowledge,old)
        module=load('function-reuse-plan');report=module.build(self.root,knowledge,new)
        self.assertEqual(module.ordered_sources(knowledge,self.root),[new,old])
        self.assertEqual(report['summary']['primary_verified'],1)
        self.assertEqual(report['inventory'][0]['address'],'0x140001040')
        self.assertEqual(report['inventory'][0]['aliases'][0]['family'],'packet')

    def test_explicit_source_identity_without_suffix_is_supported(self):
        old,new=self.image(0x1000),self.image(0x1020)
        knowledge=self.root/'knowledge-src';self.registry(knowledge,old,new);path,value=self.context(knowledge,old)
        del value['release_id'];path.write_text(json.dumps(value))
        self.assertEqual(load('function-reuse-plan').build(self.root,knowledge,new)['summary']['verified'],1)

    def test_registry_rejects_duplicate_source_order_and_unknown_adapter(self):
        api=load('native-release-registry');original=api.read()
        bad=copy.deepcopy(original);bad['releases'][1]['order']=bad['releases'][0]['order']
        with self.assertRaisesRegex(ValueError,'duplicate'):api.validate(bad)
        bad=copy.deepcopy(original);bad['projections'][0]['adapter']='guess-all-addresses'
        with self.assertRaisesRegex(ValueError,'typed native projection'):api.validate(bad)
        bad=copy.deepcopy(original);bad['suite_adapters'][0]['adapter']='arbitrary-shell'
        with self.assertRaisesRegex(ValueError,'reviewed native suite adapter'):api.validate(bad)

    def test_all_eight_known_graph_gaps_have_explicit_executable_projections(self):
        api=load('native-release-registry');items=api.projected_contexts(HERE/'knowledge',api.read())
        addresses={at for _,context,_ in items for at in context['functions'].values()}
        self.assertEqual(addresses,{'0x1456e89e0','0x1467cf830','0x1445ce420','0x1445c4cd0',
            '0x1416dd990','0x1415c96b0','0x1456e84d0','0x14679e2d0'})
        self.assertEqual(sum(len(context['functions']) for _,context,_ in items),8)

    def test_source_store_is_shared_by_catalog_batches(self):
        old,new=self.image(0x1000),self.image(0x1020)
        knowledge=self.root/'knowledge-src';self.registry(knowledge,old,new);self.context(knowledge,old)
        bindings=load('update-bindings');store=bindings.SourceStore(self.index.api(),self.root)
        report=load('function-reuse-plan').build(self.root,knowledge,new,source_store=store)
        self.assertEqual(report['summary']['verified'],1)
        self.assertLessEqual(store.metrics['source_reads'],2)
        self.assertGreater(store.metrics['source_cache_hits'],0)
        store.validate()

    def test_unsupported_family_is_reported_without_running_legacy_suite(self):
        old,new=self.image(0x1000),self.image(0x1020)
        knowledge=self.root/'knowledge-src';value=self.registry(knowledge,old,new)
        value['suite_adapters']=[dict(id='entry',family='entry',adapter='unsupported',reason='Reviewed OS adapter missing')]
        (knowledge/'native-release-registry.json').write_text(json.dumps(value))
        result=load('update-native-contexts').materialize(self.index.api(),SimpleNamespace(root=self.root,knowledge=knowledge),new,{}, {})
        self.assertEqual(result['checks'],[])
        self.assertEqual(result['queue'][0]['reason'],'unsupported_native_adapter')
        self.assertFalse(result['runtime_activated'])

    def test_unknown_generated_native_adapter_is_rejected_before_execution(self):
        tool=load('update-native-contexts')
        with self.assertRaisesRegex(ValueError,'Unreviewed generated native check'):
            tool.execute(self.index.api(),SimpleNamespace(root=self.root),'f'*64,dict(adapter='shell',scope='anything'))

    def test_missing_or_modified_generated_index_receipt_is_rejected(self):
        api=load('native-release-registry');path=self.root/'knowledge/generated-native/index.json';path.parent.mkdir(parents=True)
        path.write_text(json.dumps(dict(schema=1,contexts=[dict(context=dict(path=str(self.root/'untrusted.json'),sha256='a'*64),
            check=dict(path=str(self.root/'untrusted2.json'),sha256='b'*64),order=12000)])))
        with self.assertRaisesRegex(ValueError,'receipt changed'):api.generated_contexts(self.root,api.read())


def load_tests(loader,tests,pattern):
    return loader.loadTestsFromTestCase(NativeRegistryTests)


if __name__=='__main__':unittest.main()
