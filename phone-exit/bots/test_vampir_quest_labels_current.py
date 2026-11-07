"""Current label proof, generated consumer and unchanged-cache boundaries."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

HERE=Path(__file__).parent


class QuestLabelsCurrentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=HERE/'resource-tools/vampir/verify-quest-labels-current.py'
        spec=importlib.util.spec_from_file_location('quest_labels_current_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.pointer=cls.tool.verify();cls.report=json.loads(Path(cls.pointer['report']).read_bytes())

    def test_qualified_names_reuse_current_named_payloads_and_shared_lookup(self):
        r=self.report
        self.assertEqual(r['names'],1341);self.assertEqual(len(r['skipped']),12)
        self.assertEqual(r['key_binding']['shared_lookup'],'0x145b4bf30')
        self.assertEqual(r['key_binding']['property'],'QuestInfoId')
        self.assertTrue(r['metadata']['shared_catalog'])
        self.assertFalse(r['native_execution']);self.assertFalse(r['runtime_admitted'])
        self.assertFalse(r['dialogues_verified']);self.assertFalse(r['outgoing_actions_admitted'])
        self.assertEqual(r['tables']['Quest']['rows'],1353)
        self.assertEqual(r['tables']['QuestNamesRu']['rows'],1691)

    def test_warm_cache_repeats_no_pe_catalog_or_directory_recovery(self):
        # These public entrypoints cover the cold PE, catalog and rendering
        # path; the owner still rehashes every retained input.
        with patch.object(self.tool,'key_binding',side_effect=AssertionError('key replay')), \
                patch.object(self.tool,'catalog',side_effect=AssertionError('catalog replay')), \
                patch.object(self.tool,'render',side_effect=AssertionError('render replay')), \
                patch('subprocess.Popen',side_effect=AssertionError('new process')):
            self.assertEqual(self.tool.verify(),dict(self.pointer,reused=True))

    def test_modified_scope_binding_or_tables_cannot_reuse_receipt(self):
        for key,value in [('runtime_admitted',True),('dialogues_verified',True),('source_sha256','0'*64)]:
            r=copy.deepcopy(self.report);r[key]=value
            with self.assertRaisesRegex(ValueError,'boundary differs'):self.tool.validate(r,self.report['definition'])
        r=copy.deepcopy(self.report);r['key_binding']['shared_lookup']='0x145828f00'
        with self.assertRaisesRegex(ValueError,'boundary differs'):self.tool.validate(r,self.report['definition'])
        r=copy.deepcopy(self.report);r['tables']['Quest']['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'boundary differs'):self.tool.validate(r,self.report['definition'])

    def test_catalog_keeps_ambiguous_and_untranslated_names_unknown(self):
        bodies=dict(Quest=b'Id,PreQuestId\n1,\n2,\n3,\n4,\n',QuestNamesRu=(
            'Id,Name,DescObjective\n1,Проверка,Найти NPC\n2,Первое,\n2,Второе,\n3,English,\n').encode())
        names,skipped=self.tool.catalog(bodies)
        self.assertEqual(names,{'1':dict(title='Проверка',objective='Найти NPC')})
        self.assertEqual(skipped,[dict(id='2',reason='ambiguous'),dict(id='3',reason='untranslated'),dict(id='4',reason='missing')])

    def test_generated_consumer_translates_only_qualified_source_in_shared_model(self):
        ui=HERE/'vampir/ui-prototype'
        script="""
const assert=require('node:assert/strict');
const root=process.argv[1],base=require(root+'/quest-names-ru.js'),labels=require(root+'/quest-names-current.js');
const model=require(root+'/prototype-live-model.js');
const source=labels.currentSourceSha256;
assert.equal(base.get('110120',source),null);
assert.equal(labels.get('110120',source).title,'Зов крови');
assert.equal(labels.get('110120',base.sourceSha256).title,'Зов крови');
assert.equal(labels.get('110120','f'.repeat(64)),null);
assert.equal(labels.get('unknown',source),null);
assert(Object.isFrozen(labels));assert(Object.isFrozen(labels.get('110120',source)));
const snapshot={schema:2,state:'connected',coverage:{quests:'last_received_message'},character:{key:'22',world_id:10010,stats:[]},
 quests:[{id:'110120',group:1,state:2}],quest_snapshot:{source_sha256:source,semantics:'last_received_message',applied_to_local_task:false,character_key:'22',world_id:10010}};
assert.equal(model.project(snapshot).quests[0].title,'Зов крови');
snapshot.quest_snapshot.source_sha256='f'.repeat(64);
assert.equal(model.project(snapshot).quests[0].title,'Квест 110120');
process.stdout.write('current and legacy names, unknown source, shared model, immutable records passed');
"""
        result=subprocess.run(['node','-e',script,str(ui.resolve())],capture_output=True,text=True,encoding='utf-8',check=True,timeout=10)
        self.assertIn('shared model',result.stdout)


    def test_observation_refresh_reuses_native_scenarios_without_processes(self):
        observation=self.tool.load('verify-quest-observation-current')
        original=Path.is_file
        def cold(path):
            if 'quest-observation-current-v1-cache' in path.parts:return False
            return original(path)
        with patch('unicorn.Uc.emu_start',side_effect=AssertionError('native replay')), \
                patch('subprocess.Popen',side_effect=AssertionError('new process')):
            with patch.object(Path,'is_file',cold):first=observation.verify()
            self.assertFalse(first['reused'])
            with patch.object(observation,'packet_bindings',side_effect=AssertionError('PE replay')), \
                    patch.object(observation,'projection',side_effect=AssertionError('portable replay')):
                second=observation.verify()
            self.assertTrue(second['reused']);self.assertEqual(first['sha256'],second['sha256'])
        current=json.loads(Path(first['report']).read_bytes())
        self.assertFalse(current['native_execution']);self.assertTrue(current['native_proofs_reused'])
        self.assertEqual(current['inherited_native_cases'],1178)
        self.assertEqual(self.report['definition']['observation_proof'],
            dict(path=first['report'],sha256=first['sha256']))

    def test_observation_refresh_keeps_source_lineage_and_current_inputs(self):
        from types import SimpleNamespace
        context=json.loads(self.tool.CONTEXT.read_bytes())
        lineage=json.loads(Path(context['observation_proof']['path']).read_bytes())
        pointer=self.report['definition']['observation_proof']
        fresh=json.loads(Path(pointer['path']).read_bytes())
        retained={}
        owner=SimpleNamespace(root=self.tool.ROOT.resolve(),expect=lambda name,sha:retained.update({name:sha}))
        verifier=SimpleNamespace(RECIPE='quest-observation-current-v1',
            verify=lambda **_:dict(report=pointer['path'],sha256=pointer['sha256']))
        with patch.object(self.tool,'load',return_value=verifier), \
                patch.object(self.tool,'checked',side_effect=[lineage,fresh]):
            result,selected=self.tool.current_observation(owner,context)
        self.assertEqual(selected,pointer);self.assertEqual(result,fresh)
        self.assertEqual(retained,fresh['definition']['inputs'])
        for field,reason in [('source_sha256','unqualified'),('parents','lineage differs')]:
            forged=copy.deepcopy(fresh)
            if field=='source_sha256':forged[field]='0'*64
            else:forged[field]['1854']['sha256']='0'*64
            with patch.object(self.tool,'load',return_value=verifier), \
                    patch.object(self.tool,'checked',side_effect=[lineage,forged]), \
                    self.assertRaisesRegex(ValueError,reason):
                self.tool.current_observation(owner,context)

if __name__=='__main__':unittest.main()
