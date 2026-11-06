"""Bounded model evidence is reusable without granting live quest actions."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent


def load(name):
    path=HERE/'resource-tools/vampir'/(name+'.py')
    spec=importlib.util.spec_from_file_location('test_'+name.replace('-','_'),path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


class QuestModelCurrentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool=load('verify-quest-model-current');cls.pointer=cls.tool.verify()
        cls.report=json.loads(Path(cls.pointer['report']).read_bytes())

    def test_current_projection_and_wrapper_scopes_remain_offline(self):
        r=self.report
        self.assertEqual(r['matching_cases_reused'],324)
        self.assertTrue(r['native_proofs_reused'])
        for key in ('runtime_admitted','network_used','active_task_verified','ordered_catalog_verified',
                    'action_admitted','factory_executed','model_applied_online'):
            self.assertIs(r[key],False)
        self.assertEqual(len(r['results']['projection']['cases']),79)
        self.assertEqual(r['results']['projection']['metrics']['abi_checks'],79)
        self.assertEqual(len(r['results']['wrapper']['cases']),20)
        self.assertEqual(r['results']['wrapper']['metrics']['abi_checks'],32)
        self.assertIs(r['results']['factory_static']['native_execution'],False)
        self.assertEqual(r['results']['factory_static']['switch_entries'],31)

    def test_negative_native_slots_are_evidence_not_admitted_indices(self):
        projection=self.report['results']['projection']
        negatives=[row for row in projection['cases'] if row['signed_index']<0]
        self.assertTrue(negatives)
        self.assertTrue(any(row['found'] for row in negatives))
        self.assertFalse(projection['negative_indexes_admitted'])
        self.assertFalse(self.report['ordered_catalog_verified'])

    def test_incomplete_or_forged_child_proofs_are_rejected(self):
        for kind in ('projection','wrapper'):
            forged=copy.deepcopy(self.report);forged['results'][kind]['cases']=[]
            with self.assertRaises(ValueError):self.tool.validate(forged,self.report['definition'])
        forged=copy.deepcopy(self.report);forged['results']['factory_static']['native_execution']=True
        with self.assertRaises(ValueError):self.tool.validate(forged,self.report['definition'])
        with self.assertRaisesRegex(ValueError,'scope differs'):
            self.tool.validate(dict(self.report,action_admitted=True),self.report['definition'])

    def test_warm_cache_does_not_run_native_or_spawn_processes(self):
        original=self.tool.load
        names=('quest-model-projection-cases-v1','quest-model-wrapper-cases-v1','quest-model-factory-static-v1')
        modules={name:original(name) for name in names}
        with patch.object(self.tool,'load',side_effect=lambda name:modules[name] if name in modules else original(name)), \
                patch.object(modules[names[0]],'execute',side_effect=AssertionError('projection replay')), \
                patch.object(modules[names[1]],'execute',side_effect=AssertionError('wrapper replay')), \
                patch.object(modules[names[2]],'verify',side_effect=AssertionError('static replay')), \
                patch('subprocess.Popen',side_effect=AssertionError('process spawn')):
            self.assertEqual(self.tool.verify(),dict(self.pointer,reused=True))

    def test_cached_proof_requires_a_final_input_barrier(self):
        with patch.object(self.tool,'barrier',side_effect=[None,ValueError('late input change')]) as barrier:
            with self.assertRaisesRegex(ValueError,'late input change'):self.tool.verify()
        self.assertEqual(barrier.call_count,2)

    def test_matching_runtime_cannot_silently_replace_a_retained_input(self):
        original=self.tool.load
        wrapper=original('knowledge-index');index=wrapper.api()
        current=index.extension
        runtime=current('native-publication-v2')
        retained=next(str(path.resolve()) for path in runtime.runtime_files()
            if str(path.resolve()) in self.report['definition']['inputs'])
        original_digest=self.tool.digest
        def changed(path):
            return '0'*64 if str(Path(path).resolve())==retained else original_digest(path)
        def extension(name):
            return runtime if name=='native-publication-v2' else current(name)
        index.extension=extension;wrapper.api=lambda:index
        with patch.object(self.tool,'load',side_effect=lambda name:wrapper if name=='knowledge-index' else original(name)), \
                patch.object(self.tool,'digest',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'reused runtime changed'):
                self.tool.verify()


if __name__=='__main__':unittest.main()
