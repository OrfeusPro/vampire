"""Current replacement evidence remains bounded and separate from action admission."""
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


class TaskReplacementCurrentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool=load('verify-quest-task-replacement-current')
        cls.pointer=cls.tool.verify();cls.report=json.loads(Path(cls.pointer['report']).read_bytes())

    def test_kind6_creation_and_primary_failure_fallback_keep_scope(self):
        r=self.report;result=r['result']
        self.assertEqual(len(result['cases']),48)
        self.assertEqual(result['metrics']['abi_checks'],96)
        self.assertEqual(sum(row['case']['primary_failure'] for row in result['cases']),24)
        for field in ('runtime_admitted','network_used','active_task_verified','ordered_catalog_verified',
                      'action_admitted','model_applied_online'):
            self.assertIs(r[field],False)
        self.assertTrue(result['actual_native_refcounts'])
        self.assertFalse(result['other_factory_kinds_executed'])

    def test_fallback_and_lifecycle_are_distinct_from_real_gameplay(self):
        rows=self.report['result']['cases']
        success=next(row for row in rows if not row['case']['primary_failure'])
        fallback=next(row for row in rows if row['case']['primary_failure'])
        self.assertEqual(success['final_table'],'0x149907e00')
        self.assertEqual(fallback['final_table'],'0x149906828')
        self.assertEqual(fallback['final_index'],255)
        self.assertIn('task_data',success['events']);self.assertNotIn('task_data',fallback['events'])
        self.assertEqual(success['final_control'],[1,1])
        self.assertEqual(fallback['final_control'],[1,1])
        self.assertEqual(self.report['result']['lifecycle'],'fixtures')

    def test_incomplete_or_forged_admission_fails_closed(self):
        forged=copy.deepcopy(self.report);forged['result']['cases'].pop()
        with self.assertRaises(ValueError):self.tool.validate(forged,self.report['definition'])
        forged=copy.deepcopy(self.report);forged['result']['actual_native_refcounts']=False
        with self.assertRaises(ValueError):self.tool.validate(forged,self.report['definition'])
        forged=copy.deepcopy(self.report);forged['result']['metrics']['entry_counts'].pop('0x1455ab5c0')
        with self.assertRaises(ValueError):self.tool.validate(forged,self.report['definition'])
        with self.assertRaisesRegex(ValueError,'scope differs'):
            self.tool.validate(dict(self.report,action_admitted=True),self.report['definition'])

    def test_warm_cache_does_not_replay_parent_or_replacement(self):
        original=self.tool.load
        model=original('verify-quest-model-current')
        cases=original('quest-task-replacement-current-cases-v1')
        modules={'verify-quest-model-current':model,'quest-task-replacement-current-cases-v1':cases}
        with patch.object(self.tool,'load',side_effect=lambda name:modules[name] if name in modules else original(name)), \
                patch.object(model,'verify',side_effect=AssertionError('parent replay')), \
                patch.object(cases,'execute',side_effect=AssertionError('replacement replay')), \
                patch('subprocess.Popen',side_effect=AssertionError('new process')):
            self.assertEqual(self.tool.verify(),dict(self.pointer,reused=True))

    def test_warm_result_keeps_final_input_barrier(self):
        # definition also validates retained parent inputs before the child barriers.
        with patch.object(self.tool,'barrier',side_effect=[None,None,ValueError('late change')]) as checked:
            with self.assertRaisesRegex(ValueError,'late change'):self.tool.verify()
        self.assertEqual(checked.call_count,3)

    def test_runtime_conflict_with_parent_is_not_overwritten(self):
        original=self.tool.load;wrapper=original('knowledge-index');index=wrapper.api()
        current=index.extension
        selected=next(str(path.resolve()) for path in current('native-publication-v2').runtime_files()
            if str(path.resolve()) in self.report['definition']['inputs'])
        normal=self.tool.digest
        reads=0
        def changed(path):
            nonlocal reads
            if str(Path(path).resolve())==selected:
                reads+=1
                if reads>1:return '0'*64
            return normal(path)
        wrapper.api=lambda:index
        with patch.object(self.tool,'load',side_effect=lambda name:wrapper if name=='knowledge-index' else original(name)), \
                patch.object(self.tool,'digest',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'reused runtime changed'):self.tool.verify()


if __name__=='__main__':unittest.main()
