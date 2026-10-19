"""Native result handoff: preserved response, deferred receiver, empty binding."""
import importlib.util
import json
from pathlib import Path
import unittest


class SdkResultDispatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).parent/'resource-tools/vampir/replay-sdk-result-dispatch.py'
        spec=importlib.util.spec_from_file_location('sdk_dispatch_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/sdk-result-dispatch-replay.json').read_text('utf-8'))

    def test_reproduces_source_bound_report(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(len(self.report['cases']),8)
        rows={r['address']:r for f in self.report['fragments'] for r in f['instructions']}
        self.assertEqual(rows[0x1444d83cd]['operands'],'qword ptr [rax + 0x60]')
        self.assertEqual(rows[0x1444e008f]['direct_target'],0x141404350)
        self.assertEqual(rows[0x1414044ec]['operands'],'qword ptr [rsi + 0x10], r15')

    def test_native_binding_bridge_preserves_response_and_returns_true(self):
        self.assertEqual(len(self.report['native_binding_cases']),8)
        table=self.report['delegate_vtable']
        self.assertEqual(table['slots'][8],0x144237840)
        self.assertEqual(table['slots'][12],0x14423aaf0)
        self.assertEqual(self.report['sign_in_binding_instructions'][-1]['direct_target'],0x1444ba4f0)
        for case in self.report['native_binding_cases']:
            with self.subTest(case['fixture']):
                self.assertTrue(case['original_delegate_cleared'])
                self.assertTrue(case['closure_has_original_response_pair'])
                expected=5 if case['fixture']['refcounted'] else 4
                self.assertEqual(case['strong_count_after_dispatch'],expected)
                events=case['events']
                called=[e for e in events if e['action']=='bound_function_capture']
                self.assertEqual(called,[dict(action='bound_function_capture',original_response_pair=True,
                                             returned=int(case['fixture']['execute_ok']))])
                self.assertEqual([e['al'] for e in events if e['action']=='native_delegate_return'],[1])
                self.assertEqual(sum(e['action']=='function_storage_clone_fixture' for e in events),2)

    def test_original_binding_consumed_and_response_retained(self):
        for case in self.report['cases']:
            with self.subTest(case['fixture']):
                self.assertTrue(case['original_delegate_cleared'])
                self.assertTrue(case['closure_has_original_response_pair'])
                expected=5 if case['fixture']['refcounted'] else 4
                self.assertEqual(case['strong_count_after_dispatch'],expected)
                self.assertEqual(case['strong_count_after_thunk'],expected)
                events=case['events'];actions=[e['action'] for e in events]
                self.assertEqual(actions.count('task_schedule_capture'),1)
                if case['fixture']['bound']:
                    self.assertEqual(actions.count('delegate_clone_fixture'),2)
                    self.assertEqual(actions.count('delegate_execute_capture'),1)
                    self.assertLess(actions.index('fixture_task_drain'),actions.index('delegate_execute_capture'))
                    executed=next(e for e in events if e['action']=='delegate_execute_capture')
                    self.assertTrue(executed['original_response_pair'])
                    self.assertEqual(executed['returned'],case['fixture']['execute_ok'])
                    self.assertEqual([e['original'] for e in events if e['action']=='delegate_destroy_capture'],[True,False])
                else:
                    self.assertNotIn('delegate_execute_capture',actions)
                    self.assertNotIn('delegate_clone_fixture',actions)


if __name__=='__main__':
    unittest.main()
