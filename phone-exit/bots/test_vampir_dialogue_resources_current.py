"""Dialogue links are resource data; native parameter selection is separately bounded."""
import copy
import csv
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

HERE=Path(__file__).parent


def body(values):
    stream=io.StringIO();writer=csv.DictWriter(stream,fieldnames=list(values[0]))
    writer.writeheader();writer.writerows(values);return stream.getvalue().encode()


def sample():
    return dict(tasks=body([dict(Id='1',QuestInfoId='10',Type='6',Param=json.dumps(dict(type='Dialog',dialogGroupId=100)))]),
        lines=body([dict(Id='1001',GroupId='100',DialogChoiceGroupId='200',UnableToSkip='1',UnableToSkipLine='0',IgnoreAutoSetting='1')]),
        choices=body([dict(Id='2001',GroupId='200',Order='2',DialogGroupId='300')]),
        lines_ru=body([dict(Id='1001',Name='Персонаж',Title='',Text='Реплика',Untranslated='')]),
        choices_ru=body([dict(Id='2001',Text='Ответ',Untranslated='Text')]))


class DialogueResourcesCurrentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=HERE/'resource-tools/vampir/verify-dialogue-resources-current.py'
        spec=importlib.util.spec_from_file_location('dialogue_resources_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.pointer=cls.tool.verify();cls.report=json.loads(Path(cls.pointer['report']).read_bytes())
        cls.graph=json.loads(Path(cls.report['graph']['path']).read_bytes())

    def test_qualified_native_and_resource_scopes_are_separate_from_gameplay(self):
        r=self.report
        self.assertEqual(r['whole_exports_verified'],8)
        self.assertEqual(r['counts']['lines'],8302);self.assertEqual(r['counts']['choices'],241)
        self.assertEqual(r['counts']['scripted_dialogue_tasks'],1049)
        self.assertEqual(r['native_parameter']['metrics']['call_counts'],26)
        self.assertFalse(r['runtime_admitted']);self.assertFalse(r['received_prompts_verified'])
        self.assertFalse(r['active_task_verified']);self.assertFalse(r['skip_behavior_verified'])
        self.assertEqual(len(self.graph['groups']['11012002']),6)
        self.assertFalse(self.graph['order_admitted']);self.assertFalse(self.graph['active'])

    def test_warm_cache_does_not_replay_graph_native_or_processes(self):
        with patch.object(self.tool,'graph',side_effect=AssertionError('graph replay')), \
                patch('subprocess.Popen',side_effect=AssertionError('new process')):
            self.assertEqual(self.tool.verify(),dict(self.pointer,reused=True))

    def test_resource_join_preserves_skip_flags_untranslated_fields_and_missing_targets(self):
        g=self.tool.graph(sample());line=g['groups']['100'][0];choice=g['choice_groups']['200'][0]
        self.assertTrue(line['unable_to_skip']);self.assertFalse(line['unable_to_skip_line'])
        self.assertTrue(line['ignore_auto_setting']);self.assertEqual(line['text']['Text'],'Реплика')
        self.assertEqual(choice['text']['status'],'untranslated')
        self.assertEqual(choice['text']['untranslated_fields'],['Text'])
        self.assertEqual(choice['order'],'2');self.assertEqual(choice['next_group_id'],'300')
        self.assertIn(dict(kind='choice_target',id='2001',reason='missing_group',group_id='300'),g['unresolved'])
        self.assertFalse(g['skip_behavior_verified'])

    def test_ambiguous_text_and_primary_records_are_not_arbitrarily_selected(self):
        b=sample();row=dict(Id='1001',Name='',Title='',Text='Первое',Untranslated='')
        b['lines_ru']=body([row,dict(row,Text='Второе')])
        self.assertEqual(self.tool.graph(b)['groups']['100'][0]['text'],dict(status='ambiguous'))
        c=dict(Id='2001',GroupId='200',Order='2',DialogGroupId='300');b['choices']=body([c,c])
        g=self.tool.graph(b)
        self.assertEqual(g['choice_groups'],{})
        self.assertTrue(any(x['reason']=='missing_choice_group' for x in g['unresolved']))

    def test_class_string_stays_raw_and_does_not_select_an_active_task(self):
        b=sample();param=dict(type='Dialog',classBranch=[dict(classInfoId='1',dialogGroupId=100)])
        b['tasks']=body([dict(Id='1',QuestInfoId='10',Type='6',Param=json.dumps(param))])
        g=self.tool.graph(b);task=g['tasks']['1']
        self.assertEqual(task['candidates'][0]['class_id_raw'],'1')
        self.assertFalse(task['candidates'][0]['class_scalar_conversion_verified']);self.assertFalse(task['active'])
        self.assertTrue(any(v['reason']=='class_scalar_conversion_not_verified' for v in g['unresolved']))

    def test_bad_parameters_flags_and_forged_runtime_scope_fail_closed(self):
        with self.assertRaisesRegex(ValueError,'duplicate JSON'):self.tool.strict_object([('type',1),('type',2)])
        with self.assertRaisesRegex(ValueError,'flag'):self.tool.flag('yes')
        for field in ('runtime_admitted','received_prompts_verified','active_task_verified','skip_behavior_verified'):
            forged=copy.deepcopy(self.report);forged[field]=True
            with self.assertRaisesRegex(ValueError,'scope differs'):self.tool.validate(forged,self.report['definition'])
        forged=copy.deepcopy(self.report);forged['native_parameter']['cases'][0]['group']='99'
        with self.assertRaisesRegex(ValueError,'native parameter proof scope differs'):
            self.tool.validate(forged,self.report['definition'])

    def test_native_parameter_cache_excludes_resource_text_changes(self):
        labels=self.tool.load('verify-quest-labels-current')
        owner,_,_,_,_,_,definition=labels.inputs(labels.ROOT,labels.CONTEXT)
        try:
            c=json.loads(self.tool.CONTEXT.read_bytes());c['table_sha256']={'changed_resource':'0'*64}
            native=self.tool.load('dialogue-parameter-cases-v1');export=json.loads(Path(c['export']['path']).read_bytes())
            with patch.object(native,'execute',side_effect=AssertionError('native replay')):
                result,pointer,pending=native.cached_execute(owner.index,owner,labels.ROOT,c,export,b'',definition['runtime_inputs'])
            self.assertIsNone(pending);self.assertEqual(pointer,self.report['native_parameter_proof'])
            self.assertEqual(result,self.report['native_parameter']);owner.finish()
        except BaseException:
            owner.abort();raise


if __name__=='__main__':unittest.main()
