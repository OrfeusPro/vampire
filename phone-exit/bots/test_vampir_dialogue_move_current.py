"""A current static NPC field proof must not imply execution or live admission."""
import copy
import csv
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent


def csv_body(rows):
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode('utf-8')


class DialogueMoveCurrentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = HERE/'resource-tools/vampir/verify-dialogue-move-current.py'
        spec = importlib.util.spec_from_file_location('dialogue_move_current_test', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.pointer = cls.tool.verify()
        cls.report = json.loads(Path(cls.pointer['report']).read_bytes())
        cls.context = json.loads(cls.tool.CONTEXT.read_bytes())
        table = cls.report['definition']['table']['path']
        cls.rows = list(csv.DictReader(io.StringIO(Path(table).read_text('utf-8-sig'), newline='')))

    def test_whole_current_exports_and_npc_resource_are_qualified_static_evidence(self):
        r = self.report
        self.assertEqual(r['whole_exports_verified'], 7)
        self.assertEqual(r['result']['wire']['request']['bytes'], 49)
        self.assertEqual(r['result']['wire']['response']['bytes'], 53)
        self.assertEqual([v['wire'] for v in r['result']['wire']['fields']],
                         ['Q', 'Q', 'fff', 'Q', 'f', 'Q', 'B'])
        row = r['result']['sequence']
        self.assertEqual(row['id'], '1101111002001')
        self.assertEqual(row['param']['objectType'], 'NPC')
        self.assertEqual(row['param']['spawnInfoId'], 10011001)
        self.assertEqual(row['param']['moveFinished'], dict(yaw=-100, withAnim=1, duration=1))
        self.assertTrue(all(r[key] is False for key in self.tool.FALSE_FIELDS))
        runtime = r['definition']['runtime_inputs']
        self.assertTrue(runtime)
        self.assertTrue(all(r['definition']['inputs'][name] == expected
                            for name, expected in runtime.items()))

    def test_resource_only_dialogue_patch_invalidates_quest_contract(self):
        contracts=self.tool.load('update-contracts')
        index=self.tool.load('knowledge-index').api()
        data=contracts.load(index,self.tool.HERE/'knowledge')
        quest=next(row for row in data['contracts'] if row['id']=='quests')
        self.assertIn('quest-dialogue-current',quest['checks'])
        for path in ('Dialog.csv','DialogChoice.csv','DialogSequence.csv',
                     'L10N/ru/Dialog_Name.csv','L10N/ru/DialogChoice_Name.csv'):
            with self.subTest(path=path):
                dirty=contracts.affected(data,exe_changed=False,changes=[dict(
                    archive='pakchunk1-Windows.pak',paths=['ProjectRED/Content/RED/Data/CSV/'+path])])
                self.assertIn('quests',dirty)
                self.assertNotIn('sdk-gmc2',dirty)

    def test_warm_cache_does_not_repeat_source_or_native_scenarios_or_start_processes(self):
        with patch.object(self.tool, 'whole_exports', side_effect=AssertionError('exports replay')), \
                patch.object(self.tool, 'source_bindings', side_effect=AssertionError('source replay')), \
                patch.object(self.tool, 'resource_row', side_effect=AssertionError('CSV replay')), \
                patch('subprocess.Popen', side_effect=AssertionError('new process')):
            self.assertEqual(self.tool.verify(), dict(self.pointer, reused=True))

    def test_changed_or_ambiguous_sequence_is_not_accepted_as_the_current_npc(self):
        for update in ({'Type': '6'}, {'GroupId': '11011110030'}, {'DialogSequenceTiming': '1'},
                       {'Param': json.dumps(dict(self.tool.NPC_PARAM, objectType='PC'))}):
            values = copy.deepcopy(self.rows)
            row = next(r for r in values if r['Id'] == '1101111002001')
            row.update(update)
            with self.assertRaises(ValueError):
                self.tool.resource_row(csv_body(values))
        values = copy.deepcopy(self.rows)
        values.append(copy.deepcopy(next(r for r in values if r['Id'] == '1101111002001')))
        with self.assertRaisesRegex(ValueError, 'membership'):
            self.tool.resource_row(csv_body(values))
        with self.assertRaisesRegex(ValueError, 'duplicate parameter'):
            self.tool.strict_object([('objectType', 'NPC'), ('objectType', 'PC')])

    def test_instruction_binding_corruption_fails_closed(self):
        class Image:
            class PE:
                base = 0
            pe = PE()

            def offset(self, address):
                return 0

        with self.assertRaisesRegex(ValueError, 'instruction binding'):
            self.tool.source_bindings(Image(), b'\x00'*512, self.context)

    def test_forged_execution_layout_row_or_unknowns_are_not_reused(self):
        for key in self.tool.FALSE_FIELDS:
            forged = copy.deepcopy(self.report)
            forged[key] = True
            with self.assertRaisesRegex(ValueError, 'scope differs'):
                self.tool.validate(forged, self.report['definition'])
        for location, key, value in (
            (('wire', 'request'), 'bytes', 48),
            (('wire',), 'selected_actor_type', 2),
            (('wire',), 'current_instance', 'resolved'),
            (('sequence',), 'timing', 1),
            (('sequence',), 'row_sha256', '0'*64),
            (('sequence', 'param'), 'spawnInfoId', 10011008),
        ):
            forged = copy.deepcopy(self.report)
            target = forged['result']
            for name in location:
                target = target[name]
            target[key] = value
            with self.assertRaisesRegex(ValueError, 'field or sequence'):
                self.tool.validate(forged, self.report['definition'])

    def test_decoder_runtime_change_invalidates_cached_definition(self):
        selected = copy.deepcopy(self.report['definition'])
        name = next(iter(selected['runtime_inputs']))
        selected['runtime_inputs'][name] = '0'*64
        selected['inputs'][name] = '0'*64
        with self.assertRaisesRegex(ValueError, 'scope differs'):
            self.tool.validate(self.report, selected)


if __name__ == '__main__':
    unittest.main()
