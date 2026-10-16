import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).parent
spec = importlib.util.spec_from_file_location('runtime_reference_builder', ROOT / 'resource-tools/vampir/build-runtime-chain.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class ReferenceCatalogJoin(unittest.TestCase):
    def setUp(self):
        self.catalog = dict(quests={'1': dict(source=dict(entry=1448, csv_record=2), requiredLevel='1')},
                            tasks={'11': dict(quest='1', typeName='EQuestTaskType::NpcShopBuy', param=dict(count=1))})
        self.rewards = dict(missingRewardGroups=[], unresolvedRequiredQuests=[],
            rewardGroups={'500': [dict(Type='2', typeName='ERewardType::Exp', MinCount='100', MaxCount='100')]},
            quests=[dict(questId='1', source=dict(entry=1448, csv_record=2), requiredLevel='1', contentsLockId='10',
                         rewardGroups=['500'], requiredCompletedQuests=[], retryable='0', serverServiceGroup='')])
        self.locks = dict(missingLocks=[], missingConditionGroups=[],
            locks={'10': dict(conditions=[dict(ConditionType='1', ConditionTypeValue1='99')],
                              combination='unknown_do_not_assume_AND_OR', evaluation='not_evaluated')},
            unmatchedType1QuestCandidates=['99'], interpretations={'1': 'not_proven'})
        self.shops = dict(issues=[], unresolvedTabLockKeywords=['76'], tasks=[dict(
            task=dict(Id='11', QuestInfoId='1'), typeName='EQuestTaskType::NpcShopBuy', param=dict(count=1))])

    def attach(self):
        builder.attach_reference_data(self.catalog, self.rewards, self.locks, self.shops)

    def test_unknown_conditions_and_unresolved_candidates_are_retained_without_evaluator(self):
        raw = copy.deepcopy(self.locks['locks'])
        self.attach()
        self.assertEqual(self.catalog['referenceRevision'], 2)
        self.assertEqual(self.catalog['contentsLocks'], raw)
        self.assertEqual(self.catalog['unresolvedLockQuestCandidates'], ['99'])
        self.assertEqual(self.catalog['sourceInterpretations']['lockEvaluator'], 'not_implemented')

    def test_missing_reward_lock_or_quest_link_is_rejected(self):
        for field in ('reward', 'lock', 'quest'):
            with self.subTest(field=field):
                self.setUp()
                if field == 'reward':
                    self.rewards['rewardGroups'] = {}
                elif field == 'lock':
                    self.locks['locks'] = {}
                else:
                    self.rewards['quests'] = []
                with self.assertRaises(ValueError):
                    self.attach()

    def test_mixed_requirement_source_is_rejected(self):
        self.rewards['quests'][0]['source']['csv_record'] = 3
        with self.assertRaises(ValueError):
            self.attach()

    def test_shop_type_or_parameters_must_match_same_task(self):
        self.shops['tasks'][0]['param']['count'] = 2
        with self.assertRaises(ValueError):
            self.attach()

    def test_duplicate_source_rows_do_not_overwrite_existing_rows(self):
        self.rewards['quests'].append(copy.deepcopy(self.rewards['quests'][0]))
        with self.assertRaises(ValueError):
            self.attach()


class ClientPredicateReferenceJoin(unittest.TestCase):
    def setUp(self):
        self.native = dict(source='reviewed.exe', sha256='a' * 64)
        self.meta = dict(entry=69, file='locks.csv', offset=42, sha256='b' * 64)
        self.row = dict(Id='10', SaveType='2', ContentsLockConditionGroupId='20')
        self.catalog = dict(nativeEnumSource=self.native, sources={'locks:69': self.meta},
                            contentsLockConditionTypes={str(i): 'type' + str(i) for i in range(11)},
                            contentsLocks={'10': dict(self.row, source=dict(entry=69, csv_record=2),
                                                      evaluation='not_evaluated',
                                                      combination='unknown_do_not_assume_AND_OR')})
        self.predicate = dict(self.native, runtime_evaluator_enabled=False,
            forced_lock_presence_checked_first=True, missing_or_empty_group_result=True,
            group_loop='all_conditions_until_first_false_after_prechecks_and_overrides',
            switch=dict(entries=[dict(type=i, name='type' + str(i), target=100 + i) for i in range(11)]))
        self.fields = dict(self.native, csv_source=self.meta, predicate=0x145cf2dc0,
            csv_rows=[dict(csv_record=2, row=self.row)], fields=[dict(name=n, object_offset=o, width=w)
            for n, o, w in [('Id', 8, 4), ('OpenNotification', 12, 1), ('SystemMessageNotify', 13, 1),
                            ('SaveType', 14, 1), ('ContentsLockConditionGroupId', 32, 4)]])

    def attach(self):
        builder.attach_client_predicate_reference(self.catalog, self.predicate, self.fields)

    def test_proven_client_path_does_not_enable_player_evaluation(self):
        locks = copy.deepcopy(self.catalog['contentsLocks'])
        self.attach()
        self.assertEqual(self.catalog['contentsLocks'], locks)
        self.assertEqual(self.catalog['referenceRevision'], 4)
        self.assertFalse(self.catalog['clientPredicateReference']['runtimeEvaluatorEnabled'])

    def test_mixed_native_table_or_row_is_rejected_before_mutation(self):
        for mismatch in ('native', 'table', 'row', 'record'):
            self.setUp()
            if mismatch == 'native':
                self.predicate['sha256'] = 'c' * 64
            elif mismatch == 'table':
                self.fields['csv_source'] = dict(self.meta, sha256='c' * 64)
            elif mismatch == 'row':
                self.fields['csv_rows'][0]['row'] = dict(self.row, SaveType='1')
            else:
                self.fields['csv_rows'][0]['csv_record'] = 3
            before = copy.deepcopy(self.catalog)
            with self.subTest(mismatch=mismatch), self.assertRaises(ValueError):
                self.attach()
            self.assertEqual(self.catalog, before)

    def test_changed_scope_types_or_layout_is_rejected(self):
        for mismatch in ('scope', 'type', 'layout'):
            self.setUp()
            if mismatch == 'scope':
                self.predicate['runtime_evaluator_enabled'] = True
            elif mismatch == 'type':
                self.predicate['switch']['entries'][0]['name'] = 'guessed'
            else:
                self.fields['fields'][4]['object_offset'] = 24
            with self.subTest(mismatch=mismatch), self.assertRaises(ValueError):
                self.attach()


class CompiledFullCatalog(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = json.loads((ROOT / 'vampir/quest-runtime.json').read_text(encoding='utf-8'))

    def test_full_counts_and_native_task_names(self):
        c = self.catalog
        self.assertEqual((len(c['quests']), len(c['tasks']), len(c['actions'])), (1353, 5944, 3892))
        self.assertEqual(sum(map(len, c['rewardGroups'].values())), 5759)
        self.assertEqual(len(c['contentsLocks']), 269)
        self.assertEqual(sum(len(r['conditions']) for r in c['contentsLocks'].values()), 330)
        self.assertEqual(len(c['shopTasks']), 2)
        self.assertTrue(all(task['typeName'].startswith('EQuestTaskType::') for task in c['tasks'].values()))

    def test_bookseller_barrier_is_linked_to_supplies_guide_not_bloodshape(self):
        c = self.catalog
        self.assertEqual(c['quests']['110540']['requiredCompletedQuests'], ['901030'])
        self.assertEqual(c['tasks']['901030010']['typeName'], 'EQuestTaskType::NpcShopBuy')
        self.assertEqual(c['quests']['901030']['contentsLock'], '10100030')
        self.assertEqual(c['contentsLocks']['10100030']['conditions'][0]['ConditionTypeValue1'], '901010')
        self.assertEqual(c['contentsLocks']['10100030']['evaluation'], 'not_evaluated')

    def test_condition_native_names_preserve_unknown_evaluation(self):
        c = self.catalog
        self.assertEqual(c['referenceRevision'], 4)
        self.assertFalse(c['clientPredicateReference']['runtimeEvaluatorEnabled'])
        self.assertEqual(c['clientPredicateReference']['lockFields']['ContentsLockConditionGroupId'],
                         dict(offset=32, width=4))
        self.assertEqual(c['contentsLockConditionTypes']['1'], 'CompletedQuest')
        self.assertEqual(c['contentsLocks']['10100030']['conditions'][0]['typeName'], 'CompletedQuest')
        for lock in c['contentsLocks'].values():
            self.assertEqual(lock['combination'], 'unknown_do_not_assume_AND_OR')
            self.assertEqual(lock['evaluation'], 'not_evaluated')
            for condition in lock['conditions']:
                self.assertEqual(condition['typeName'], c['contentsLockConditionTypes'][condition['ConditionType']])
        self.assertEqual(c['sourceInterpretations']['lockEvaluator'], 'not_implemented')

    def test_reward_rows_keep_native_types_and_source_records(self):
        for rows in self.catalog['rewardGroups'].values():
            self.assertTrue(all(r['typeName'].startswith('ERewardType::') and r['source']['entry'] == 1475 for r in rows))


class ConditionNamesJoin(unittest.TestCase):
    def setUp(self):
        self.meta = dict(entry=70, file='condition.csv', offset=100, sha256='table_hash')
        self.row = dict(Id='199', GroupId='10100030', ConditionType='1', ConditionTypeValue1='901010', ConditionTypeValue2='0')
        self.catalog = dict(nativeEnumSource=dict(source='game.exe', sha256='native_hash'),
            sources={'locks:70': dict(self.meta)}, sourceInterpretations=dict(lockEvaluator='not_implemented'),
            contentsLocks={'10100030': dict(conditions=[dict(self.row, source=dict(entry=70, csv_record=199))],
                evaluation='not_evaluated', combination='unknown_do_not_assume_AND_OR')})
        self.report = dict(source='game.exe', sha256='native_hash', condition_source=dict(self.meta),
            types=[dict(value=i, name='CompletedQuest' if i == 1 else 'Type' + str(i)) for i in range(11)],
            conditions=[dict(row=dict(self.row), csv_record=199, type_name='CompletedQuest', evaluation='not_evaluated')])

    def test_name_does_not_enable_evaluator_or_change_values(self):
        builder.attach_condition_types(self.catalog, self.report)
        condition = self.catalog['contentsLocks']['10100030']['conditions'][0]
        self.assertEqual(condition['ConditionTypeValue1'], '901010')
        self.assertEqual(condition['typeName'], 'CompletedQuest')
        self.assertEqual(self.catalog['sourceInterpretations']['lockEvaluator'], 'not_implemented')

    def test_mixed_native_and_csv_sources_rejected(self):
        for location, key in [('native', 'sha256'), ('native', 'source'), ('table', 'sha256'), ('table', 'offset')]:
            self.setUp()
            (self.report if location == 'native' else self.report['condition_source'])[key] = 'changed'
            with self.assertRaises(ValueError):
                builder.attach_condition_types(self.catalog, self.report)

    def test_changed_type_record_or_provenance_rejected_without_partial_mutation(self):
        for mode in ('type', 'raw', 'record', 'missing', 'evaluated'):
            self.setUp()
            if mode == 'type': self.report['conditions'][0]['type_name'] = 'Other'
            elif mode == 'raw': self.report['conditions'][0]['row']['ConditionTypeValue1'] = '999'
            elif mode == 'record': self.report['conditions'][0]['csv_record'] = 200
            elif mode == 'missing': self.report['conditions'] = []
            else: self.report['conditions'][0]['evaluation'] = 'true'
            before = copy.deepcopy(self.catalog)
            with self.assertRaises(ValueError):
                builder.attach_condition_types(self.catalog, self.report)
            self.assertEqual(self.catalog, before)

    def test_duplicate_or_incomplete_symbols_rejected(self):
        for mode in ('duplicate_value', 'duplicate_name', 'missing'):
            self.setUp()
            if mode == 'duplicate_value': self.report['types'][2]['value'] = 1
            elif mode == 'duplicate_name': self.report['types'][2]['name'] = 'CompletedQuest'
            else: self.report['types'].pop()
            with self.assertRaises(ValueError):
                builder.attach_condition_types(self.catalog, self.report)
