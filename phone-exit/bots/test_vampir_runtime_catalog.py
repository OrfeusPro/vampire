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

    def test_reward_rows_keep_native_types_and_source_records(self):
        for rows in self.catalog['rewardGroups'].values():
            self.assertTrue(all(r['typeName'].startswith('ERewardType::') and r['source']['entry'] == 1475 for r in rows))
