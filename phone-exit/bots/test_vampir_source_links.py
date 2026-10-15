"""Source-link validation does not require a local game installation."""
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('reward_links', Path(__file__).parent / 'resource-tools/vampir/build-reward-links.py')
links = importlib.util.module_from_spec(spec)
spec.loader.exec_module(links)


class ContentsLockLinks(unittest.TestCase):
    def test_multiple_conditions_preserve_order_and_unknown_semantics(self):
        rows = [dict(Id='a', GroupId='g', ConditionType='1', ConditionTypeValue1='901010'),
                dict(Id='b', GroupId='g', ConditionType='0', ConditionTypeValue1='48')]
        result = links.connect_locks([dict(Id='lock', ContentsLockConditionGroupId='g')], rows)['lock']
        self.assertEqual(result['conditions'], rows)
        self.assertEqual(result['groupResolution'], 'resolved')
        self.assertEqual(result['evaluation'], 'not_evaluated')
        self.assertEqual(result['combination'], 'unknown_do_not_assume_AND_OR')

    def test_missing_group_is_distinct_from_no_declared_group(self):
        result = links.connect_locks([dict(Id='a', ContentsLockConditionGroupId='missing'),
                                      dict(Id='b', ContentsLockConditionGroupId='0')], [])
        self.assertEqual(result['a']['groupResolution'], 'missing')
        self.assertEqual(result['b']['groupResolution'], 'none_declared')
        self.assertEqual(result['b']['evaluation'], 'not_evaluated')

    def test_duplicate_ids_are_rejected_instead_of_silently_overwritten(self):
        row = dict(Id='duplicate', ContentsLockConditionGroupId='g')
        with self.assertRaises(ValueError):
            links.connect_locks([row, row], [])

    def test_source_fields_and_flags_survive_join(self):
        row = dict(Id='lock', ContentsLockConditionGroupId='g', OverrideCollapsed='1',
                   ServerServiceGroupId='123', source=dict(entry=69, csv_record=2))
        result = links.connect_locks([row], [])['lock']
        for key, value in row.items():
            self.assertEqual(result[key], value)

    def test_duplicate_condition_ids_are_rejected(self):
        condition = dict(Id='duplicate', GroupId='g')
        with self.assertRaises(ValueError):
            links.connect_locks([], [condition, condition])
