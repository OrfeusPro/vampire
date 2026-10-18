"""Level replacements must not erase base cooldowns or cross skill boundaries."""
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('skill_levels', Path(__file__).parent/
    'resource-tools/vampir/build-skill-level-code.py')
levels = importlib.util.module_from_spec(spec); spec.loader.exec_module(levels)


extra_spec=importlib.util.spec_from_file_location('skill_level_extra',Path(__file__).parent/
    'resource-tools/vampir/build-skill-level-extra-code.py')
extra=importlib.util.module_from_spec(extra_spec);extra_spec.loader.exec_module(extra)


mp_spec=importlib.util.spec_from_file_location('skill_level_mp',Path(__file__).parent/
    'resource-tools/vampir/build-skill-level-mp-code.py')
mp=importlib.util.module_from_spec(mp_spec);mp_spec.loader.exec_module(mp)


class SkillMpTests(unittest.TestCase):
    def test_independent_mp_replacement_first_inclusive_row_and_base_fallback(self):
        skill=dict(Id='1',MpMin='10',MpMax='20',provenance=dict(csv_record=2))
        rows=[dict(SkillInfoId='11',MinLevel='6',MaxLevel='7',ChangeMpMin='90',ChangeMpMax='90'),
              dict(SkillInfoId='1',MinLevel='6',MaxLevel='7',ChangeMpMin='7',ChangeMpMax='0',provenance=dict(csv_record=3)),
              dict(SkillInfoId='1',MinLevel='6',MaxLevel='7',ChangeMpMin='1',ChangeMpMax='1')]
        for level in [5,6,7,8]:
            result=mp.mp_at_level(skill,rows,level)
            self.assertEqual(result['values'],dict(MpMin='7',MpMax='20') if level in [6,7] else dict(MpMin='10',MpMax='20'))
            self.assertFalse(result['runtime_verified'])
        self.assertEqual(mp.mp_at_level(skill,rows,6)['origins']['MpMin']['provenance'],dict(csv_record=3))
        self.assertEqual(mp.mp_at_level(skill,[dict(rows[1],ChangeMpMin='')],6)['values']['MpMin'],'10')

    def test_mp_invalid_input_is_not_wrapped_or_partially_parsed(self):
        for value in ['-1','2147483648','12tail','１２']:
            with self.assertRaises(ValueError):mp.mp_at_level(dict(Id='1'),[dict(SkillInfoId='1',MinLevel='0',MaxLevel='7',ChangeMpMin=value)],6)
        for level in [-1,32768,6.5]:
            with self.assertRaises(ValueError):mp.mp_at_level(dict(Id='1'),[],level)


class SkillExtraTests(unittest.TestCase):
    def test_resource_and_stack_replacements_are_independent_and_not_additive(self):
        skill=dict(Id='1',Resource='base',StackCount='1',provenance=dict(csv_record=2))
        rows=[dict(SkillInfoId='11',MinLevel='6',MaxLevel='7',ChangeResource='wrong',ChangeStackCount='99'),
              dict(SkillInfoId='1',MinLevel='6',MaxLevel='7',ChangeResource='A',ChangeStackCount='2',provenance=dict(csv_record=3))]
        for level in [5,6,7,8]:
            result=extra.extra_at_level(skill,rows,level)
            self.assertEqual(result['values'],dict(Resource='A',StackCount='2') if level in [6,7] else dict(Resource='base',StackCount='1'))
            self.assertFalse(result['runtime_verified'])
        self.assertEqual(extra.extra_at_level(skill,rows,6)['origins']['Resource']['provenance'],dict(csv_record=3))

    def test_first_range_zero_fallback_does_not_continue_and_resource_is_not_trimmed(self):
        skill=dict(Id='1',Resource='base',StackCount='3')
        first=dict(SkillInfoId='1',MinLevel='6',MaxLevel='7',ChangeResource='',ChangeStackCount='0')
        second=dict(first,ChangeResource='other',ChangeStackCount='8')
        self.assertEqual(extra.extra_at_level(skill,[first,second],6)['values'],dict(Resource='base',StackCount='3'))
        self.assertEqual(extra.extra_at_level(skill,[dict(first,ChangeResource=' ')],6)['values']['Resource'],' ')

    def test_invalid_stack_bytes_and_levels_fail(self):
        skill=dict(Id='1',Resource='',StackCount='')
        for value in ['256','-1','2tail','２']:
            with self.assertRaises(ValueError):extra.extra_at_level(skill,[dict(SkillInfoId='1',MinLevel='0',MaxLevel='7',ChangeStackCount=value)],6)
        for level in [-1,32768,6.5]:
            with self.assertRaises(ValueError):extra.extra_at_level(skill,[],level)


class SkillLevelTests(unittest.TestCase):
    def setUp(self):
        self.base = dict(Id='110033', MinCoolTime='30000', MaxCoolTime='30000',
                         provenance=dict(table='Skill', csv_record=2))
        self.change = dict(SkillInfoId='110033', MinLevel='6', MaxLevel='7',
            ChangeMinCoolTime='23000', ChangeMaxCoolTime='23000',
            provenance=dict(table='SkillLevel', csv_record=3))

    def test_both_range_endpoints_and_adjacent_levels(self):
        for level in [5, 6, 7, 8]:
            result = levels.cooldown_at_level(self.base, [self.change], level)
            self.assertEqual(result['values']['MinCoolTime'], '23000' if level in [6,7] else '30000')
            self.assertEqual(result['values']['MaxCoolTime'], result['values']['MinCoolTime'])
            self.assertIsNone(result['time_unit'])
            self.assertFalse(result['runtime_cooldown_verified'])
        self.assertEqual(levels.cooldown_at_level(self.base, [self.change], 6)
            ['origins']['MinCoolTime']['provenance']['csv_record'], 3)

    def test_zero_and_empty_changes_keep_each_base_field(self):
        for raw in ['', '0', '00']:
            result = levels.cooldown_at_level(self.base,
                [dict(self.change, ChangeMinCoolTime=raw)], 6)
            self.assertEqual(result['values'], dict(MinCoolTime='30000', MaxCoolTime='23000'))
            self.assertEqual(result['origins']['MinCoolTime']['table'], 'Skill')
            self.assertEqual(result['origins']['MaxCoolTime']['table'], 'SkillLevel')

    def test_unrelated_skill_and_first_matching_row(self):
        unrelated = dict(self.change, SkillInfoId='another')
        self.assertEqual(levels.cooldown_at_level(self.base, [unrelated], 6)
                         ['values']['MaxCoolTime'], '30000')
        # A zero in the first match falls back to base, not a later overlapping row.
        first = dict(self.change, ChangeMaxCoolTime='0')
        self.assertEqual(levels.cooldown_at_level(self.base, [first,self.change], 6)
                         ['values']['MaxCoolTime'], '30000')
        self.assertEqual(self.base['MinCoolTime'], '30000')

    def test_reject_ambiguous_levels(self):
        for level in [True, '6', 6.5, -1, 32768]:
            with self.assertRaises(ValueError):
                levels.cooldown_at_level(self.base, [self.change], level)


if __name__ == '__main__':
    unittest.main()
