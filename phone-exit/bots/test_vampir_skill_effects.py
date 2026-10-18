"""Effect ID matches never become verified skill relations or recursive applications."""
import importlib.util
import unittest
from pathlib import Path

spec=importlib.util.spec_from_file_location('effect_links',Path(__file__).parent/'resource-tools/vampir/skill-effect-links.py')
links=importlib.util.module_from_spec(spec);spec.loader.exec_module(links)


class SkillEffectTests(unittest.TestCase):
    def test_item_effect_match_keeps_provenance_and_does_not_prove_application(self):
        effect=dict(record=dict(Id='12'),operations=[dict(record=dict(OperationType='2001',OperationParam1='12'))])
        result=links.item_candidate(dict(Id='item',EffectType='1',EffectParams='12',provenance=dict(csv_record=3)),{'12':effect})
        self.assertEqual(result['origin'],'item')
        self.assertEqual(result['item_provenance'],dict(csv_record=3))
        self.assertEqual(result['effect'],effect)
        self.assertFalse(result['relation_verified'])
        self.assertFalse(result['runtime_application_verified'])
        self.assertNotIn('effect',result['effect']['operations'][0])

    def test_item_effect_candidates_exclude_other_types_and_do_not_parse_id_prefixes(self):
        for kind,param in [('4','12'),('20','12'),('1',''),('1','0')]:
            self.assertIsNone(links.item_candidate(dict(Id='i',EffectType=kind,EffectParams=param),{'12':{}}))
        for param in ['12tail','012','missing']:
            result=links.item_candidate(dict(Id='i',EffectType='1',EffectParams=param),{'12':{}})
            self.assertEqual(result['effect_id'],param)
            self.assertIsNone(result['effect'])
            self.assertEqual(result['status'],'candidate_definition_missing')

    def test_time_fields_keep_distinct_values_without_choosing_duration_or_units(self):
        record=dict(Duration='500',MinDuration='7000',MaxDuration='7000',DurationGrowthRate='1',Period='0')
        timing=links.timing_fields(record)
        self.assertEqual(timing['raw'],record)
        self.assertTrue(timing['duration_outside_bounds'])
        self.assertIsNone(timing['unit'])
        self.assertFalse(timing['field_precedence_verified'])
        self.assertFalse(links.timing_fields(dict(record,Duration='7000'))['duration_outside_bounds'])
        self.assertIsNone(links.timing_fields(dict(record,Duration=''))['duration_outside_bounds'])
        self.assertIsNone(links.timing_fields(dict(record,Duration='1.5'))['duration_outside_bounds'])
        big=dict(Duration='2500000000',MinDuration='2500000000',MaxDuration='2500000000')
        self.assertFalse(links.timing_fields(big)['duration_outside_bounds'])

    def test_buff_and_overlay_domains_have_distinct_zero_and_fallbacks(self):
        semantics=dict(buff_types={'0':dict(name='Deadly')},overlay_types={'0':dict(name='Allow'),'3':dict(name='ForceAllow')},
            unknown_buff_value=3,unknown_overlay_value=5)
        self.assertEqual(links.describe_rule('0',semantics,'buff')['name'],'Deadly')
        self.assertEqual(links.describe_rule('0',semantics,'overlay')['name'],'Allow')
        self.assertEqual(links.describe_rule('3',semantics,'buff')['status'],'parser_fallback')
        self.assertEqual(links.describe_rule('3',semantics,'overlay')['name'],'ForceAllow')
        self.assertIsNone(links.describe_rule('5',semantics,'overlay')['name'])
        self.assertFalse(links.describe_rule('0',semantics,'overlay')['runtime_rule_verified'])
        self.assertEqual(links.describe_rule('99',semantics,'overlay')['status'],'unknown')
        self.assertEqual(links.describe_rule('0',None,'buff')['status'],'unknown')
        with self.assertRaises(ValueError):
            links.describe_rule('0',semantics,'other')

    def test_action_none_zero_and_parser_fallback_are_distinct(self):
        semantics=dict(actions={'0':dict(name='None'),'6':dict(name='Stun')},unknown_parser_value=56)
        self.assertEqual(links.describe_action('0',semantics)['name'],'None')
        self.assertEqual(links.describe_action('6',semantics)['name'],'Stun')
        self.assertEqual(links.describe_action('56',semantics)['status'],'parser_fallback')
        self.assertIsNone(links.describe_action('56',semantics)['name'])
        self.assertEqual(links.describe_action('101',semantics)['status'],'unknown')
        self.assertFalse(links.describe_action('6',semantics)['runtime_behavior_verified'])
        self.assertEqual(links.describe_action('0',None)['status'],'unknown')

    def test_matching_id_is_candidate_and_all_effect_actions_are_preserved(self):
        effects=links.index_effects([dict(Id='e',Type='0')],
            [dict(EffectInfoId='e',OperationType='101',OperationParam1='0'),
             dict(EffectInfoId='e',OperationType='2001',OperationParam1='e')],
            dict(EOperationType={'101':dict(name='Stun')},EEffectType={}))
        result=links.candidate(dict(Id='op',OperationType='2001',OperationParam1='e'),effects)
        self.assertEqual(result['status'],'candidate_param1_id_match_only')
        self.assertFalse(result['relation_verified'])
        self.assertFalse(result['runtime_application_verified'])
        self.assertEqual(len(result['effect']['operations']),2)
        self.assertEqual(result['effect']['operations'][0]['record']['OperationParam1'],'0')
        self.assertNotIn('effect',result['effect']['operations'][1])

    def test_unrelated_operations_sentinels_and_missing_definitions(self):
        for kind,param in [('2004','321001'),('2001','0'),('2001','')]:
            self.assertIsNone(links.candidate(dict(Id='op',OperationType=kind,OperationParam1=param),{}))
        result=links.candidate(dict(Id='op',OperationType='2001',OperationParam1='missing'),{})
        self.assertEqual(result['status'],'candidate_definition_missing')
        self.assertIsNone(result['effect'])
        self.assertFalse(result['relation_verified'])

    def test_duplicate_definitions_are_rejected(self):
        with self.assertRaises(ValueError):
            links.index_effects([dict(Id='same',Type='0'),dict(Id='same',Type='1')],[],dict(EOperationType={},EEffectType={}))


if __name__=='__main__':
    unittest.main()
