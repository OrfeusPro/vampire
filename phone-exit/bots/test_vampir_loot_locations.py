"""Filtering source locations must keep same-name NPCs and worlds distinct."""
import importlib.util
import unittest
from pathlib import Path


def load(name,file):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).parent/'resource-tools/vampir'/file)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


query=load('loot_location_query','query-npc-loot.py')
records=load('loot_record_evidence','build-loot-record-links.py')


class LootLocations(unittest.TestCase):
    def fixture(self):
        chains=[dict(npc_id='a',npc_reward_id='r1',raw_rate='90',chance_percent=None),
                dict(npc_id='a',npc_reward_id='r2',raw_rate='5',chance_percent=None),
                dict(npc_id='b',npc_reward_id='r3',raw_rate='30',chance_percent=None)]
        npcs=[dict(id='a',name='Same name'),dict(id='b',name='Same name')]
        locations={'a':[dict(Id='s1',WorldInfoId='10',PositionGroupId='p',PosX='123',VisibleOnQuestTaskInfoId='q'),
                        dict(Id='s2',WorldInfoId='11')], 'b':[dict(Id='s3',WorldInfoId='12')]}
        return chains,npcs,locations

    def test_world_filter_keeps_both_chains_and_visibility_source_fields(self):
        result=query.filter_item_locations(*self.fixture(),world='10')
        self.assertEqual([r['npc_reward_id'] for r in result['npc_sources']],['r1','r2'])
        self.assertEqual([n['id'] for n in result['npcs']],['a'])
        self.assertEqual(result['spawn_records']['a'][0]['PositionGroupId'],'p')
        self.assertEqual(result['spawn_records']['a'][0]['VisibleOnQuestTaskInfoId'],'q')
        self.assertFalse(result['navigation_ready'])

    def test_exact_world_ids_are_not_prefix_matches(self):
        result=query.filter_item_locations(*self.fixture(),world='1')
        self.assertEqual(result['npc_sources'],[])
        self.assertEqual(result['spawn_records'],{})

    def test_no_world_filter_keeps_all_sources(self):
        result=query.filter_item_locations(*self.fixture())
        self.assertEqual(len(result['npc_sources']),3)
        self.assertEqual(len(result['spawn_records']['a']),2)
        self.assertTrue(all(r['chance_percent'] is None for r in result['npc_sources']))

    def test_missing_spawn_does_not_mean_no_loot(self):
        chains,npcs,locations=self.fixture();locations.pop('a')
        result=query.filter_item_locations(chains,npcs,locations)
        self.assertEqual(len(result['npc_sources']),3)
        self.assertEqual(result['spawn_records']['a'],[])
        result=query.filter_item_locations(chains,npcs,locations,world='10')
        self.assertEqual(result['npc_sources'],[])

    def test_rate_callback_requires_both_expected_pointer_and_exact_empty_code(self):
        records.validate_slot(0x1413fe190,0x1413fe190,bytes.fromhex('c20000'))
        with self.assertRaises(ValueError):records.validate_slot(0x1413fe191,0x1413fe190,bytes.fromhex('c20000'))
        with self.assertRaises(ValueError):records.validate_slot(0x1413fe190,0x1413fe190,bytes.fromhex('9090c3'))


if __name__=='__main__':unittest.main()
