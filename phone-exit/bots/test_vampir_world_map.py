"""A combined map must preserve contexts, provenance, and missing geometry."""
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('world_map', Path(__file__).parent / 'resource-tools/vampir/build-world-map.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def row(**values):
    return dict(provenance=dict(entry=123, csv_record=4), **values)


class WorldMapTests(unittest.TestCase):
    def fixture(self):
        self.scope = [dict(id='a'), dict(id='b')]
        self.tables = dict(
            World=[row(Id=w, ParentWorldId=w, WorldBoxQuadPosList='') for w in ['a', 'b', 'outside']],
            Area=[row(Id='area', WorldInfoId='a', Waypoint='wp', MapIconId='', MapIconX='', MapIconY=''),
                  row(Id='unknown', WorldInfoId='b', Waypoint='', MapIconId='', MapIconX='', MapIconY='')],
            NpcSpawn=[row(Id='1', WorldInfoId='a', NpcInfoId='n1', PosX='12', PosY='34', MapIconId='', AreaInfoId='', Radius='20'),
                      row(Id='2', WorldInfoId='b', NpcInfoId='n2', PosX='12', PosY='34', MapIconId='', AreaInfoId='', Radius='20'),
                      row(Id='3', WorldInfoId='outside', NpcInfoId='n1', PosX='12', PosY='34', MapIconId='', AreaInfoId='', Radius='20')],
            GadgetSpawn=[row(Id='g', WorldInfoId='a', GadgetInfoId='gd', BasePosX='100', BasePosY='200', MapIconId='')],
            Gadget=[row(Id='gd', BPName='Gate', MapIconId='2001', Type='6')],
            Npc=[row(Id='n1', NameEN='Same', MapIconId='', Img='', Level='2'), row(Id='n2', NameEN='Same', MapIconId='', Img='', Level='3')],
            WorldSpot=[row(Id='destination', WorldInfoId='b', PosX='500', PosY='700', MapIconId='')],
            Waypoint=[row(Id='wp', GadgetSpawnInfoId='g', TeleportSpot='destination')], AreaBox=[],
            QuestName_en=[dict(Id='q', Name='Quest')], QuestTaskName_en=[dict(Id='t', TaskName='Task')],
            QuestTask=[row(Id='t', QuestInfoId='q', TargetSpotInfoId='destination', AreaInfoId='area')])

    def setUp(self):
        self.fixture()

    def build(self):
        return builder.scene(self.tables, self.scope, {'area': ['Area name']}, {}, {'n1': [dict(item_id='item', chains=2)]}, {})

    def test_same_name_and_position_do_not_merge_different_world_records(self):
        scene = self.build()
        records = [p for p in scene['points'] if p['type'] == 'NpcSpawn']
        self.assertEqual([p['key'] for p in records], ['NpcSpawn:1', 'NpcSpawn:2'])
        self.assertEqual([p['world_id'] for p in records], ['a', 'b'])
        self.assertEqual(scene['npcs']['n1']['loot'][0]['chains'], 2)
        self.assertEqual(scene['npcs']['n2']['loot'], [])

    def test_portal_source_is_gadget_position_destination_is_explicit_spot(self):
        scene = self.build()
        point = next(p for p in scene['points'] if p['type'] == 'Waypoint')
        self.assertEqual((point['x'], point['y']), (100, 200))
        edge = scene['portal_links'][0]
        self.assertEqual(edge['destination']['Id'], 'destination')
        self.assertEqual(edge['destination']['WorldInfoId'], 'b')
        self.assertFalse(edge['walkable_path'])

    def test_missing_area_anchor_not_invented_at_origin(self):
        scene = self.build()
        self.assertFalse(any(p['key'] == 'Area:unknown' for p in scene['points']))
        self.assertEqual(scene['unplaced'][0]['key'], 'Area:unknown')
        self.assertEqual(scene['unplaced'][0]['provenance']['csv_record'], 4)

    def test_nonzero_yaw_and_inverted_extents_remain_source_only(self):
        self.tables['AreaBox'] = [row(Id='r', WorldInfoId='a', AreaId='area', Yaw='45', AreaBoxMinPos='x=1,y=2', AreaBoxMaxPos='x=10,y=20'),
                                 row(Id='bad', WorldInfoId='a', AreaId='area', Yaw='0', AreaBoxMinPos='x=10,y=20', AreaBoxMaxPos='x=1,y=2')]
        scene = self.build()
        self.assertEqual(len(scene['polygons']), 0)
        self.assertEqual(scene['rotated_area_boxes'][0]['Id'], 'r')
        self.assertEqual(scene['invalid_area_boxes'][0]['record']['Id'], 'bad')

    def test_quest_relation_keeps_both_worlds_but_exact_point_uses_spot_world(self):
        scene = self.build()
        self.assertEqual(scene['quest_links'][0]['world_ids'], ['a', 'b'])
        task = next(p for p in scene['points'] if p['type'] == 'QuestTask')
        self.assertEqual((task['world_id'], task['x'], task['y']), ('b', 500, 700))

    def test_verified_rotated_box_is_projected_around_its_center_and_can_anchor_a_label(self):
        self.tables['AreaBox']=[row(Id='rotated',WorldInfoId='b',AreaId='unknown',Yaw='90',AreaBoxMinPos='x=100,y=200',AreaBoxMaxPos='x=120,y=260')]
        scene=builder.scene(self.tables,self.scope,{}, {},{}, {},rotation_verified=True)
        self.assertEqual(scene['rotated_area_boxes'],[])
        poly=scene['polygons'][0]
        self.assertTrue(poly['rotation_verified'])
        for a,b in zip(poly['vertices'][0],[140,220]):self.assertAlmostEqual(a,b,places=5)
        label=next(p for p in scene['points'] if p['key']=='Area:unknown')
        self.assertEqual((label['x'],label['y']),(110,230))

    def test_area_only_quest_has_link_without_false_target_coordinate(self):
        self.tables['QuestTask'][0]['TargetSpotInfoId'] = ''
        scene = self.build()
        self.assertEqual(len(scene['quest_links']), 1)
        self.assertFalse(any(p['type'] == 'QuestTask' for p in scene['points']))

    def test_locale_variants_preserved_without_duplicate_strings(self):
        self.assertEqual(builder.names([dict(Id='1', Name='A'), dict(Id='1', Name='B'), dict(Id='1', Name='A')], 'Name'), {'1': ['A', 'B']})


if __name__ == '__main__':
    unittest.main()
