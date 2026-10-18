"""Atlas integrity and ambiguity checks; no installed game or phone required."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parent / 'resource-tools/vampir' / file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


atlas = module('map_atlas', 'build-map-atlas.py')
query = module('map_query', 'query-map-atlas.py')


class MapAtlasTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'table-study').mkdir()

    def table(self, text, header, rows):
        data = text.encode('utf-8-sig')
        (self.root / 'table-study/test.csv').write_bytes(data)
        return dict(file='test.csv', sha256=atlas.sha(data), header=header, rows=rows, entry=123)

    def test_hash_change_blocks_table_even_when_schema_and_count_match(self):
        meta = self.table('Id,WorldInfoId\r\n1,10\r\n', ['Id', 'WorldInfoId'], 1)
        (self.root / 'table-study/test.csv').write_text('Id,WorldInfoId\n1,11\n', encoding='utf-8-sig')
        with self.assertRaisesRegex(ValueError, 'Changed CSV'):
            atlas.load_table(self.root, meta, ['Id'], 'WorldSpot')

    def test_csv_records_and_quoted_newlines_preserve_provenance(self):
        meta = self.table('Id,Name\r\n1,"Карта\nNocturne"\r\n2,Other\r\n', ['Id', 'Name'], 2)
        rows = atlas.load_table(self.root, meta, ['Id'], 'Map')
        self.assertEqual(rows[0]['Name'], 'Карта\nNocturne')
        self.assertEqual(rows[1]['provenance'], dict(table='Map', entry=123, csv_record=3))

    def test_duplicate_map_ids_rejected(self):
        meta = self.table('Id,Name\n1,A\n1,B\n', ['Id', 'Name'], 2)
        with self.assertRaisesRegex(ValueError, 'Duplicate key'):
            atlas.load_table(self.root, meta, ['Id'], 'Map')

    def test_duplicate_localization_variants_retained(self):
        meta = self.table('Id,Name\n1,A\n1,B\n', ['Id', 'Name'], 2)
        rows = atlas.load_table(self.root, meta, ['Id'], 'QuestName_en')
        self.assertEqual([r['Name'] for r in atlas.group(rows, 'Id')['1']], ['A', 'B'])

    def test_image_group_does_not_mix_fog_or_similar_resource_names(self):
        prefix = '/Game/RED/UI/Resource/Texture/Map/'
        self.assertEqual(atlas.image_group(dict(asset_path=prefix+'WorldMap/Field/Nocturne/Fog/Fog_1')),
                         ('WorldMap', 'Field/Nocturne/Fog'))
        self.assertEqual(atlas.image_group(dict(asset_path=prefix+'MiniMap/Dungeon/Argent_01/A_00')),
                         ('MiniMap', 'Dungeon/Argent_01'))
        with self.assertRaises(ValueError):
            atlas.image_group(dict(asset_path='/Game/Other/Nocturne'))

    def test_short_or_extra_csv_cells_rejected(self):
        for text in ['Id,Name\n1\n', 'Id,Name\n1,A,extra\n']:
            meta = self.table(text, ['Id', 'Name'], 1)
            with self.assertRaisesRegex(ValueError, 'row structure'):
                atlas.load_table(self.root, meta, ['Id'], 'Map')

    def test_schema_drift_rejected(self):
        meta = self.table('Id,World\n1,10\n', ['Id', 'World'], 1)
        with self.assertRaisesRegex(ValueError, 'schema'):
            atlas.load_table(self.root, meta, ['Id', 'WorldInfoId'], 'WorldSpot')

    def fixture(self):
        out = self.root / 'maps/atlas'
        (out / 'worlds').mkdir(parents=True)
        world = dict(world=dict(Id='10', MapId='5'))
        atlas.dump(out / 'worlds/10.json', world)
        tables = dict(WorldSpot=[dict(Id='s', WorldInfoId='10')],
                      QuestTask=[dict(Id='t', QuestInfoId='q', TargetSpotInfoId='s', AreaInfoId='a')],
                      Area=[dict(Id='a', WorldInfoId='10')])
        atlas.dump(out / 'tables.json', tables)
        atlas.dump(out / 'index.json', dict(worlds=[dict(id='10', file='worlds/10.json',
            sha256=atlas.file_sha(out / 'worlds/10.json'))], tables_sha256=atlas.file_sha(out / 'tables.json')))
        return out

    def test_quest_and_spot_queries_return_source_links_without_pixel_coordinates(self):
        self.fixture()
        result = query.query(self.root, quest_id='q')
        self.assertEqual(result['tasks'][0]['target_spot']['Id'], 's')
        self.assertEqual(result['tasks'][0]['target_area']['Id'], 'a')
        self.assertNotIn('pixel', result['tasks'][0])
        result = query.query(self.root, spot_id='s')
        self.assertEqual(result['world']['Id'], '10')
        self.assertEqual(result['tasks'][0]['Id'], 't')

    def test_query_rejects_tampered_world_and_tables(self):
        out = self.fixture()
        (out / 'worlds/10.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'World JSON hash'):
            query.query(self.root, world_id='10')
        (out / 'tables.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'Tables JSON hash'):
            query.query(self.root, quest_id='q')


if __name__ == '__main__':
    unittest.main()
