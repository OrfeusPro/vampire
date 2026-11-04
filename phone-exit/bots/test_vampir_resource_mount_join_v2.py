"""Mount/dir/name v2: обычная оркестрация с сохранением строгого пути v1."""
import copy
import unittest
from unittest.mock import patch

from test_vampir_resource_directory_v1 import DIRECTORY, WORKFLOW, ResourceDirectoryV1Tests
from test_vampir_update_contracts import load


PATHS = load('resource-directory-paths-v2')
PATH_RULE = 'pak-directory-mount-join-v1'


class ResourceMountJoinV2Tests(ResourceDirectoryV1Tests):
    def setUp(self):
        super().setUp()
        self.modules['resource-directory-paths-v2'] = PATHS
        self.entries[0].update(directory='CSV/',name='Fixture.csv')
        self.activate_v2()

    def activate_v2(self):
        if not self.owner.closed:
            self.owner.abort()
        self.rule = dict(schema=2,recipe=DIRECTORY.RECIPE,key_proof=self.key_proof,path_rule=PATH_RULE)
        self.selector.write_bytes(WORKFLOW.canonical(self.rule))
        self.begin()

    def activate_legacy(self):
        if not self.owner.closed:
            self.owner.abort()
        self.rule = dict(schema=1,recipe=DIRECTORY.RECIPE,key_proof=self.key_proof)
        self.selector.write_bytes(WORKFLOW.canonical(self.rule))
        self.begin()

    def test_verified_directory_separator_and_subdirectory_join_to_mount(self):
        self.entries[0].update(path='/Fixture.csv',directory='/',name='Fixture.csv')
        self.tables.append(dict(self.tables[0],entry=8,offset=64))
        self.records.append(dict(self.records[0],entry=8,offset=64))
        self.prefixes[12] = dict(self.prefixes[0],offset=64)
        self.entries.append(dict(path='/Sub/Second.csv',directory='/Sub/',name='Second.csv',encoded_entry_offset=12))
        value = self.result(self.process())
        self.assertEqual(value['state'],'bound')
        self.assertEqual(value['inputs']['path_rule'],PATH_RULE)
        self.assertEqual([row['canonical_path'] for row in value['csv_bindings']],
            ['ProjectRED/Content/RED/Data/Fixture.csv','ProjectRED/Content/RED/Data/Sub/Second.csv'])
        self.assertEqual(value['directory_entries'][0]['directory'],'/')
        self.assertEqual(value['directory_entries'][0]['name'],'Fixture.csv')
        self.assertEqual(value['path_gaps'],[])

    def test_leading_separator_in_filename_is_never_normalized(self):
        self.entries[0].update(path='CSV//Fixture.csv',directory='CSV/',name='/Fixture.csv')
        value = self.result(self.process())
        self.assertEqual(value['state'],'partial')
        self.assertEqual(value['csv_bindings'],[])
        self.assertIsNone(value['directory_entries'][0]['canonical_path'])
        self.assertEqual(value['unmatched_csv'][0]['reason'],'unsupported_logical_path_form')

    def test_missing_authenticated_components_never_fall_back_to_flattened_name(self):
        self.entries[0].pop('directory')
        with self.assertRaises(ValueError):
            self.process()
        self.assertEqual(self.cache_files(),[])

    def test_legacy_schema_keeps_leading_directory_separator_unmatched(self):
        self.activate_legacy()
        self.entries[0].update(path='/Fixture.csv',directory='/',name='Fixture.csv')
        value = self.result(self.process())
        self.assertNotIn('path_rule',value['inputs'])
        self.assertEqual(value['state'],'partial')
        self.assertEqual(value['csv_bindings'],[])
        self.assertEqual(value['unmatched_csv'][0]['reason'],'unsupported_logical_path_form')

    def test_component_parser_projection_must_equal_original_authenticated_parser(self):
        self.encrypted_directory_fixture()
        original = PATHS.directory_parts
        for field in ('path','encoded_entry_offset','file_count'):
            def changed(raw, count, Cursor, field=field):
                result = copy.deepcopy(original(raw,count,Cursor))
                if field=='file_count':
                    result[field] += 1
                elif field=='path':
                    result['entries'][0][field] = 'CSV/Different.csv'
                else:
                    result['entries'][0][field] += 1
                return result
            with self.subTest(field=field),patch.object(PATHS,'directory_parts',side_effect=changed), \
                    self.assertRaises(ValueError):
                self.scope.directory(self.archive)

    def test_normalization_alias_collision_is_rejected(self):
        self.entries[0].update(path='/Sub/Fixture.csv',directory='/Sub/',name='Fixture.csv')
        self.prefixes[12] = dict(self.prefixes[0],offset=64)
        self.entries.append(dict(path='Sub/Fixture.csv',directory='Sub/',name='Fixture.csv',encoded_entry_offset=12))
        with self.assertRaisesRegex(ValueError,'names are ambiguous'):
            self.process()

    def test_unknown_v2_recipe_and_incomplete_selector_are_rejected(self):
        for changed in ('path_rule','missing','extra','schema'):
            value = dict(self.rule)
            if changed=='path_rule':value['path_rule'] = 'unreviewed-path-join'
            elif changed=='missing':value.pop('path_rule')
            elif changed=='extra':value['unreviewed'] = True
            else:value['schema'] = True
            self.selector.write_bytes(WORKFLOW.canonical(value))
            with self.subTest(selector=changed),self.assertRaises(ValueError):
                DIRECTORY.enabled(self.index,self.args)

    def test_rule_version_changes_cache_identity_and_unchanged_v2_reuses(self):
        self.activate_legacy()
        first = self.process();legacy = self.result(first)
        self.owner.finish()
        self.activate_v2()
        second = self.process();v2 = self.result(second)
        self.assertNotEqual(first['report'],second['report'])
        for key in ('source','record_index','current_csv','key_proof'):
            self.assertEqual(legacy['inputs'][key],v2['inputs'][key])
        self.assertEqual([v['canonical_path'] for v in legacy['csv_bindings']],
            [v['canonical_path'] for v in v2['csv_bindings']])
        self.assertEqual(v2['inputs']['path_rule'],PATH_RULE)
        repeated = self.process()
        self.assertEqual(second['report'],repeated['report'])
        self.assertEqual(self.scope.metrics['cache_hits'],1)
        self.assertEqual(self.scope.metrics['cache_writes'],1)
        self.owner.finish()


def load_tests(loader, tests, pattern):
    # Inherit only the ordinary fixture factory, not its established test suite.
    names = sorted(name for name in ResourceMountJoinV2Tests.__dict__ if name.startswith('test_'))
    return unittest.TestSuite(ResourceMountJoinV2Tests(name) for name in names)


if __name__=='__main__':
    unittest.main()
