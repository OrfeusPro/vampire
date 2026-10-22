from dataclasses import replace
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))
from vampir_core.account_catalog import build_account_catalog
from vampir_core.account_store import AccountStore
from vampir_core.lobby_server_list import LobbyServerListResult, LobbyServerGroup, LobbyServerRecord

STAMP = '2026-10-22T19:00:00+00:00'


def fixture():
    records = tuple(LobbyServerRecord((label, 'not-exported.invalid', ''), (group, identifier, 0, 0),
        (12000, 0), (0, state, 0), (True, False, False, False, False), ())
        for group, identifier, label, state in ((358, 383, '프렐류드1', 0), (358, 384, '프렐류드2', 0),
            (359, 385, '오퍼스1', 2), (10, 1, 'Other 1', 0)))
    return LobbyServerListResult(0, (LobbyServerGroup(358, 'Prelude', 7), LobbyServerGroup(359, 'Opus', 7),
        LobbyServerGroup(10, 'Other', 6)), records, (), (), (), (False, False), 0, ('', ''))


class AccountCatalogTests(unittest.TestCase):
    def catalog(self, source):
        return build_account_catalog(source, region='EU', observed_utc=STAMP)

    def test_europe_names_are_derived_from_lobby_and_other_regions_are_absent(self):
        catalog = self.catalog(fixture())
        self.assertEqual([s['name'] for s in catalog['servers']], ['Prelude 1', 'Prelude 2', 'Opus 1'])
        self.assertEqual(catalog['servers'][1]['id'], 384)
        self.assertEqual(catalog['servers'][1]['source_name'], '프렐류드2')
        self.assertFalse(catalog['servers'][1]['excluded'])
        self.assertTrue(catalog['servers'][2]['excluded'])
        self.assertNotIn('not-exported.invalid', str(catalog))

    def test_unknown_label_is_preserved_instead_of_guessing_a_number(self):
        source = fixture()
        source = replace(source, servers=(replace(source.servers[0], strings=('Seasonal', '', '')),))
        self.assertEqual(self.catalog(source)['servers'][0]['name'], 'Seasonal')

    def test_ambiguous_ids_and_alternate_or_rejected_results_are_rejected(self):
        source = fixture()
        for value in (replace(source, groups=source.groups + source.groups[:1]),
                      replace(source, servers=source.servers + source.servers[:1]),
                      replace(source, flags=(False, True)), replace(source, result_code=9),
                      replace(source, servers=())):
            with self.subTest(value=value), self.assertRaises(ValueError): self.catalog(value)

    def test_rejected_update_keeps_previous_catalog_and_restart_keeps_names(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'console.sqlite3'
            store = AccountStore(path)
            store.save_catalog('EU', self.catalog(fixture()))
            with self.assertRaises(ValueError):
                store.save_catalog('EU', self.catalog(replace(fixture(), result_code=9)))
            self.assertEqual(AccountStore(path).catalogs()['EU']['servers'][1]['name'], 'Prelude 2')


if __name__ == '__main__': unittest.main()
