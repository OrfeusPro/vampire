"""Check generated catalogue against independent raw CSV reads, including every join."""
import csv
import hashlib
import json
import unittest
from pathlib import Path

ROOT = Path('F:/PhoneExit Resources/Vampir')


@unittest.skipUnless((ROOT/'maps/collections/manifest.json').exists(), 'Resource library unavailable')
class CollectionDataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads((ROOT/'maps/collections/manifest.json').read_text('utf-8'))
        cls.data = json.loads((ROOT/'maps/collections/collections.json').read_text('utf-8'))

    def rows(self, entry):
        with (ROOT/f'table-study/pakchunk1-Windows-{entry}.csv').open(encoding='utf-8-sig', newline='') as stream:
            return list(csv.DictReader(stream))

    def test_source_hashes_and_deployed_data(self):
        for relative, expected in self.manifest['sources'].items():
            self.assertEqual(hashlib.sha256((ROOT/relative).read_bytes()).hexdigest(), expected, relative)
        self.assertEqual(hashlib.sha256((ROOT/'maps/collections/collections.json').read_bytes()).hexdigest(), self.manifest['sha256'])

    def test_all_groups_members_and_enchant_counts_preserved(self):
        groups = self.rows(53)
        members = self.rows(51)
        output = self.data['entries']
        self.assertEqual({r['Id'] for r in groups}, {r['id'] for r in output})
        actual = {m['row']['Id']: (e['id'], m) for e in output for m in e['requirements']}
        self.assertEqual(len(actual), len(members))
        for raw in members:
            group, member = actual[raw['Id']]
            self.assertEqual(group, raw['GroupId'])
            for key, value in raw.items():
                self.assertEqual(member['row'][key], value)
            self.assertEqual(member['item_id'], raw['CollectParam'])
            self.assertIn(member['item_id'], self.data['items'])

    def test_all_bonus_rows_exact_and_no_group_without_bonus(self):
        operations = self.rows(1521)
        by_group = {}
        for row in operations:
            by_group.setdefault(row['GroupId'], []).append(row)
        for entry in self.data['entries']:
            expected = by_group[entry['row']['OperationGroupId']]
            self.assertEqual(len(entry['bonuses']), len(expected))
            self.assertEqual([{k: b['row'][k] for k in expected[0]} for b in entry['bonuses']], expected)

    def test_localized_names_and_placeholders_resolved_without_eval(self):
        names = {r['Id']: r['Name'] for r in self.rows(406)}
        for entry in self.data['entries']:
            name = names[entry['id']]
            for i in (1, 2):
                name = name.replace('{ReplaceString'+str(i)+'}', entry['row']['ReplaceString'+str(i)])
            self.assertEqual(entry['name'], name.strip())
            self.assertNotIn('{ReplaceString', entry['name'])

    def test_native_diagnostics_still_match_client(self):
        exe = self.manifest['client_exe']
        raw = Path(exe['path']).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), exe['sha256'])
        for diagnostic in self.manifest['diagnostics']:
            expected = diagnostic['text'].encode('utf-16le')
            self.assertEqual(raw[diagnostic['offset']:diagnostic['offset']+len(expected)], expected)


if __name__ == '__main__':
    unittest.main()
