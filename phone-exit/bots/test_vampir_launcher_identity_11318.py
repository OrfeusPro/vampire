"""Current native callback must preserve independent identity fields and gates."""
import importlib.util
from pathlib import Path
import unittest


class IdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p = Path(__file__).parent/'resource-tools/vampir/replay-launcher-identity-11318.py'
        spec = importlib.util.spec_from_file_location('launcher_identity', p)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        cls.artifact, cls.report = module.run()

    def test_native_keys_and_execution_boundaries(self):
        r = self.report
        self.assertTrue(self.artifact.is_file()); self.assertTrue(r['native_execution'])
        self.assertFalse(r['network_used']); self.assertFalse(r['profile_activation'])
        self.assertEqual(r['constructor']['keys'], dict(zip(
            ('0x20', '0x28', '0x30', '0x38', '0x40', '0x48', '0x50'),
            ('playerInfo', 'player', 'playerId', 'playerStatus', 'gameRegion', 'idpInfo', 'joinedCountryCode'))))
        self.assertEqual(set(r['coverage']), {'0x1444d3a30', '0x1444c2010', '0x144552560'})
        self.assertEqual(r['coverage']['0x1444c2010'], 16)

    def test_fields_missing_empty_and_lazy_context(self):
        rows = self.report['cases']; self.assertEqual(len(rows), 40)
        for lazy in (False, True):
            selected = [r for r in rows if r['lazy_init'] == lazy]
            self.assertEqual(len(selected), 20)
            missing = next(r for r in selected if r['name'] == 'no-result')
            self.assertEqual(missing['sdk_access_token'], 'old-sdk-fixture')
            self.assertEqual(missing['game_region'], 'old-region-fixture')
            self.assertFalse(any(e[0] in ('player-setter', 'save', 'load', 'sdk-init') for e in missing['events']))
            empty = next(r for r in selected if r['name'] == 'empty-fields')
            self.assertEqual((empty['sdk_access_token'], empty['game_region'], empty['joined_country']), ('', '', ''))
            for row in selected:
                p = row['body'].get('resultData', {}).get('playerInfo', {}).get('player')
                statuses = [e[1] for e in row['events'] if e[0] == 'status']
                self.assertEqual(statuses, [p['playerStatus']] if p and 'playerStatus' in p else [])
                self.assertEqual(sum(e[0] == 'dispatch-original' for e in row['events']), 1)


if __name__ == '__main__': unittest.main()
