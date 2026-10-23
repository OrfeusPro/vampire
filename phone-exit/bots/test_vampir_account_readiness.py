from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))
from vampir_core.account_readiness import account_readiness


class ReadinessTests(unittest.TestCase):
    def test_saved_sdk_is_not_live_access_and_empty_list_is_not_missing_list(self):
        account = dict(id='fixture', region='JP', server_id=261, character_key=None, registration_status='sdk_created')
        catalogs = {'JP': dict(servers=[dict(id=261)], observed_utc='fixture-time')}
        missing = account_readiness(account, catalogs, {})
        self.assertIn('прочитать персонажей', missing['next_step'])
        empty = account_readiness(account, catalogs, {'fixture|JP|261': dict(characters=[])})
        self.assertIn('пустой список', empty['next_step'])
        self.assertFalse(empty['live_access_verified'])
        self.assertEqual(empty['route'], 'direct')
        self.assertEqual([s['observed'] for s in empty['steps']], [True, True, True, True, True, False])

    def test_existing_character_requires_matching_key_and_target(self):
        account = dict(id='fixture', region='EU', server_id=384, character_key='123', registration_status='registered')
        catalogs = {'EU': dict(servers=[dict(id=384)])}
        lists = {'fixture|EU|384': dict(characters=[dict(index=0, key='456')])}
        self.assertIn('нового не создавать', account_readiness(account, catalogs, lists)['next_step'])
        account['character_key'] = '456'
        self.assertIn('Персонаж назначен', account_readiness(account, catalogs, lists)['next_step'])
        account['region'] = 'JP'
        self.assertFalse(account_readiness(account, catalogs, lists)['steps'][-1]['observed'])


if __name__ == '__main__':
    unittest.main()
