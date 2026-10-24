from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))
from vampir_core.account_store import AccountStore
from vampir_core.bot_device_settings import new_identity
from test_vampir_account_console import FixtureVault


class CharacterConnectionTests(unittest.TestCase):
    def test_different_profiles_on_same_network_survive_switches_and_restart(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'fixture.sqlite3'; store = AccountStore(path, FixtureVault())
            identifier = store.save('fixture@unit.invalid', password='fixture', assignment={})
            store.save_characters(identifier, region='EU', server_id=384, observed_utc='2026-10-24T01:00:00+00:00',
                characters=[dict(index=0, key='111', name='First'), dict(index=1, key='222', name='Second')])
            identities = [new_identity(), new_identity()]
            for index, identity in enumerate(identities):
                store.save('fixture@unit.invalid', assignment=dict(region='EU', server_id=384,
                    character_index=index, character_key=('111', '222')[index], device_profile='custom',
                    device_settings=dict(identity=identity), socks_port=1080))
            connections = AccountStore(path, FixtureVault()).character_connections()
            first = connections[identifier + '|EU|384|111']
            second = connections[identifier + '|EU|384|222']
            self.assertNotEqual(first['device_settings'], second['device_settings'])
            self.assertEqual(first['socks_port'], second['socks_port'])
            store.save('fixture@unit.invalid', assignment=dict(region='EU', server_id=384,
                character_index=0, character_key='111', **first))
            self.assertEqual(store.accounts()[0]['device_settings']['identity'], identities[0])
            self.assertEqual(store.character_connections()[identifier + '|EU|384|222'], second)

    def test_scope_requires_same_account_region_server_key_and_confirmed_slot(self):
        with tempfile.TemporaryDirectory() as folder:
            store = AccountStore(Path(folder) / 'fixture.sqlite3', FixtureVault())
            identifier = store.save('first@unit.invalid', password='fixture', assignment={})
            store.save('second@unit.invalid', password='fixture', assignment={})
            store.save_characters(identifier, region='EU', server_id=384, observed_utc='2026-10-24T01:00:00+00:00',
                characters=[dict(index=0, key='111', name='First')])
            for email, region, server, index, key in (
                    ('second@unit.invalid', 'EU', 384, 0, '111'),
                    ('first@unit.invalid', 'JP', 384, 0, '111'),
                    ('first@unit.invalid', 'EU', 385, 0, '111'),
                    ('first@unit.invalid', 'EU', 384, 0, '222'),
                    ('first@unit.invalid', 'EU', 384, 1, '111')):
                store.save(email, assignment=dict(region=region, server_id=server,
                    character_index=index, character_key=key))
            self.assertEqual(store.character_connections(), {})
            store.save('first@unit.invalid', assignment=dict(region='EU', server_id=384,
                character_index=0, character_key='111', socks_port=1080))
            before = store.character_connections()
            store.save('first@unit.invalid', assignment={})
            store.save_characters(identifier, region='EU', server_id=384, observed_utc='2026-10-24T02:00:00+00:00',
                characters=[dict(index=0, key='222', name='Replacement')])
            store.save('first@unit.invalid', assignment=dict(region='EU', server_id=384,
                character_index=0, character_key='111', socks_port=1081))
            self.assertEqual(store.character_connections(), before)


if __name__ == '__main__': unittest.main()
