import copy
import importlib.util
import json
from pathlib import Path
import unittest
from types import SimpleNamespace

HERE = Path(__file__).parent/'resource-tools/vampir'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE/(name+'.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


class UpdateContractsTests(unittest.TestCase):
    def setUp(self):
        self.index = load('knowledge-index')
        self.tool = load('update-contracts')
        self.data = self.tool.load(self.index.api(), HERE/'knowledge')

    def test_real_registry_links_and_order(self):
        self.assertEqual(len(self.data['contracts']), 12)
        self.assertLess(self.data['order'].index('game-login'), self.data['order'].index('position'))
        self.assertIn('heartbeat', self.data['capabilities']['world-session']['requires'])

    def test_resource_change_is_local_then_propagates(self):
        changed = self.tool.affected(self.data, exe_changed=False,
            changes=[dict(archive='Game.pak', paths=['Data/QuestTable.csv'])])
        self.assertEqual(changed, ['quests'])
        changed = self.tool.affected(self.data, exe_changed=False,
            changes=[dict(archive='ProjectRED-Windows.pak', paths=['ProjectRED/Config/DefaultGame.ini'])])
        self.assertIn('game-version', changed); self.assertIn('position', changed)
        self.assertNotIn('sdk-gmc2', changed)
        self.assertEqual(self.tool.affected(self.data, exe_changed=False, changes=[]), [])

    def test_unknown_resource_contents_remain_conservative(self):
        changed = self.tool.affected(self.data, exe_changed=False, changes=[dict(archive='Game.pak')])
        self.assertTrue({'map-data','quests','game-ui'} <= set(changed))

    def test_launcher_success_is_not_world_readiness(self):
        result = self.tool.readiness(self.data, {c:dict(state='passed') for c in ('sdk-gmc2','launcher')})
        self.assertEqual(result['launcher']['state'], 'prepared_offline')
        self.assertEqual(result['world-session']['state'], 'incomplete')
        self.assertFalse(result['launcher']['live_verified'])

    def test_invalid_references_cycles_and_builder_are_rejected(self):
        original = self.index.read_json
        for mutation in ('cycle','check','recipe','builder','report-role','report-path','report-cases'):
            data = copy.deepcopy(self.data)
            c = data['contracts'][0]
            if mutation == 'cycle': c['depends_on'] = ['position']
            if mutation == 'check': c['checks'] = ['missing']
            if mutation == 'recipe': c['recipes'] = [dict(key='bad', method='shell')]
            if mutation == 'builder': c['builder'] = 'arbitrary.py'
            if mutation.startswith('report-'):
                c=data['contracts'][1]
                if mutation=='report-role':del c['profile_reports']['defaults']
                if mutation=='report-path':c['profile_reports']['defaults']['pattern']='../private/*/manifest.json'
                if mutation=='report-cases':c['profile_reports']['defaults']['min_cases']=0
            api = self.index.api()
            api.read_json = lambda path: data if path.name == 'update-contracts.json' else original(path)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.tool.load(api, HERE/'knowledge')


if __name__ == '__main__': unittest.main()
