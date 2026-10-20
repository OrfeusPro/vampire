import importlib.util
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.lobby_login_error import describe_lobby_login_error


class LobbyResultErrorTests(unittest.TestCase):
    def test_native_mapper_and_localization_reproduce(self):
        path=Path(__file__).parent/'resource-tools/vampir/replay-lobby-result-error.py'
        spec=importlib.util.spec_from_file_location('test_lobby_mapper',path)
        tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)
        actual=tool.build()
        saved=json.loads((tool.mapper.native.ROOT/'code-clues/lobby-result-error-replay.json').read_text('utf-8'))
        self.assertEqual(actual,saved)
        case=next(c for c in actual['cases'] if c['code']==10036)
        self.assertEqual(case['key'],'IsInspect')
        self.assertEqual(case['literal']['address'],0x1498ffc68)
        row=next(r for r in actual['localization']['matches'] if r['row']['Key']=='IsInspect')
        self.assertEqual(row['row']['Value'],'Under maintenance')
        self.assertEqual(describe_lobby_login_error(10036)[0],case['key'])

    def test_unknown_results_are_not_guessed_or_treated_as_winsock(self):
        for code in (0,16,58,10035,0xffffffff):self.assertIsNone(describe_lobby_login_error(code))
        for code in (True,-1,0x100000000,'10036'):
            with self.assertRaises(ValueError):describe_lobby_login_error(code)


if __name__=='__main__':unittest.main()
