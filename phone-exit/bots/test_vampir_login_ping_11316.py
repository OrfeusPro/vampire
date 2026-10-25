"""Current native replay and source refusal; no credentials or network."""
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).parent/'resource-tools/vampir'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'),HERE/(name+'.py'))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m


class LoginPing11316Tests(unittest.TestCase):
    def exports(self):
        return json.loads((HERE/'knowledge/native-contexts/login-ping-exports-11316.json').read_text('utf-8'))

    def test_current_native_clock_and_lobby_offset(self):
        result = load('replay-login-clock-11316').verify(self.exports())
        self.assertEqual((result['cases'],result['lobby_cases']),(24,10))

    def test_current_producer_boundaries_and_readiness(self):
        self.assertEqual(load('replay-login-ping-11316').verify(self.exports())['cases'],36)

    def test_tampered_export_is_refused(self):
        bad = {key:'0'*64 for key in self.exports()}
        with self.assertRaisesRegex(ValueError,'export SHA'):
            load('replay-login-ping-11316').verify(bad)


if __name__ == '__main__': unittest.main()
