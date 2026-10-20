import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).parent / 'resource-tools/vampir'


class SignInLogPresentTests(unittest.TestCase):
    def test_present_service_produces_two_exact_event_fields(self):
        spec = importlib.util.spec_from_file_location('sign_in_present_test', HERE / 'replay-sdk-sign-in-log-present.py')
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        saved = json.loads((tool.native.ROOT / 'code-clues/sdk-sign-in-log-present-replay.json').read_text('utf-8'))
        self.assertEqual(tool.build(), saved)
        self.assertEqual([c['channel_fixture'] for c in saved['cases']], [0, 20, 33, 255])
        for case in saved['cases']:
            self.assertFalse(case['optional_platform_type_available'])
            self.assertEqual(len(case['sent']), 1)
            event = case['sent'][0]
            self.assertEqual((event['raw_mode'], event['raw_event']), (1, 2))
            self.assertEqual([p['key'] for p in event['pairs']], ['GameCode', 'ChannelCode'])
            self.assertEqual(event['pairs'][0]['variant']['value'], 'fixture-game-code')
            self.assertEqual(event['pairs'][1]['variant']['value'], case['channel_fixture'])
            self.assertEqual(case['events'][-1], 'platform_type_absent_fixture')
        names = [row['literal']['text'] for row in saved['sink_names']]
        self.assertIn('FLogImpl::SendPlatformLog', names[0])
        self.assertEqual(names[1:], ['I_LogId', 'I_LogDetailId', 'I_PCSeq', 'I_LogDes'])
        self.assertEqual([r['direct_target'] for r in saved['sink_common_data_calls']].count(0x144551060), 2)


if __name__ == '__main__':
    unittest.main()
