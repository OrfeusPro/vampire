"""Current-source whole Login checks shared by the registered package suites."""
import hashlib
import json
from pathlib import Path

from test_vampir_update_contracts import load, HERE

ROOT = Path('F:/PhoneExit Resources/Vampir')
SHA = 'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
COUNTS = {'login-prepare': 672, 'login-prepare-sdk': 2016,
          'login-prepare-metadata': 448, 'login-metadata': 288,
          'login-result': 320, 'login-result-input': 320,
          'login-result-string': 160, 'login-result-buffer': 160,
          'login-result-handler': 40, 'login-result-body-handler': 160,
          'login-post-state': 44, 'login-continuation': 8}


def current_context(name):
    return json.loads((HERE / 'knowledge/native-contexts' / (name + '-11318.json')).read_text('utf-8'))


def verify_current(test, name, tool):
    context = current_context(name)
    report = load(tool).verify(context, ROOT)
    test.assertEqual(report['source_sha256'], SHA)
    test.assertFalse(report['network_used'] or report['profile_activated'])
    if name in COUNTS:
        test.assertEqual(len(report['cases']), COUNTS[name])
        for case in report['cases']:
            if 'guards' in case:
                test.assertTrue(case['guards'])
    if name.startswith('login-result') and name != 'login-result-registration' and name != 'login-result-handler':
        test.assertEqual((len(report['truncated']), len(report['failures'])), (332, 25))
    if name in ('login-result-buffer', 'login-result-body-handler'):
        test.assertEqual(len(report['construction_cases']), 72)
    if name == 'login-result-body-handler':
        handler = report['handler']
        test.assertTrue(handler['same_packet_reader_used'])
        test.assertEqual((len(handler['cases']), len(handler['rejected'])), (46, 131))
        for case in handler['rejected']:
            test.assertFalse(case['handler_invoked'] or case['events'] or case['writes'])
    if name == 'login-prepare-sdk':
        keys = [field['key'] for field in report['metadata_fields']]
        test.assertEqual((len(keys), len(set(keys)), keys.count('I_World')), (27, 26, 2))
    if name in ('login-result-handler', 'login-result-body-handler'):
        handler = report['handler'] if name == 'login-result-body-handler' else report
        special = [case for case in handler['cases'] if case['code'] == 0x1197]
        test.assertEqual(len(special), 2)
        for case in special:
            allowed = case['settings']['gate_state'] == 0
            actions = [event['action'] for event in case['events']]
            test.assertEqual('post_state' in actions, allowed)
            test.assertEqual(bool([w for w in case['writes'] if w['region'] == 'state']), allowed)
            test.assertEqual('gate_error' in actions, allowed)
    # The same registered run retains its detailed native evidence; a separate
    # replay solely to create an evidence file would duplicate this work.
    load('research-workflow').snapshot(ROOT, 'login-batch-verified-11318', dict(
        name=name, source_sha256=SHA,
        context_sha256=hashlib.sha256((HERE / 'knowledge/native-contexts' / (name + '-11318.json')).read_bytes()).hexdigest(),
        tool_sha256=hashlib.sha256((HERE / (tool + '.py')).read_bytes()).hexdigest(),
        report=report))
    return report
