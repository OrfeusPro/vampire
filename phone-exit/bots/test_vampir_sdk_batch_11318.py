import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from test_vampir_update_contracts import load,HERE

ROOT=Path('F:/PhoneExit Resources/Vampir')
CONTEXT=HERE/'knowledge/native-contexts/sdk-batch-11318.json'


class SdkBatch11318Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool=load('run-sdk-batch-11318')
        cls.path,cls.report,_=cls.tool.run(ROOT)

    def test_all_native_components_and_one_assembled_candidate(self):
        r=self.report
        self.assertEqual(r['native_case_executions'],3667)
        self.assertEqual(r['primitive_cases'],dict(numeric=112,channels=176))
        self.assertEqual(len(r['guard']['roots']),34)
        self.assertEqual(len(r['guard']['switch_cases']),21)
        self.assertEqual(set(r['reports']),set(self.tool.CASES))
        self.assertFalse(r['network_used'] or r['profile_activated'] or r['active_runtime_settings_verified'])
        self.assertEqual(r['profile_candidate']['public_gmc2']['profile'],dict(
            base='https://apis.netmarble.com/gc2',group='netmarbles-v5',sdk_version='5.2.11',
            build_code=0,market='nmp',game_code='thered',service_code='netmarbles'))
        self.assertEqual(len(r['profile_candidate']['public_gmc2']['request']['headers']),6)
        for report in r['reports'].values():
            self.assertEqual(report['source_sha256'],self.tool.SHA)
            for case in report['cases']:
                if 'canaries_unchanged' in case:self.assertTrue(case['canaries_unchanged'])

    def test_nid_rejected_inputs_never_reach_adoption(self):
        for name in ('replay-nid-result-11318','replay-nid-primitives-11318'):
            report=self.report['reports'][name]
            self.assertEqual(len(report['cases']),self.tool.CASES[name])
            for case in report['cases']:
                captures=[e for e in case['events'] if e['kind'] in ('settings_capture','country_capture','channel_capture')]
                self.assertEqual(bool(captures),case['outcome']=='adoption_calls_reached')
        self.assertTrue(self.report['reports']['replay-nid-primitives-11318']['native_primitives'])

    def test_one_cached_report_is_reused_without_native_replay(self):
        original=self.tool.load
        def lookup(name):
            if name in self.tool.CASES:raise AssertionError('Native replay repeated on unchanged inputs')
            return original(name)
        with patch.object(self.tool,'load',side_effect=lookup):
            path,report,reused=self.tool.run(ROOT)
        self.assertTrue(reused);self.assertEqual(path,self.path);self.assertEqual(report,self.report)

    def test_corrupted_cache_report_is_rejected(self):
        original=Path.read_bytes
        def read(path):
            raw=original(path)
            return raw+b'changed' if path.resolve()==self.path.resolve() else raw
        with patch.object(Path,'read_bytes',read):
            with self.assertRaisesRegex(ValueError,'cache report changed'):self.tool.run(ROOT)

    def test_changed_source_export_and_table_are_rejected(self):
        base=json.loads(CONTEXT.read_text('utf-8'));tool=load('verify-sdk-batch-11318')
        for kind in ('source','export','table','generated'):
            context=copy.deepcopy(base)
            if kind=='source':context['source_sha256']='0'*64
            elif kind=='export':context['exports'][next(iter(context['exports']))]='0'*64
            elif kind=='table':context['switches'][0]['bytes']='00'+context['switches'][0]['bytes'][2:]
            else:context['generated_files'][next(iter(context['generated_files']))]='0'*64
            with self.subTest(kind=kind),self.assertRaisesRegex(ValueError,'source|export SHA|table|replay changed'):
                tool.verify(context,ROOT)

    def test_candidate_stays_offline_and_uses_same_native_report(self):
        profile=load('build-sdk-profile-11318').build(ROOT)
        self.assertEqual(profile['source_sha256'],self.tool.SHA)
        self.assertEqual(profile['evidence']['batch']['path'],str(self.path))
        self.assertEqual(profile['supported_auth_flows'],[])
        self.assertFalse(profile['runtime_enabled'] or profile['network_ready'] or profile['game_protocol_verified'])


if __name__=='__main__':unittest.main()
