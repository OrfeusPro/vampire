"""Caller policy branches must reach the actual CharacterListRead constructor."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

HERE=Path(__file__).resolve().parent


class CharacterListCallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location('request_caller_test',HERE/'resource-tools/vampir/replay-character-list-caller.py')
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/character-list-caller-replay.json').read_text('utf-8'))

    def test_native_report_and_slot90_call_source(self):
        self.assertEqual(self.tool.build(),self.report)
        raw=Path(self.report['source']).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),self.report['sha256'])
        rows={r['address']:r for f in self.report['fragments'] for r in f['instructions']}
        self.assertEqual(rows[0x1468f1e48]['direct_target'],0x1456048e0)
        self.assertEqual(rows[0x1468f1e53]['bytes'],'ff9290000000')
        for f in self.report['fragments']:
            data=raw[f['file_offset']:f['file_offset']+f['end_rva']-f['begin_rva']]
            self.assertEqual(hashlib.sha256(data).hexdigest(),f['sha256'])
        self.assertFalse(self.report['network_ready'])

    def test_two_policy_reads_control_independent_branches(self):
        self.assertEqual(len(self.report['cases']),32)
        for c in self.report['cases']:
            actions=[e['action'] for e in c['events']]
            values=[e['value'] for e in c['events'] if e['action']=='policy_virtual_capture']
            self.assertEqual(values,[c['first'],c['second']])
            self.assertEqual(actions.count('service_virtual98_capture'),int(c['first']==2))
            self.assertEqual(actions.count('owner_virtual_a00_capture'),int(c['first']==2))
            sends=[e for e in c['events'] if e['action']=='send_capture']
            self.assertEqual(len(sends),int(c['second']==1))
            if sends:self.assertEqual(sends[0]['vtable'],0x1498d84d8)
            self.assertEqual(c['flags'],[1,1]);self.assertEqual(c['field260'],1)

    def test_direct_call_scan_has_validated_candidate(self):
        p=self.tool.native.ROOT/'code-clues/selection-service-callers.json'
        self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(),self.report['scan_sha256'])
        scan=json.loads(p.read_text('utf-8'))
        matches=[c for c in scan['callers'] if c['address']==0x1468f1e48]
        self.assertEqual(len(matches),1)
        self.assertEqual(matches[0]['root'],self.tool.CALLER)
        self.assertEqual(len(scan['callers']),505)
        self.assertEqual(len(scan['unresolved']),16)
        self.assertEqual(len(scan['failures']),9)


if __name__=='__main__':unittest.main()
