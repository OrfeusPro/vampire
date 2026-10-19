"""Source-bound state getter caller scan and ID102 -> rawF0 propagation."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.character_list import decode_character_list,SOURCE_SHA256


def module(name,filename):
    spec=importlib.util.spec_from_file_location(name,HERE/'resource-tools/vampir'/filename)
    tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)
    return tool


class CharacterStateTests(unittest.TestCase):
    def test_getter_scan_reproduces_validated_calls_not_field_semantics(self):
        tool=module('state_scan_test','build-character-state-callers.py')
        report=json.loads((tool.scan.native.ROOT/'code-clues/character-state-callers.json').read_text('utf-8'))
        self.assertEqual(tool.build(),report)
        self.assertEqual(report['sha256'],SOURCE_SHA256)
        self.assertEqual((len(report['callers']),len(report['unresolved']),len(report['failures'])),(105,0,0))
        self.assertTrue(any(c['root']==0x145dc05f0 for c in report['field_f0_candidates']))
        for c in report['callers']:
            row=next(r for r in c['context'] if r['address']==c['address'])
            self.assertTrue(tool.scan.scan.checked_call(row,0x145c859f0))

    def test_native_state_report_reproduces(self):
        tool=module('f0_native_test','replay-character-state-f0.py')
        report=json.loads((tool.native.ROOT/'code-clues/character-state-f0-replay.json').read_text('utf-8'))
        self.assertEqual(tool.build(),report)
        self.assertEqual(report['sha256'],SOURCE_SHA256)
        self.assertEqual((len(report['cases']),len(report['setters'])),(45,12))
        self.assertFalse(report['network_ready'])
        for c in report['cases']:
            model=decode_character_list(bytes.fromhex(c['decoded']['payload_hex']),max_payload_size=4096,max_characters=4,max_extension_items=64)
            applied=any(e['action']=='selection_event_capture' for e in c['events'])
            self.assertEqual(c['state_raw_f0'],model.tail[3] if applied else 0)
            self.assertEqual(sum(e['action']=='native_setter_entry' for e in c['events']),int(applied))
        for c in report['setters']:
            self.assertEqual(c['actual'],c['new'])
            self.assertEqual(sum(e['action']=='persistence_capture' for e in c['events']),int(c['old']!=0 and c['old']!=c['new']))


if __name__=='__main__':unittest.main()
