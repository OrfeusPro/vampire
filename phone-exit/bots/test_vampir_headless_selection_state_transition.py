"""Native state2 preparation, SDK gate, schedule boundary and deferred paths."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

HERE=Path(__file__).resolve().parent


class SelectionStateTransitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=HERE/'resource-tools/vampir/replay-selection-state-transition.py'
        spec=importlib.util.spec_from_file_location('state_transition_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/selection-state-transition-replay.json').read_text('utf-8'))

    def test_native_report_source_and_calls_reproduce(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertFalse(self.report['network_ready'])
        raw=Path(self.report['source']).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),self.report['sha256'])
        for f in self.report['fragments']:
            data=raw[f['file_offset']:f['file_offset']+f['end_rva']-f['begin_rva']]
            self.assertEqual(hashlib.sha256(data).hexdigest(),f['sha256'])
        rows={r['address']:r for f in self.report['fragments'] for r in f['instructions']}
        self.assertTrue(any(r.get('direct_target')==0x144a720c0 for r in rows.values()))
        self.assertTrue(any(r.get('direct_target')==0x144328fe0 for r in rows.values()))

    def test_state_write_pending_and_sdk_guards(self):
        self.assertEqual(len(self.report['cases']),10)
        for c in self.report['cases']:
            f=c['fixture']
            gated=f['sdk_enabled'] and f['manager_present'] and f['auth_present']
            rejected=gated and (not f['module_present'] or not f['auth_ready'])
            ready=f['ready_object'] and bool(f['ready'])
            self.assertEqual(c['queued'],not rejected and ready)
            self.assertEqual(c['state'],[2,0] if c['queued'] else [7,9])
            self.assertEqual(c['pending'],int(not rejected and not ready))
            schedules=[e for e in c['events'] if e['action']=='schedule_capture']
            self.assertEqual(schedules,[dict(action='schedule_capture',callback=0x145600690)] if c['queued'] else [])
            self.assertFalse(any(e['action']=='send_capture' for e in c['events']))
            if rejected:
                self.assertFalse(any(e['action']=='pre_state_helper_capture' for e in c['events']))
            else:
                self.assertIn(dict(action='state_lookup_capture',raw=2),c['events'])

    def test_deferred_callback_controls_and_writes(self):
        self.assertEqual(len(self.report['callbacks']),12)
        for c in self.report['callbacks']:
            f=c['fixture'];allowed=not f['player_present'] or f['player_ready']
            load=allowed and f['phase']<2 and not f['busy']
            self.assertEqual(c['returned'],int(allowed))
            self.assertEqual(c['flag731'],2 if allowed else 127)
            self.assertEqual(c['field718'],0 if load and not f['player_present'] else 0xabcdef)
            copies=[e for e in c['events'] if e['action']=='load_label_copy_fixture']
            self.assertEqual(copies,[dict(action='load_label_copy_fixture',text='callback-label-fixture')] if load else [])
            loads=[e for e in c['events'] if e['action']=='player_load_virtual_capture']
            self.assertEqual(loads,[dict(action='player_load_virtual_capture',text='callback-label-fixture',raw=0)] if load and f['player_present'] else [])
            self.assertFalse(any(e['action']=='send_capture' for e in c['events']))


if __name__=='__main__':unittest.main()
