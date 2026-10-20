"""Native engine function delegates to source-bound owner tables."""
import importlib.util
import json
from pathlib import Path
import unittest

HERE=Path(__file__).parent


class WorldOwnerDispatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=HERE/'resource-tools/vampir/replay-world-owner-dispatch.py'
        spec=importlib.util.spec_from_file_location('engine_dispatch_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/world-owner-dispatch-replay.json').read_text('utf-8'))

    def test_native_engine_function_reproduces(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertEqual(len(self.report['cases']),45)
        self.assertFalse(self.report['network_ready'])

    def test_field_receiver_and_real_owner_dispatch_respect_status(self):
        for case in self.report['cases']:
            events=case['events'];self.assertEqual(events[0]['action'],'native_engine_dispatch')
            self.assertIn((case['constructor'],case['table']),self.tool.base.OWNERS)
            calls=[e for e in events if e['action']=='engine_owner_receiver']
            self.assertEqual(len(calls),int(case['owner_present']))
            sends=[e for e in events if e['action']=='finish_packet_capture']
            accepted=case['owner_present'] and case['status'] in (2,3,4)
            self.assertEqual(len(sends),int(accepted))
            self.assertEqual(case['state']['status30'],5 if accepted else case['status'])
            self.assertEqual(case['state']['owner_handle'],0x12345678 if case['owner_present'] else 0)
            self.assertIn(dict(action='engine_iteration_capture',callback=0x143963850),events)

    def test_secondary_slot_requires_primary_and_flag_cache_is_bounded(self):
        for case in self.report['cases']:
            secondary=[e for e in case['events'] if e['action']=='secondary_virtual_capture']
            self.assertEqual(len(secondary),int(case['owner_present'] and case['secondary']))
            if not case['cached']:
                self.assertEqual(case['state']['cached_d9'],int(case['world_kind'] in (1,3,5,6)))
                probes=[e for e in case['events'] if e['action']=='engine_cached_flag_capture']
                self.assertEqual(len(probes),2 if case['world_kind'] in (1,3,5,6) else 0)


if __name__=='__main__':unittest.main()
