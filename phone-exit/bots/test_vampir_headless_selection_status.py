"""Source-bound status transition following ID110, with diagnostic boundaries."""
import importlib.util
import json
from pathlib import Path
import unittest

HERE=Path(__file__).parent


class SelectionStatusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=HERE/'resource-tools/vampir/replay-selection-status.py'
        spec=importlib.util.spec_from_file_location('selection_status_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/selection-status-replay.json').read_text('utf-8'))

    def test_native_execution_reproduces(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertEqual(len(self.report['cases']),64)
        self.assertFalse(self.report['network_ready'])

    def test_status_byte_written_before_diagnostic_sink(self):
        for case in self.report['cases']:
            value=case['argument'] & 255
            self.assertEqual(case['status'],value)
            events=case['events']
            self.assertEqual(events[0]['action'],'native_status_set')
            self.assertEqual(events[0]['old'],case['old'])
            self.assertEqual(events[0]['value'],value)
            sinks=[e for e in events if e['action']=='text_sink_capture']
            self.assertEqual(len(sinks),1)
            self.assertEqual(sinks[0]['status'],value)
            self.assertEqual(events[-1]['action'],'security_cookie_capture')

    def test_whole_response_acceptance_controls_status_write(self):
        for case in self.report['pipeline']:
            accepted=case['fixture']['code'] in (0,0x1197)
            self.assertEqual(case['state']['status30'],int(accepted))
            setters=[e for e in case['events'] if e['action']=='native_status_set']
            self.assertEqual(len(setters),int(accepted))
            self.assertFalse(any(e['action']=='selection_event_capture' for e in case['events']))
            if accepted:
                self.assertEqual(setters[0]['value'],1)
                self.assertEqual(case['state']['vector_hex'],case['decoded']['vector188_hex'])


if __name__=='__main__':unittest.main()
