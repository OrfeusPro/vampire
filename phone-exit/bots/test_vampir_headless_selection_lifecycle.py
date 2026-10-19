"""Source-bound lifecycle stores, broadcast arguments and callback tail jump."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

HERE=Path(__file__).resolve().parent


class SelectionLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location('lifecycle_test',HERE/'resource-tools/vampir/replay-selection-lifecycle.py')
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/selection-lifecycle-replay.json').read_text('utf-8'))

    def test_reproducible_native_source(self):
        self.assertEqual(self.tool.build(),self.report)
        raw=Path(self.report['source']).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),self.report['sha256'])
        for f in self.report['fragments']:
            data=raw[f['file_offset']:f['file_offset']+f['end_rva']-f['begin_rva']]
            self.assertEqual(hashlib.sha256(data).hexdigest(),f['sha256'])
        leaf=self.report['leaf'];off=leaf['file_offset']
        self.assertEqual(raw[off:off+16].hex(),leaf['bytes'])
        self.assertFalse(self.report['network_ready'])

    def test_state_and_broadcast_arguments(self):
        self.assertEqual([c['raw'] for c in self.report['events']],[0,1,2,18,0x7fffffff,0x80000000,0xffffffff])
        for c in self.report['events']:
            self.assertEqual(c['state40'],c['raw'])
            self.assertEqual(c['events'],[
                dict(action='state_dispatch_capture',this_is_service=True,raw=c['raw']),
                dict(action='delegate_broadcast_capture',this_offset=8,descriptor=0x141423088,raw=c['raw'])])

    def test_callback_uses_singleton_slot38(self):
        self.assertEqual(self.report['callback_global'],0x14b574a90)
        self.assertEqual(self.report['callback']['events'],[
            dict(action='virtual38_capture',this_is_service=True,raw=0)])


if __name__=='__main__':unittest.main()
