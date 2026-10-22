"""Bounded tutorial parser and parity with current whole native reader; no network."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import unittest

HERE=Path(__file__).parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.tutorial_update import decode_tutorial_update
from vampir_core.world_move_start import SOURCE_SHA256


class TutorialUpdateTests(unittest.TestCase):
    def decode(self,body,**kw):
        options=dict(source_sha256=SOURCE_SHA256,max_records=8,max_payload_size=1024)
        options.update(kw)
        return decode_tutorial_update(body,**options)

    def test_exact_lengths_budgets_and_source(self):
        body=struct.pack('<BHIIIB',1,1,1001,2,1001002,1)
        for size in range(len(body)):
            with self.assertRaises(ValueError):self.decode(body[:size])
        with self.assertRaises(ValueError):self.decode(body+b'\0')
        with self.assertRaises(BufferError):self.decode(body,max_records=0)
        with self.assertRaises(BufferError):self.decode(body,max_payload_size=3)
        with self.assertRaises(ValueError):self.decode(body,source_sha256='old')

    def test_flag_clamp_and_raw_fields_without_semantic_guess(self):
        result=self.decode(struct.pack('<BH',255,2)+struct.pack('<IIIB',0xffffffff,0,1001002,255)*2)
        self.assertTrue(result.flag);self.assertEqual(len(result.records),2)
        self.assertEqual(result.records[0].raw08,0xffffffff)
        self.assertEqual(result.records[0].raw10,1001002)
        self.assertEqual(result.records[0].state,3)
        self.assertNotIn('1001002',repr(result))

    def test_whole_native_reader(self):
        run=subprocess.run([sys.executable,'-X','utf8',str(HERE/'resource-tools/vampir/replay-release-tutorial-update.py')],
            capture_output=True,text=True,encoding='utf-8',check=True,timeout=120)
        report=json.loads(Path(json.loads(run.stdout)['report']).read_text('utf-8'))
        self.assertEqual(report['source_sha256'],SOURCE_SHA256)
        self.assertTrue(report['native_execution']);self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']),72)
        self.assertEqual([r['size'] for r in report['short']],list(range(29)))


if __name__=='__main__':unittest.main()
