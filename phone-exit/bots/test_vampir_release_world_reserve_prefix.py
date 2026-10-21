"""Portable prefix vs current native reader stopping at an explicit boundary."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

HERE=Path(__file__).parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.world_move_start import SOURCE_SHA256
from vampir_core.world_reserve_context import decode_world_reserve_context


class ReleaseWorldReservePrefixTests(unittest.TestCase):
    def test_native_prefix_fields_and_all_truncations(self):
        run=subprocess.run([sys.executable,'-X','utf8',str((HERE/'resource-tools/vampir/replay-release-world-reserve-prefix.py').resolve())],
            cwd=HERE.parents[1],capture_output=True,text=True,encoding='utf-8',check=True,timeout=60)
        report=json.loads(Path(json.loads(run.stdout)['report']).read_text('utf-8'))
        self.assertEqual(report['source_sha256'],SOURCE_SHA256)
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']),80)
        for case in report['cases']:
            body=bytes.fromhex(case['body_hex'])
            self.assertEqual(case['consumed'],len(body))
            if not case['reached_opaque_boundary']:
                with self.assertRaises(ValueError):
                    decode_world_reserve_context(body,max_payload_size=4096,source_sha256=SOURCE_SHA256)
            else:
                value=decode_world_reserve_context(body,max_payload_size=4096,source_sha256=SOURCE_SHA256)
                self.assertEqual([value.result_code,value.raw14,value.raw20,value.raw28,value.flag2c,value.raw2d],case['fields'])


if __name__=='__main__':unittest.main()
