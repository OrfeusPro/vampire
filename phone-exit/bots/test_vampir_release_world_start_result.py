"""Current whole native ID204 reader vs portable decoder; no network IO."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import unittest

HERE=Path(__file__).parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.world_move_start import SOURCE_SHA256
from vampir_core.world_move_start_result import decode_world_move_start_result


class ReleaseWorldStartResultTests(unittest.TestCase):
    def test_current_native_result_fields_vectors_and_all_short_inputs(self):
        tool=(HERE/'resource-tools/vampir/replay-release-world-start-result.py').resolve()
        run=subprocess.run([sys.executable,'-X','utf8',str(tool)],cwd=HERE.parents[1],
            capture_output=True,text=True,encoding='utf-8',check=True,timeout=60)
        report=json.loads(Path(json.loads(run.stdout)['report']).read_text('utf-8'))
        self.assertEqual(report['source_sha256'],SOURCE_SHA256)
        self.assertEqual(report['packet_id'],204)
        self.assertEqual(len(report['cases']),72)
        self.assertEqual(len(report['short']),30)
        for case in report['cases']:
            body=bytes.fromhex(case['body_hex'])
            value=decode_world_move_start_result(body,max_payload_size=64)
            self.assertEqual([value.result_code,*(value.data.at(o) for o in (0x14,0x30,0x31,0x38))],case['fields'])
            self.assertEqual(struct.pack('<ddd',*value.data.at(0x18).finite_values()).hex(),case['vector_hex'])
        for case in report['short']:
            with self.assertRaises(ValueError):
                decode_world_move_start_result(body[:case['size']],max_payload_size=64)


if __name__=='__main__':unittest.main()
