"""Current incoming movement codec against whole native readers; no game IO."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import unittest

HERE = Path(__file__).parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.character_move_event import decode_move_notify, decode_move_result
from vampir_core.world_move_start import SOURCE_SHA256


class CharacterMoveEventTests(unittest.TestCase):
    def test_exact_length_and_source_required(self):
        for decoder,size in ((decode_move_notify,16),(decode_move_result,4)):
            for length in (*range(size),size+1):
                with self.assertRaises(ValueError):decoder(bytes(length),source_sha256=SOURCE_SHA256)
            with self.assertRaises(ValueError):decoder(bytes(size),source_sha256='old')

    def test_raw_coordinate_bits_survive_until_consumer(self):
        event=decode_move_notify(struct.pack('<QII',2**64-1,0x80000000,0x7fc12345),source_sha256=SOURCE_SHA256)
        self.assertEqual(event.entity_key,2**64-1)
        self.assertEqual(event.xy_bits,(0x80000000,0x7fc12345))
        with self.assertRaises(ValueError):event.finite_xy()
        event=decode_move_notify(struct.pack('<Qff',42,-0.0,123.5),source_sha256=SOURCE_SHA256)
        self.assertEqual(struct.pack('<ff',*event.finite_xy()),struct.pack('<ff',-0.0,123.5))

    def test_native_parity_and_short_reads(self):
        run=subprocess.run([sys.executable,'-X','utf8',str(HERE/'resource-tools/vampir/replay-release-character-move.py')],
            capture_output=True,text=True,encoding='utf-8',check=True,timeout=120)
        report=json.loads(Path(json.loads(run.stdout)['report']).read_text('utf-8'))
        self.assertEqual(report['source_sha256'],SOURCE_SHA256)
        self.assertTrue(report['native_execution']);self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']),28)
        for packet_id,size in ((306,4),(307,16)):
            rows=[r for r in report['short'] if r['packet_id']==packet_id]
            self.assertEqual([r['length'] for r in rows],list(range(size)))
            self.assertTrue(all(r['consumed']<=r['length'] for r in rows))


if __name__=='__main__':unittest.main()
