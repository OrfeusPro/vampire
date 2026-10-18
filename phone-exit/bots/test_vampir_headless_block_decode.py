"""Native differential block vectors, corruption and bounded extraction tests."""
import hashlib
import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.block_decode import decode_transport_block
from vampir_core.transport_header import take_transport_frame


class SharedBlockTests(unittest.TestCase):
    def test_overlap_and_output_budget(self):
        block=b'\x1fA\x01\x00\x01\x50tail!'
        self.assertEqual(decode_transport_block(block,max_output_size=26),b'A'*21+b'tail!')
        for limit in [1,20,25,False,0,0x100001,1.5]:
            with self.assertRaises(ValueError):decode_transport_block(block,max_output_size=limit)

    def test_corrupt_lengths_offsets_and_tail(self):
        for block in [b'',b'\xf0',b'\xf0\xff',b'\x50abc',b'\x10a\0\0\x50tail!',
                      b'\x10a\x02\0\x50tail!',b'\x10a\x01',b'\x10a\x01\0',
                      b'\x10a\x01\0\x10z']:
            with self.subTest(block=block.hex()), self.assertRaises(ValueError):
                decode_transport_block(block,max_output_size=1024)

    def test_frame_fragments_coalescence_and_empty_result(self):
        block=b'\x1fA\x01\x00\x01\x50tail!'
        frame=(0x800000+3+len(block)).to_bytes(3,'little')+block
        for cut in range(len(frame)):
            self.assertIsNone(take_transport_frame(frame[:cut],max_frame_size=128,max_output_size=26))
        self.assertEqual(take_transport_frame(frame+b'extra',max_frame_size=128,max_output_size=26),
                         (b'A'*21+b'tail!',len(frame)))
        self.assertEqual(take_transport_frame(b'\x08\0\0hello',max_frame_size=128,max_output_size=5),
                         (b'hello',8))
        for raw,limit in [(frame,25),(b'\x08\0\0hello',4),(b'\x04\0\x80\0',26)]:
            with self.assertRaises(ValueError):
                take_transport_frame(raw,max_frame_size=128,max_output_size=limit)


class NativeBlockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root=Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES','F:/PhoneExit Resources/Vampir'))
        path=root/'code-clues/headless-block-decode.json'
        if not path.exists():raise unittest.SkipTest('Generate native block evidence first')
        cls.report=json.loads(path.read_text('utf-8'))
        cls.raw=Path(cls.report['source']).read_bytes()

    def test_source_fragments_tables_and_listener_thunks(self):
        r=self.report
        self.assertFalse(r['network_ready'])
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(),r['sha256'])
        for f in r['fragments']+r['listener_fragments']:
            content=self.raw[f['file_offset']:f['file_offset']+f['end_rva']-f['begin_rva']]
            self.assertEqual(hashlib.sha256(content).hexdigest(),f['sha256'])
            self.assertEqual(b''.join(bytes.fromhex(i['bytes']) for i in f['instructions']),content)
        for row in [r['copy_table']]+r['listener_thunks']:
            data=bytes.fromhex(row['bytes'])
            self.assertEqual(self.raw[row['file_offset']:row['file_offset']+len(data)],data)
        self.assertEqual(hashlib.sha256(bytes.fromhex(r['copy_table']['bytes'])).hexdigest(),r['copy_table']['sha256'])
        self.assertEqual([t['virtual_slot'] for t in r['listener_thunks']],[0x38,0x40])
        rows={i['address']:i for f in r['listener_fragments'] for i in f['instructions']}
        self.assertEqual(rows[0x1445ed723]['direct_target'],0x1415f6848)
        self.assertEqual(rows[0x1445ed65a]['rip_references'],[0x1437113e4])
        self.assertEqual(rows[0x1445ed677]['direct_target'],0x1445dede0)
        self.assertEqual(rows[0x1445def22]['operands'],'qword ptr [rsp + 0x98]')

    def test_all_native_vectors_and_invalid_inputs(self):
        self.assertEqual(self.report['statistics'],dict(native_valid_cases=166,native_invalid_cases=86))
        for row in self.report['cases']:
            output=decode_transport_block(bytes.fromhex(row['block_hex']),max_output_size=row['capacity'])
            self.assertEqual(output.hex(),row['output_hex'])
            self.assertEqual(len(output),row['result'])
        for row in self.report['invalid_cases']:
            self.assertLess(row['result'],0)
            with self.assertRaises(ValueError):
                decode_transport_block(bytes.fromhex(row['block_hex']),max_output_size=row['capacity'])

    def test_native_replay_and_transport_integration(self):
        path=HERE/'resource-tools/vampir/build-headless-block-decode.py'
        spec=importlib.util.spec_from_file_location('block_replay',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        emulator=module.BlockEmulator()
        for index in [0,1,20,60,100,165]:
            row=self.report['cases'][index];block=bytes.fromhex(row['block_hex'])
            result,output=emulator.decode(block,row['capacity'])
            self.assertEqual(result,row['result']);self.assertEqual(output.hex(),row['output_hex'])
            if output:
                raw=(0x800000+len(block)+3).to_bytes(3,'little')+block
                stage=emulator.execute_stage(raw)
                self.assertEqual(stage['output_hex'],row['output_hex'])
                self.assertEqual(stage['remaining_hex'],'')


if __name__=='__main__':unittest.main()
