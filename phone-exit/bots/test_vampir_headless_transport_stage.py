"""Native first receive-stage evidence and shared size23/compression flag parser."""
import hashlib
import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.transport_header import inspect_transport_header,take_uncompressed_transport_frame


class SharedTransportHeaderTests(unittest.TestCase):
    def test_flag_is_not_part_of_size(self):
        header=inspect_transport_header(bytes.fromhex('110080'),max_frame_size=256)
        self.assertEqual(header.total_size,17)
        self.assertTrue(header.compressed)
        self.assertIsNone(take_uncompressed_transport_frame(bytes.fromhex('110080'),max_frame_size=256))
        with self.assertRaises(NotImplementedError):
            take_uncompressed_transport_frame(bytes.fromhex('110080')+bytes(14),max_frame_size=256)

    def test_boundaries_and_fragment_coalescence(self):
        raw=b'\x08\0\0hello'
        for length in range(8):self.assertIsNone(take_uncompressed_transport_frame(raw[:length],max_frame_size=256))
        self.assertEqual(take_uncompressed_transport_frame(raw+raw,max_frame_size=256),(b'hello',8))
        for size in range(3):
            with self.assertRaises(ValueError):inspect_transport_header(size.to_bytes(3,'little'),max_frame_size=256)
        for limit in [2,0x800000,False,1.0]:
            with self.assertRaises(ValueError):inspect_transport_header(b'',max_frame_size=limit)
        with self.assertRaises(ValueError):inspect_transport_header(b'\xff\xff\x7f',max_frame_size=256)


class NativeTransportStageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root=Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES','F:/PhoneExit Resources/Vampir'))
        path=root/'code-clues/headless-transport-stage.json'
        if not path.exists():raise unittest.SkipTest('Generate native transport stage evidence first')
        cls.report=json.loads(path.read_text('utf-8'))
        cls.raw=Path(cls.report['source']).read_bytes()

    def test_original_code_and_scope(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(),self.report['sha256'])
        self.assertFalse(self.report['network_ready'])
        for f in self.report['fragments']:
            content=self.raw[f['file_offset']:f['file_offset']+f['end_rva']-f['begin_rva']]
            self.assertEqual(hashlib.sha256(content).hexdigest(),f['sha256'])
            self.assertEqual(b''.join(bytes.fromhex(i['bytes']) for i in f['instructions']),content)
        self.assertEqual([i['name'] for i in self.report['memory_imports']],['memmove','memset'])

    def test_native_single_frame_matches_shared_uncompressed_extraction(self):
        self.assertEqual(len(self.report['cases']),62)
        compressed_complete=0
        for case in self.report['cases']:
            stream=bytes.fromhex(case['stream_hex'])
            if len(stream)<3:
                self.assertEqual(case['remaining_hex'],stream.hex())
                continue
            header=inspect_transport_header(stream,max_frame_size=4096)
            if header.compressed:
                if len(stream)>=header.total_size:
                    compressed_complete+=1
                    self.assertGreater(case['decompress_calls'],0)
                continue
            if case['skip']==3 and not case['existing_hex'] and len(stream)<=header.total_size:
                parsed=take_uncompressed_transport_frame(stream,max_frame_size=4096)
                if parsed is None:
                    self.assertEqual(case['output_hex'],'')
                else:
                    self.assertEqual(parsed[0].hex(),case['output_hex'])
                    self.assertEqual(case['remaining_hex'],'')
        self.assertGreater(compressed_complete,0)

    def test_native_replay_mixed_and_fragmented_frames(self):
        path=HERE/'resource-tools/vampir/build-headless-transport-stage.py'
        spec=importlib.util.spec_from_file_location('stage_replay',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        emulator=module.TransportStageEmulator()
        raw=b'\x08\0\0hello'
        self.assertEqual(emulator.execute_stage(raw[:-1])['output_hex'],'')
        self.assertEqual(emulator.execute_stage(raw)['output_hex'],b'hello'.hex())
        body=module.literal_block(b'world')
        compressed=(0x800000+len(body)+3).to_bytes(3,'little')+body
        case=emulator.execute_stage(raw+compressed+b'\x01',existing=b'prefix:')
        self.assertEqual(case['output_hex'],b'prefix:helloworld'.hex())
        self.assertEqual(case['remaining_hex'],'01')
        self.assertEqual(case['decompress_calls'],1)


if __name__=='__main__':unittest.main()
