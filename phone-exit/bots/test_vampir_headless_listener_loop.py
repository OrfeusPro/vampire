"""Native receive loop, opaque receive-A extraction and cross-stage boundaries."""
import hashlib
import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.receive_frame import take_receive_a_frame


class ReceiveAExtractionTests(unittest.TestCase):
    def test_partial_limit_and_no_mutation(self):
        from vampir_core.frame_primitives import xor_transform
        frame=b'\x08\0\0'+xor_transform(b'hello')
        for cut in range(8):self.assertIsNone(take_receive_a_frame(frame[:cut],max_frame_size=128))
        original=bytearray(frame+frame)
        self.assertEqual(take_receive_a_frame(original,max_frame_size=128),(b'\x08\0\0hello',8))
        self.assertEqual(original,bytearray(frame+frame))
        with self.assertRaises(ValueError):take_receive_a_frame(frame,max_frame_size=7)
        with self.assertRaises(ValueError):take_receive_a_frame(b'\x04\0\0ab',max_frame_size=128)


class NativeListenerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root=Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES','F:/PhoneExit Resources/Vampir'))
        path=root/'code-clues/headless-listener-loop.json'
        if not path.exists():raise unittest.SkipTest('Generate listener evidence first')
        cls.report=json.loads(path.read_text('utf-8'))
        cls.raw=Path(cls.report['source']).read_bytes()

    def test_provenance(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(),self.report['sha256'])
        self.assertFalse(self.report['network_ready'])
        for f in self.report['fragments']:
            data=self.raw[f['file_offset']:f['file_offset']+f['end_rva']-f['begin_rva']]
            self.assertEqual(hashlib.sha256(data).hexdigest(),f['sha256'])
            self.assertEqual(data,b''.join(bytes.fromhex(i['bytes']) for i in f['instructions']))
        for leaf in self.report['leaves']:
            data=bytes.fromhex(leaf['bytes'])
            self.assertEqual(self.raw[leaf['file_offset']:leaf['file_offset']+len(data)],data)
            self.assertEqual(hashlib.sha256(data).hexdigest(),leaf['sha256'])
        row=self.report['receive_table'];data=bytes.fromhex(row['bytes'])
        self.assertEqual(self.raw[row['file_offset']:row['file_offset']+len(data)],data)

    def test_all_vectors_match_shared_extraction(self):
        self.assertEqual(self.report['statistics']['native_listener_cases'],44)
        for case in self.report['cases']:
            pending=bytes.fromhex(case['stream_hex']);delivered=[]
            if case['mode']=='live':
                while True:
                    result=take_receive_a_frame(pending,max_frame_size=2048)
                    if result is None:break
                    output,count=result;delivered.append(output.hex());pending=pending[count:]
            self.assertEqual(delivered,case['delivered'])
            self.assertEqual(pending.hex(),case['remaining_hex'])
            if case['mode']=='expired':self.assertEqual(case['expired_cleanups'],1)

    def emulator(self):
        path=HERE/'resource-tools/vampir/build-headless-listener-loop.py'
        spec=importlib.util.spec_from_file_location('listener_replay',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module,module.ListenerEmulator()

    def test_native_replay_continuation_and_lifecycle(self):
        module,emulator=self.emulator();frame=module.wire_frame(bytes(range(16)))
        first=emulator.execute_listener(frame[:7])
        self.assertEqual(first['delivered'],[])
        second=emulator.execute_listener(bytes.fromhex(first['remaining_hex'])+frame[7:]+frame)
        self.assertEqual(len(second['delivered']),2)
        self.assertEqual(second['remaining_hex'],'')
        for mode in ['none','expired']:
            result=emulator.execute_listener(frame,mode)
            self.assertEqual(result['remaining_hex'],frame.hex())
            self.assertEqual(result['delivered'],[])

    def test_compressed_transport_split_inside_internal_frame(self):
        module,emulator=self.emulator();frame=module.wire_frame(bytes(range(64)))
        pending=b'';delivered=[]
        # Outer block boundaries deliberately split an inner header and payload.
        for part in [frame[:2],frame[2:11],frame[11:]+frame]:
            block=module.blocks.stage.literal_block(part)
            raw=(0x800000+len(block)+3).to_bytes(3,'little')+block
            stage=emulator.execute_stage(raw)
            self.assertEqual(stage['remaining_hex'],'')
            result=emulator.execute_listener(pending+bytes.fromhex(stage['output_hex']))
            pending=bytes.fromhex(result['remaining_hex']);delivered.extend(result['delivered'])
        self.assertEqual(pending,b'')
        self.assertEqual(delivered,[(frame[:3]+bytes(range(64))).hex()]*2)


if __name__=='__main__':unittest.main()
