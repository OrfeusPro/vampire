import sys
from pathlib import Path
import unittest
import importlib.util
import json
import hashlib
import base64
from tempfile import TemporaryDirectory
sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.login_packet import LoginPayload, decode_login_payload
from vampir_core.send_frame import encode_login_frame_b


class LoginDecodeTests(unittest.TestCase):
    def test_all_fields_unicode_and_raw_bytes_roundtrip(self):
        value=LoginPayload(tuple('поле🙂'+str(i) for i in range(15)),
            (0,256,0xffffffff,1),(3,3,7,255,128),0xfedcba9876543210)
        body=value.encode(max_payload_size=4096)
        self.assertEqual(decode_login_payload(body,max_payload_size=4096),value)
        for end in range(len(body)):
            with self.assertRaises(ValueError):decode_login_payload(body[:end],max_payload_size=4096)
        with self.assertRaises(ValueError):decode_login_payload(body+b'x',max_payload_size=4096)
        with self.assertRaises(BufferError):decode_login_payload(body,max_payload_size=59)

    def test_invalid_utf8_and_empty_fields(self):
        value=LoginPayload(('',)*15,(0,0,0,0),(0,0,0,0,0),0)
        body=value.encode(max_payload_size=59)
        self.assertEqual(decode_login_payload(body,max_payload_size=59),value)
        with self.assertRaises(ValueError):decode_login_payload(b'\x01\x00\xff'+body[2:],max_payload_size=4096)

    def test_capture_report_redacts_values_and_checks_crc_and_sha(self):
        spec=importlib.util.spec_from_file_location('login_capture_inspect',Path(__file__).parent/'vampir-headless/inspect-captured-login.py')
        tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)
        texts=['private-fixture']*15
        texts[11]='{"I_PID":"secret-player-fixture","secret-key-fixture":"secret-value-fixture"}'
        login=LoginPayload(tuple(texts),(258392,256,207,1),(3,3,1,0,0),0)
        frame=encode_login_frame_b(login,0,0,max_payload_size=4096)
        with TemporaryDirectory() as root:
            path=Path(root)/'traffic.jsonl'
            def write(data):
                content=(json.dumps(dict(type='data',flow=6,direction='c2s',data=base64.b64encode(data).decode()))+'\n').encode()
                path.write_bytes(content)
                return hashlib.sha256(content).hexdigest()
            digest=write(frame)
            report=tool.inspect(path,flow=6,expected_sha256=digest)
            for secret in ('private-fixture','secret-player-fixture','secret-key-fixture','secret-value-fixture'):
                self.assertNotIn(secret,json.dumps(report))
            self.assertEqual(report['raw_bytes'],(3,3,1,0,0))
            with self.assertRaises(ValueError):tool.inspect(path,flow=6,expected_sha256='0'*64)
            damaged=bytearray(frame);damaged[-1]^=1
            digest=write(damaged)
            with self.assertRaises(ValueError):tool.inspect(path,flow=6,expected_sha256=digest)


if __name__=='__main__':unittest.main()
