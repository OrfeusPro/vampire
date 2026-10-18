"""Native drain evidence, portable partial writes and actual loopback TCP."""
import hashlib,importlib.util,json,os,socket,sys,unittest
from pathlib import Path

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.outbound import OutboundFrames
from vampir_core.ping import PingPayload
from vampir_core.key_change import KeyChangePayload
from vampir_core.socket_send import drain_outbound


def queue():
    state=OutboundFrames(key_bits=7,sequence=0,max_queued_bytes=100,max_queued_frames=4)
    frames=[state.acknowledge_key_change(KeyChangePayload(12345)),state.queue_ping(PingPayload(1,2))]
    return state,b''.join(frames)


class SocketPumpTests(unittest.TestCase):
    def test_partial_block_resume_preserves_bytes_and_budgets(self):
        state,expected=queue()
        class FakeSocket:
            def __init__(self):self.actions=[1,3,BlockingIOError(),2,100,100];self.output=bytearray()
            def send(self,pending):
                action=self.actions.pop(0)
                if isinstance(action,Exception):raise action
                count=min(action,len(pending));self.output.extend(pending[:count]);return count
        sock=FakeSocket();result=drain_outbound(sock,state,max_send_calls=4)
        self.assertEqual((result.bytes_sent,result.blocked),(4,True))
        self.assertEqual(state.queued_bytes,len(expected)-4)
        self.assertTrue(state.peek_frame().readonly)
        drain_outbound(sock,state,max_send_calls=4)
        self.assertEqual(bytes(sock.output),expected)
        self.assertEqual((state.queued_bytes,state.queued_frames),(0,0))

    def test_zero_fatal_and_work_budget_do_not_drop_tail(self):
        for action in [0,ConnectionResetError(),InterruptedError()]:
            state,expected=queue()
            class FakeSocket:
                def send(self,pending):
                    if isinstance(action,Exception):raise action
                    return action
            if isinstance(action,InterruptedError):self.assertTrue(drain_outbound(FakeSocket(),state,max_send_calls=1).blocked)
            else:
                with self.assertRaises(ConnectionError):drain_outbound(FakeSocket(),state,max_send_calls=1)
            self.assertEqual(state.queued_bytes,len(expected))
        state,_=queue()
        class OneByteSocket:
            def send(self,pending):return 1
        self.assertEqual(drain_outbound(OneByteSocket(),state,max_send_calls=2).bytes_sent,2)
        self.assertEqual(state.queued_bytes,44)
        state.consume_sent(0)
        with self.assertRaises(ValueError):state.consume_sent(100)
        self.assertEqual(len(state.pop_frame()),17)
        self.assertEqual(state.queued_bytes,27)
        self.assertEqual(len(state.pop_frame()),27)
        self.assertEqual(state.queued_bytes,0)

    def test_actual_ipv4_loopback_tcp_bytes(self):
        state,expected=queue()
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as server:
            server.bind(('127.0.0.1',0));server.listen(1);server.settimeout(2)
            with socket.create_connection(server.getsockname(),timeout=2) as client:
                with server.accept()[0] as peer:
                    peer.settimeout(2);client.setblocking(False)
                    progress=drain_outbound(client,state,max_send_calls=8)
                    self.assertEqual(progress.bytes_sent,len(expected))
                    received=bytearray()
                    while len(received)<len(expected):
                        data=peer.recv(len(expected)-len(received))
                        self.assertTrue(data);received.extend(data)
                    self.assertEqual(bytes(received),expected)
                    self.assertEqual(state.queued_bytes,0)


class NativeDrainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root=Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES','F:/PhoneExit Resources/Vampir'))
        path=root/'code-clues/headless-send-drain.json'
        if not path.exists():raise unittest.SkipTest('Generate native drain evidence first')
        cls.report=json.loads(path.read_text('utf-8'));cls.raw=Path(cls.report['source']).read_bytes()

    def test_source_import_export_and_wake_link(self):
        r=self.report;self.assertFalse(r['network_ready'])
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(),r['sha256'])
        for f in r['fragments']:
            data=self.raw[f['file_offset']:f['file_offset']+f['end_rva']-f['begin_rva']]
            self.assertEqual(hashlib.sha256(data).hexdigest(),f['sha256'])
            self.assertEqual(data,b''.join(bytes.fromhex(i['bytes']) for i in f['instructions']))
        row=r['socket_import']
        for prefix in ['descriptor','thunk']:
            data=bytes.fromhex(row[prefix+'_bytes']);off=row[prefix+'_offset']
            self.assertEqual(self.raw[off:off+len(data)],data)
        export=r['local_export'];dll=Path(export['path']).read_bytes()
        self.assertEqual(hashlib.sha256(dll).hexdigest(),export['sha256'])
        for prefix in ['export_directory','ordinal_index','name']:
            data=bytes.fromhex(export[prefix+'_bytes']);off=export[prefix+'_offset']
            self.assertEqual(dll[off:off+len(data)],data)
        self.assertEqual(export['name'],'send')
        row=r['wake_table'];data=bytes.fromhex(row['bytes'])
        self.assertEqual(self.raw[row['file_offset']:row['file_offset']+len(data)],data)

    def test_native_partial_errors_and_replay(self):
        self.assertEqual(self.report['statistics']['native_drain_cases'],61)
        for row in self.report['cases']:
            payload=bytes.fromhex(row['payload_hex'])
            consumed=row['send_result'] if row['socket_present'] and row['send_result']>=0 else 0
            self.assertEqual(row['remaining_hex'],payload[consumed:].hex())
            self.assertEqual(row['close_requested'],bool(payload and row['send_result']<0 and row['error_code'] not in [22,23,37]))
        spec=importlib.util.spec_from_file_location('drain_replay',HERE/'resource-tools/vampir/build-headless-send-drain.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);emulator=module.DrainEmulator()
        for result,error in [(3,22),(-1,23),(-1,38),(0,22)]:
            row=emulator.execute_drain(b'abcdefgh',result,error)
            self.assertEqual(row['remaining_hex'],(b'abcdefgh'[max(0,result):]).hex())


if __name__=='__main__':unittest.main()
