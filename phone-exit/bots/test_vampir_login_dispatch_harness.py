"""Pure dispatch admission, protected-memory and framing regressions."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent/'resource-tools/vampir'
def load(name):
    s=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
harness=load('verify-login-dispatch-harness');runtime=load('verify-login-dispatch-context')


class FakeMemory:
    def __init__(self):self.writes=[]
    def mem_write(self,at,value):self.writes.append((at,bytes(value)))
    def mem_read(self,at,size):return bytes(size)


class DispatchHarnessTests(unittest.TestCase):
    def test_short_header_and_unbounded_frame_fail_before_any_native_entry(self):
        for length in (0,1,2,3,4,4097):
            with self.subTest(length=length),self.assertRaises(ValueError):runtime.check_frame(bytes(length))
        for length in (5,6,4096):self.assertEqual(runtime.check_frame(bytes(length)),bytes(length))
        for value in (None,bytearray(5),'abcde'):
            with self.assertRaises(ValueError):runtime.check_frame(value)

    def test_archive_release_preserves_packet_frame_and_decoded_string_protections(self):
        p=harness.MemoryPolicy(FakeMemory())
        p.protect([(0x1000,344),(0x2000,64),(0x3000,100),(0x4000,30)])
        runtime.release_exact(p,0x2000,64)
        self.assertNotIn((0x2000,0x2040),p.readonly)
        for at in (0x1000,0x1100,0x3001,0x4004):
            with self.assertRaises(ValueError):p.mem_write(at,b'\0')
        p.mem_write(0x2000,b'\0')
        self.assertEqual(len(p.native.writes),1)

    def test_release_does_not_silently_shorten_an_overlapping_range(self):
        p=harness.MemoryPolicy(FakeMemory());p.protect([(0x2000,96)])
        runtime.release_exact(p,0x2000,64)
        with self.assertRaises(ValueError):p.mem_write(0x2000,b'\0')

    def test_node_storage_and_both_canaries_never_overlap(self):
        boxes=runtime.node_layout(0x9000,9)
        self.assertEqual(len(boxes),9)
        for i,(at,size) in enumerate(boxes):
            self.assertEqual(size,40)
            for other,length in boxes[:i]:self.assertFalse(at-16<other+length+16 and at+size+16>other-16)
        for count in (-1,10,True):
            with self.assertRaises(ValueError):runtime.node_layout(0,count)

    def test_tls_provider_replaces_both_slots_and_keeps_unselected_index_null(self):
        for index in (0,1):
            values=runtime.tls_vector_values(index,0x50000000)
            self.assertEqual(values[index],0x50000000)
            self.assertEqual(values[1-index],0)
            self.assertEqual(sum(bool(value) for value in values),1)
        for index in (True,-1,2):
            with self.assertRaises(ValueError):runtime.tls_vector_values(index,0x50000000)

    def test_native_and_fixture_writes_cannot_reseed_registered_payload(self):
        p=harness.MemoryPolicy(FakeMemory());p.protect([(100,344)]);p.native_allow([(0,1000)])
        for native in (False,True):
            with self.assertRaises(ValueError):p.writable(104,4,native=native)
        p.begin_fixture([(0,1000)])
        with self.assertRaises(ValueError):p.mem_write(104,b'\0'*4)
        p.end_fixture()
        self.assertFalse(p.native.writes)

    def test_native_write_outside_current_phase_window_is_rejected(self):
        p=harness.MemoryPolicy(FakeMemory());p.native_allow([(100,8),(200,64)])
        p.writable(100,8,native=True)
        for at,size in ((99,1),(100,9),(263,2),(300,4)):
            with self.assertRaises(ValueError):p.writable(at,size,native=True)

    def test_fixture_scope_does_not_borrow_native_window_or_another_fixture(self):
        p=harness.MemoryPolicy(FakeMemory());p.native_allow([(0,1000)]);p.begin_fixture([(200,8)])
        p.mem_write(200,b'12345678')
        with self.assertRaises(ValueError):p.mem_write(208,b'0')
        with self.assertRaises(ValueError):p.begin_fixture([(0,1000)])
        p.end_fixture()
        with self.assertRaises(ValueError):p.end_fixture()

    def test_retired_name_is_unreadable_and_unwritable(self):
        p=harness.MemoryPolicy(FakeMemory());p.retire(100,30)
        for at,size in ((100,1),(110,10),(129,2)):
            with self.assertRaises(ValueError):p.readable(at,size)
            with self.assertRaises(ValueError):p.writable(at,size)
        p.readable(130,1)

    def test_zero_size_operations_remain_noops_inside_protected_and_retired_regions(self):
        p=harness.MemoryPolicy(FakeMemory());p.protect([(100,8)]);p.retire(200,8)
        for at in (100,104,200,204):p.readable(at,0);p.writable(at,0,native=True)
        with self.assertRaises(ValueError):p.readable(104,-1)

    def test_reference_seed_cannot_admit_native_execution(self):
        c=json.loads((HERE/'knowledge/native-contexts/login-dispatch-11322.json').read_text('utf-8'))
        functions={int(at,16) for at in c['functions'].values()};leaves={int(at,16):value for at,value in c['leaves'].items()}
        self.assertEqual((len(functions),len(leaves)),(29,12))
        with patch.object(harness,'load',side_effect=AssertionError('must fail before index')):
            with self.assertRaises(ValueError):harness.admit(c,Path('.'),functions,leaves,c['exports'])

    def test_missing_proof_alias_leaf_root_or_override_is_rejected_before_index(self):
        c=json.loads((HERE/'knowledge/native-contexts/login-dispatch-11322.json').read_text('utf-8'))
        c.update(format='login-dispatch-v1',transfer_proof={'path':'stub','sha256':'a'*64})
        functions={int(at,16) for at in c['functions'].values()};leaves={int(at,16):value for at,value in c['leaves'].items()}
        with patch.object(harness,'load',side_effect=AssertionError('must fail before index')):
            with self.assertRaises(ValueError):harness.admit(c,Path('.'),set(list(functions)[:-1]),leaves,c['exports'])
            c['function_budget']=29
            with self.assertRaises(ValueError):harness.admit(c,Path('.'),functions,leaves,c['exports'])


if __name__=='__main__':unittest.main()
