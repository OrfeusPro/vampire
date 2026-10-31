"""Pure tooling checks for memory ownership and concrete native caller guards."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent/'resource-tools/vampir'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'),TOOLS/(name+'.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


class FakeMemory:
    def __init__(self): self.data = bytearray(1024)
    def mem_read(self, at, size): return bytes(self.data[at:at+size])
    def mem_write(self, at, data): self.data[at:at+len(data)] = data


class ContainerMemoryTests(unittest.TestCase):
    def setUp(self):
        self.module = load('verify-login-container-harness')
        self.memory = self.module.MemoryPolicy(FakeMemory())

    def test_native_write_requires_a_complete_mutable_window(self):
        self.memory.native_allow([(100,16)])
        self.memory.writable(100,16,native=True)
        for at,size in ((99,1),(115,2),(116,1)):
            with self.assertRaises(ValueError): self.memory.writable(at,size,native=True)

    def test_protected_input_rejects_even_same_byte_native_and_fixture_writes(self):
        self.memory.native_allow([(100,32)]); self.memory.protect([(108,8)])
        with self.assertRaises(ValueError): self.memory.writable(108,1,native=True)
        self.memory.begin_fixture([(100,32)])
        with self.assertRaises(ValueError): self.memory.mem_write(108,b'\0')
        self.memory.end_fixture()

    def test_reserve_fixture_may_write_data_and_capacity_but_never_native_count(self):
        self.memory.begin_fixture([(100,8),(112,4)])
        self.memory.mem_write(100,b'x'*8); self.memory.mem_write(112,b'y'*4)
        with self.assertRaises(ValueError): self.memory.mem_write(108,b'\0'*4)
        with self.assertRaises(ValueError): self.memory.mem_write(100,b'\0'*16)
        self.memory.end_fixture()

    def test_fixture_cannot_modify_native_owned_count_mask_or_node_payload(self):
        self.memory.begin_fixture([(124,24),(300,64)])
        for at in (116,148,160,216):
            with self.assertRaises(ValueError): self.memory.mem_write(at,b'\0')
        self.memory.end_fixture()

    def test_free_retires_memory_for_native_and_fixture_reads_and_writes(self):
        self.memory.native_allow([(100,32)]); self.memory.retire(108,8)
        for operation in (lambda:self.memory.mem_read(108,1),lambda:self.memory.mem_write(108,b'x'),
                lambda:self.memory.writable(108,1,native=True)):
            with self.assertRaises(ValueError): operation()
        self.assertEqual(self.memory.snapshot(108,1),b'\0')

    def test_fixture_scopes_do_not_nest_and_must_close(self):
        self.memory.begin_fixture()
        with self.assertRaises(ValueError): self.memory.begin_fixture()
        with self.assertRaises(ValueError): self.memory.mem_write(100,b'x')
        self.memory.end_fixture()
        with self.assertRaises(ValueError): self.memory.end_fixture()

    def test_new_case_reset_clears_previous_retirement_but_keeps_underlying_bytes(self):
        self.memory.mem_write(100,b'x'); self.memory.protect([(100,1)]); self.memory.retire(100,1)
        self.memory.reset(); self.assertEqual(self.memory.mem_read(100,1),b'x')
        with self.assertRaises(ValueError): self.memory.writable(100,1,native=True)

    def test_invalid_ranges_and_zero_length_noops(self):
        for ranges in ([(1,0)],[(-1,1)],[(1,True)],[(1.0,1)]):
            with self.assertRaises(ValueError): self.memory.protect(ranges)
        self.memory.protect([(100,8)]); self.memory.retire(100,8)
        self.memory.writable(100,0,native=True); self.memory.readable(100,0)


class ContainerCallerTests(unittest.TestCase):
    def setUp(self):
        self.tool = load('verify-login-container-context')
        self.functions = dict(register='0x1000',ctor='0x2000')
        self.calls = dict(register={'0x1010':'qword ptr [rax + 0x38]'},ctor={'0x2020':'0x3000'})

    def test_direct_call_requires_five_byte_return_and_exact_target(self):
        self.assertEqual(self.tool.call_site(0x2025,self.functions,self.calls,0x3000),('ctor',32))
        for returned,target in ((0x2023,0x3000),(0x2025,0x3001)):
            with self.assertRaises(ValueError): self.tool.call_site(returned,self.functions,self.calls,target)

    def test_virtual_name_call_requires_three_byte_return_and_exact_slot(self):
        self.assertEqual(self.tool.call_site(0x1013,self.functions,self.calls,0x3000,
            indirect='qword ptr [rax + 0x38]'),('register',16))
        for returned,slot in ((0x1015,'qword ptr [rax + 0x38]'),(0x1013,'qword ptr [rax + 0x28]')):
            with self.assertRaises(ValueError): self.tool.call_site(returned,self.functions,self.calls,0x3000,indirect=slot)

    def test_duplicate_caller_declaration_is_rejected(self):
        self.calls['register']['0x2020']='0x3000'
        with self.assertRaises(ValueError): self.tool.call_site(0x2025,self.functions,self.calls,0x3000)

    def test_signed_source_widening_is_not_utf8_or_unsigned_latin1(self):
        self.assertEqual(self.tool.signed_units(b'\x80\xffA\0'),b'\x80\xff\xff\xffA\0\0\0')


class ContainerVectorFixtureTests(unittest.TestCase):
    def setUp(self): self.tool = load('verify-login-container-context')

    def test_reuse_keeps_old_end_capacity_and_fills_the_entire_old_range(self):
        self.assertEqual(self.tool.vector_reset_plan(0x1000,0x1080,0x1100,8,0x2000),
            dict(begin=0x1000,end=0x1080,capacity_end=0x1100,filled=16,reallocated=False))

    def test_fixture_growth_uses_fresh_exact_extent(self):
        self.assertEqual(self.tool.vector_reset_plan(0x1000,0x1080,0x1100,32,0x2000),
            dict(begin=0x2000,end=0x2100,capacity_end=0x2100,filled=32,reallocated=True))

    def test_unsupported_vector_layout_or_unbounded_request_is_rejected(self):
        for args in ((0x1001,0x1081,0x1101,8,0x2000),(0x1000,0x1081,0x1100,8,0x2000),
                (0x1000,0x1080,0x1070,8,0x2000),(0x1000,0x1080,0x1100,3,0x2000),
                (0x1000,0x1080,0x1100,130,0x2000)):
            with self.assertRaises(ValueError): self.tool.vector_reset_plan(*args)


class ContainerAdmissionTests(unittest.TestCase):
    def test_reference_context_or_missing_proof_is_never_native_admission(self):
        module=load('verify-login-container-harness')
        context=dict(family='login-container',format='reference-registration-container',functions={},exports={})
        with patch.object(module,'load',side_effect=AssertionError('no source load before rejection')):
            with self.assertRaises(ValueError): module.admit(context,Path('unused'),set(),{}, {})
            context['format']='login-container-v1'
            with self.assertRaises(ValueError): module.admit(context,Path('unused'),set(),{}, {})

    def test_function_budgets_or_fragment_roots_are_rejected_before_source_load(self):
        module=load('verify-login-container-harness')
        context=dict(family='login-container',format='login-container-v1',transfer_proof={'path':'x','sha256':'0'*64},
            functions={str(i):hex(0x1000+i*0x100) for i in range(5)},leaves={'0x3000':'b804000000c3'},
            exports={'run-example':'0'*64},function_budget=5)
        functions={int(at,16) for at in context['functions'].values()}
        with patch.object(module,'load',side_effect=AssertionError('no source load before rejection')):
            with self.assertRaises(ValueError): module.admit(context,Path('unused'),functions,{0x3000:'b804000000c3'},context['exports'])
            del context['function_budget']
            with self.assertRaises(ValueError): module.admit(context,Path('unused'),functions-{0x1000},{0x3000:'b804000000c3'},context['exports'])


if __name__ == '__main__': unittest.main()
