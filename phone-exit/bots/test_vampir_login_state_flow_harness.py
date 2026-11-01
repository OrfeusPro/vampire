"""Fail-closed root/leaf and virtual-provider admission regressions."""
import copy
import importlib.util
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent/'resource-tools/vampir'

def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

harness=load('verify-login-state-flow-harness')
providers=load('login-state-flow-native-providers')


class Memory:
    def __init__(self):self.bytes={}
    def mem_write(self,at,data):self.bytes.update((at+i,b) for i,b in enumerate(data))
    def mem_read(self,at,size):return bytes(self.bytes.get(at+i,0) for i in range(size))
    def snapshot(self,at,size):return self.mem_read(at,size)


def provider_inputs(*,raw_backed=False,bad_slot=False):
    post=dict(functions=dict(wrapper='0x1000',target='0x2000'),globals=dict(service='0x8100',chunks='0x8200',count='0x8300'),
        service_getter='0x3000',fixtures=dict(lookup='0x4000'))
    continuation=dict(functions=dict(constructor='0x5000',reset='0x6000'),getter='0x7000',
        singleton='0x8400',flag='0x8500',table='0x9000',base_table='0x9100',helpers_captured=['0x9200'])
    fields=dict(continuation_singleton=('0x8400',8),continuation_flag=('0x8500',1),post_state_service=('0x8100',8),
        post_state_chunks=('0x8200',8),post_state_count=('0x8300',4))
    context=dict(functions={'post_state.'+k:v for k,v in post['functions'].items()},
        virtual_globals={k:dict(address=at,size_bytes=size,span={}) for k,(at,size) in fields.items()})
    context['functions'].update({'continuation.'+k:v for k,v in continuation['functions'].items()})
    def offset(value):
        if raw_backed:return 0
        raise ValueError('virtual tail')
    memory=Memory();memory.mem_write(0x9028,struct.pack('<Q',0 if bad_slot else 0x6000))
    fixtures={}
    h=SimpleNamespace(uc=memory,x=None,scratch=0x28000000,image=SimpleNamespace(offset=offset,pe=SimpleNamespace(base=0)),
        add_fixture=lambda at,hook:fixtures.update({at:hook}),finish=lambda value=0:None)
    return h,context,post,continuation,fixtures


class StateFlowHarnessTests(unittest.TestCase):
    def candidate(self):
        return dict(family='login-state-flow',format='login-state-flow-v1',transfer_proof={'path':'proof','sha256':'a'*64},
            functions={str(i):hex(0x1000+i*16) for i in range(33)},
            leaves={hex(0x2000+i*16):'c3' for i in range(14)},exports={'run': 'b'*64})

    def test_rejects_incomplete_or_aliased_union_before_index(self):
        c=self.candidate();roots={int(at,16) for at in c['functions'].values()};leaves={int(at,16):v for at,v in c['leaves'].items()}
        with patch.object(harness,'load',side_effect=AssertionError('must reject before index')):
            for functions,selected_leaves in ((set(list(roots)[:-1]),leaves),(roots,dict(list(leaves.items())[:-1]))):
                with self.assertRaises(ValueError):harness.admit(c,Path('.'),functions,selected_leaves,c['exports'])
            alias=copy.deepcopy(c);alias['functions']['1']=alias['functions']['0']
            with self.assertRaises(ValueError):harness.admit(alias,Path('.'),{int(v,16) for v in alias['functions'].values()},leaves,alias['exports'])

    def test_reference_and_budget_override_never_admit_execution(self):
        for key,value in (('format','reference-login-state-flow'),('function_budget',33),('budget_scope','arbitrary'),('transfer_proof',None)):
            c=self.candidate();c[key]=value
            with self.subTest(key=key),patch.object(harness,'load',side_effect=AssertionError('must reject before index')):
                with self.assertRaises(ValueError):harness.admit(c,Path('.'),{int(at,16) for at in c['functions'].values()},
                    {int(at,16):v for at,v in c['leaves'].items()},c['exports'])

    def test_virtual_tail_cannot_silently_become_raw_backed(self):
        h,c,p,v,fixtures=provider_inputs(raw_backed=True)
        with self.assertRaisesRegex(ValueError,'raw backing'):
            providers.install(h,c,p,v,caller=None,map_source=lambda at,size:None,box=None)
        self.assertEqual(fixtures,{})

    def test_virtual_provider_width_mismatch_fails_before_hook_installation(self):
        h,c,p,v,fixtures=provider_inputs();c['virtual_globals']['continuation_flag']['size_bytes']=8
        with self.assertRaisesRegex(ValueError,'address/width'):
            providers.install(h,c,p,v,caller=None,map_source=lambda at,size:None,box=None)
        self.assertEqual(fixtures,{})

    def test_final_source_virtual_slot_cannot_target_an_unrelated_function(self):
        h,c,p,v,fixtures=provider_inputs(bad_slot=True)
        with self.assertRaisesRegex(ValueError,'reset slot'):
            providers.install(h,c,p,v,caller=None,map_source=lambda at,size:None,box=None)
        self.assertEqual(fixtures,{})

    def test_provider_mutable_windows_are_disjoint_from_packet_handler_and_tls(self):
        h,c,p,v,_=provider_inputs()
        installed=providers.install(h,c,p,v,caller=None,map_source=lambda at,size:None,box=None)
        regions=installed['native_regions']()
        old=[(h.scratch+0x1000,344),(h.scratch+0xa000,0x100),(h.scratch+0xb000,0x320),
            (h.scratch+0xf600,8),(h.scratch+0x1a0cc0,8)]
        self.assertEqual(len(regions),4)
        for at,size in regions:
            self.assertTrue(all(not (at<start+length and at+size>start) for start,length in old))
        policy=harness.MemoryPolicy(h.uc);policy.native_allow(regions);policy.protect([(0x8400,8),(0x9000,0x30)])
        for at,size in ((0x8400,8),(0x9028,8)):
            with self.assertRaises(ValueError):policy.writable(at,size,native=True)


class CapturedSecondTests(unittest.TestCase):
    def test_exact_source_table_carry_has_typed_projection(self):
        table=0x149cba918
        self.assertEqual(providers.captured_second(43,table,table),'source_vtable_low32')

    def test_relocated_table_is_derived_instead_of_hard_coded(self):
        for table in (0x140001000,0x185faf800,0x234567890,0x734567890):
            with self.subTest(table=hex(table)):
                self.assertEqual(providers.captured_second(43,table,table),'source_vtable_low32')

    def test_same_low32_but_different_high32_is_rejected(self):
        table=0x149cba918
        for actual in (0x249cba918,0x49cba918,table+(1<<40)):
            with self.subTest(actual=hex(actual)),self.assertRaisesRegex(ValueError,'register carry'):
                providers.captured_second(43,actual,table)

    def test_wrong_first_call_register_is_not_zeroed_or_silently_accepted(self):
        for actual in (0,0x1234,0x149cba919):
            with self.subTest(actual=hex(actual)),self.assertRaisesRegex(ValueError,'register carry'):
                providers.captured_second(43,actual,0x149cba918)

    def test_binary_and_high_branch_zero_observations_are_unchanged(self):
        for offset in (53,62,77,98,108,117,132,153,163,172,187,236,277,287,760):
            with self.subTest(offset=offset):
                self.assertEqual(providers.captured_second(offset,0,0x149cba918),0)

    def test_other_offsets_keep_uint32_without_new_carry_assertions(self):
        for offset in (0,42,44,53,62):
            self.assertEqual(providers.captured_second(offset,0xfedcba9876543210,0x149cba918),0x76543210)

    def test_register_width_and_exact_integer_inputs_fail_closed(self):
        for values in ((True,0,1),(43,True,1),(43,1,True),(-1,0,1),(43,-1,1),(43,1<<64,1),(43,1,0)):
            with self.subTest(values=values),self.assertRaisesRegex(ValueError,'register input'):
                providers.captured_second(*values)


if __name__=='__main__':unittest.main()
