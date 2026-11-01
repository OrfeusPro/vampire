"""Provider preparation is separate from readonly actual handler entry."""
import importlib.util
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent/'resource-tools/vampir'
s=importlib.util.spec_from_file_location('state_flow_services',HERE/'login-state-flow-handler-fixtures.py')
services=importlib.util.module_from_spec(s);s.loader.exec_module(services)


class Memory:
    def __init__(self):self.bytes={};self.hooks=[];self.writes=[]
    def mem_read(self,at,size):return bytes(self.bytes.get(at+i,0) for i in range(size))
    def mem_write(self,at,data):
        self.writes.append((at,bytes(data)))
        for i,b in enumerate(data):self.bytes[at+i]=b
    def mem_regions(self):return [(0,0xffffffffffffffff,7)]
    def hook_add(self,*args):self.hooks.append(args)
    def reg_read(self,reg):return 0x10020


def make():
    memory=Memory();scratch=0x28000000;handler=0x10000;gate=0x11000;table=0x12000;id_getter=0x13000;name_ctor=0x14000
    globals_=dict(sdk_enabled=0x15000,special22=0x15010,derived=0x15020)
    row=dict(address=handler,call=False,rip_references=list(globals_.values()))
    call=dict(address=handler+5,call=True,direct_target=gate,rip_references=[])
    ctx=dict(functions=dict(handler=hex(handler),gate=hex(gate)),call_sites=dict(handler={hex(handler+5):hex(gate)},gate={}),
        fixtures=dict(unsupported_141426950=hex(name_ctor),post_state=hex(0x16000),view_service=hex(0x17000)),leaves={},packet_table=hex(table),id_getter=hex(id_getter),
        globals={key:hex(at) for key,at in globals_.items()})
    def load(name):
        if name=='build-native-entry-code':return SimpleNamespace()
        if name=='update-bindings':return SimpleNamespace(rows=lambda *_:[row,call])
        if name=='result-gate-transfer-rules':return SimpleNamespace(rows=lambda *_:[])
        if name=='verify-login-full-handler-context':return SimpleNamespace(read_popup_selector=lambda *_:77)
        raise ValueError(name)
    fixtures={}
    h=SimpleNamespace(scratch=scratch,uc=memory,x=SimpleNamespace(UC_X86_REG_RIP=1),image=SimpleNamespace(),raw=b'',
        add_fixture=lambda at,fn:fixtures.__setitem__(at,fn),finish=lambda *_:None,
        call=lambda *_args,**_kwargs:(_ for _ in ()).throw(AssertionError('No direct native call allowed')))
    memory.mem_write(table+0x28,struct.pack('<Q',id_getter))
    packet=scratch+0x1000;packet_table=0x18000
    memory.mem_write(packet-16,b'\xa5'*16+b'\x55'*344+b'\xa6'*16)
    memory.mem_write(scratch+0xf600,struct.pack('<Q',packet_table))
    return h,ctx,load,packet,packet_table,name_ctor,fixtures


class StateFlowHandlerServicesTests(unittest.TestCase):
    def setUp(self):
        runtime=SimpleNamespace(UC_HOOK_MEM_WRITE=1,UC_HOOK_CODE=2)
        patched=patch.dict(sys.modules,unicorn=runtime);patched.start();self.addCleanup(patched.stop)

    def test_prepare_leave_finish_never_calls_native_or_reseeds_packet(self):
        h,c,load,packet,table,ctor,fixtures=make();before=h.uc.mem_read(packet-16,376)
        api=services.install(load,h,c,{},packet,handler_table=table,native_name_constructor=ctor)
        self.assertEqual(set(api),{'prepare','enter','leave','finish','receiver'})
        self.assertEqual(api['receiver'],h.scratch+0xf600)
        self.assertNotIn(ctor,fixtures)
        self.assertEqual(api['prepare']({}),api['receiver']);api['enter']();api['leave']();row=api['finish']()
        self.assertEqual(h.uc.mem_read(packet-16,376),before)
        self.assertTrue(row['handler_invoked']);self.assertEqual(row['state']['text'],'before')

    def test_finish_requires_an_observed_handler_return(self):
        h,c,load,packet,table,ctor,_=make();api=services.install(load,h,c,{},packet,handler_table=table,native_name_constructor=ctor)
        with self.assertRaises(ValueError):api['finish']()
        with self.assertRaises(ValueError):api['leave']()
        api['prepare']({})
        with self.assertRaises(ValueError):api['finish']()
        with self.assertRaises(ValueError):api['leave']()
        api['enter']()
        with self.assertRaises(ValueError):api['enter']()
        api['leave']()
        with self.assertRaises(ValueError):api['leave']()

    def test_native_alias_must_be_the_exact_reviewed_unsupported_role(self):
        h,c,load,packet,table,ctor,_=make();c['fixtures']={'other':hex(ctor)}
        with self.assertRaises(ValueError):services.install(load,h,c,{},packet,handler_table=table,native_name_constructor=ctor)

    def test_wrong_vtable_or_reference_extent_cannot_enter_handler_services(self):
        h,c,load,packet,table,ctor,_=make()
        with self.assertRaises(ValueError):services.install(load,h,c,{},packet,handler_table=table,native_name_constructor=ctor,packet_extent=352)
        api=services.install(load,h,c,{},packet,handler_table=table+8,native_name_constructor=ctor)
        with self.assertRaises(ValueError):api['prepare']({})

    def test_settings_are_preserved_without_promoting_them_to_packet_writes(self):
        h,c,load,packet,table,ctor,_=make();before=h.uc.mem_read(packet,344)
        api=services.install(load,h,c,{},packet,handler_table=table,native_name_constructor=ctor)
        api['prepare'](dict(code=22,field48=1,raw16=65535,optional_object=False))
        api['enter']();api['leave']();row=api['finish']()
        self.assertEqual(row['settings'],dict(optional_object=False))
        self.assertEqual((row['code'],row['field48'],row['raw16']),(22,1,65535))
        self.assertEqual(h.uc.mem_read(packet,344),before)

    def test_write_observer_stops_at_actual_handler_return(self):
        h,c,load,packet,table,ctor,_=make()
        api=services.install(load,h,c,{},packet,handler_table=table,native_name_constructor=ctor)
        observer=next(hook[1] for hook in h.uc.hooks if hook[0]==1)
        api['prepare']({});api['enter']()
        observer(None,None,h.scratch+0xa000+0x38,8,10,None)
        api['leave']()
        observer(None,None,h.scratch+0xa000+0x38,8,20,None)
        row=api['finish']()
        self.assertEqual(row['writes'],[dict(region='state',offset='0x38',size=8,value=10,instruction_offset=0x20)])


    def test_native_post_getter_wrapper_and_continuation_virtual_are_not_fixtures(self):
        h,c,load,packet,table,ctor,fixtures=make()
        services.install(load,h,c,{},packet,handler_table=table,native_name_constructor=ctor)
        for at in (ctor,int(c['fixtures']['post_state'],16),int(c['fixtures']['view_service'],16),h.scratch+0xf810):
            self.assertNotIn(at,fixtures)
        self.assertIn(h.scratch+0xf800,fixtures)
        self.assertIn(h.scratch+0xf820,fixtures)

    def test_missing_or_aliased_native_promotion_roles_fail_before_execution(self):
        for kind in ('missing','duplicate','name-constructor'):
            h,c,load,packet,table,ctor,_=make()
            if kind=='missing':c['fixtures'].pop('post_state')
            elif kind=='duplicate':c['fixtures']['post_state']=c['fixtures']['view_service']
            else:c['fixtures']['post_state']=hex(ctor)
            with self.subTest(kind=kind),self.assertRaises(ValueError):
                services.install(load,h,c,{},packet,handler_table=table,native_name_constructor=ctor)

    def test_preparation_does_not_write_old_view_or_native_provider_objects(self):
        h,c,load,packet,table,ctor,_=make()
        ranges=((h.scratch+0xe000,0x300),(h.scratch+0xc0000,0x9000),(h.scratch+0xd0000,0x400))
        for at,size in ranges:h.uc.mem_write(at,b'\x6d'*size)
        api=services.install(load,h,c,{},packet,handler_table=table,native_name_constructor=ctor)
        api['prepare']({})
        for at,size in ranges:self.assertEqual(h.uc.mem_read(at,size),b'\x6d'*size)

    def test_actual_entry_snapshots_native_reader_packet_without_any_memory_write(self):
        h,c,load,packet,table,ctor,_=make()
        api=services.install(load,h,c,{},packet,handler_table=table,native_name_constructor=ctor)
        with self.assertRaises(ValueError):api['enter']()
        api['prepare']({})
        # Simulate the native reader between provider preparation and entry.
        h.uc.mem_write(packet,b'\x31'*344)
        count=len(h.uc.writes)
        self.assertEqual(api['enter'](),api['receiver'])
        self.assertEqual(len(h.uc.writes),count)
        with self.assertRaises(ValueError):api['prepare']({})
        api['leave']();api['finish']()

    def test_handler_mutation_is_checked_against_actual_entry_not_preparation(self):
        h,c,load,packet,table,ctor,_=make()
        api=services.install(load,h,c,{},packet,handler_table=table,native_name_constructor=ctor)
        api['prepare']({});h.uc.mem_write(packet,b'\x31'*344);api['enter']()
        h.uc.mem_write(packet+10,b'\x32');api['leave']()
        with self.assertRaises(ValueError):api['finish']()

    def test_write_observer_does_not_collect_provider_setup_as_native_handler_stores(self):
        h,c,load,packet,table,ctor,_=make()
        api=services.install(load,h,c,{},packet,handler_table=table,native_name_constructor=ctor)
        observer=next(hook[1] for hook in h.uc.hooks if hook[0]==1)
        api['prepare']({});observer(None,None,h.scratch+0xa000+0x38,8,10,None)
        api['enter']();api['leave']()
        self.assertEqual(api['finish']()['writes'],[])


if __name__=='__main__':unittest.main()
