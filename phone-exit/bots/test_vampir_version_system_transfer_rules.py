"""Synthetic relocation-rule regressions; no native execution or private captures."""
import copy
import json
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_vampir_update_contracts import load

TOOL=load('version-system-transfer-rules')
CONTEXTS=Path(__file__).parent/'resource-tools/vampir/knowledge/native-contexts'


def baseline(family):return json.loads((CONTEXTS/(family+'-11320.json')).read_text('utf-8'))


class SchemaTests(unittest.TestCase):
    def test_exact_root_budgets_and_functional_only_result(self):
        for family,count in (('version-nm-device',2),('version-cpu',6),('version-windows',1)):
            with self.subTest(family=family):
                c=baseline(family);self.assertEqual(len(TOOL.roots(family,c)),count)
                value=TOOL.functional(family,c);self.assertFalse(set(value)&TOOL.METADATA)
                value['helpers']['memcpy']='0x1';self.assertNotEqual(c['helpers']['memcpy'],'0x1')

    def test_optional_native_fields_extra_fixtures_and_alias_roots_rejected(self):
        c=baseline('version-cpu')
        for changed in ({**c,'native_sdk':{}},{**c,'fixtures':{**c['fixtures'],'unknown':'0x1'}},
                {**c,'functions':{**c['functions'],'first':c['functions']['second']}}):
            with self.subTest(fields=tuple(changed)),self.assertRaises(ValueError):TOOL.roots('version-cpu',changed)

    def test_windows_import_roles_cannot_be_renamed_or_repurposed(self):
        for field,value in (('dll','OTHER.dll'),('fixture','version'),('extra',True)):
            c=baseline('version-windows');c['imports']['GetNativeSystemInfo'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):TOOL.functional('version-windows',c)


class TypedDataTests(unittest.TestCase):
    def image(self):
        return SimpleNamespace(pe=SimpleNamespace(base=0,sections=[dict(rva=100,raw_size=16,size=64,name='.data')]),
            data=bytes(range(16)),offset=lambda at:at-100)

    def test_file_data_and_proven_zero_fill_have_distinct_typed_receipts(self):
        image=self.image()
        self.assertEqual(TOOL.data_input(image,104,4),dict(storage='file',bytes='04050607'))
        self.assertEqual(TOOL.data_input(image,116,16),dict(storage='pe-zero-fill',size=16,section='.data'))

    def test_cross_section_cross_storage_and_outside_intervals_rejected(self):
        for at,size in ((114,4),(99,2),(160,8),(116,0)):
            with self.subTest(at=at,size=size),self.assertRaises(ValueError):TOOL.data_input(self.image(),at,size)

    def test_rip_role_count_offset_and_descriptor_linkage_are_exact(self):
        rows=[dict(address=1000+8,rip_references=[208])];mapping={208:1208};known={'cache':200}
        TOOL.rip_roles(rows,1000,{8:('cache',8)},known,mapping);self.assertEqual(mapping[200],1200)
        for malformed in ([dict(address=1009,rip_references=[208])],[dict(address=1008,rip_references=[208,216])]):
            with self.assertRaisesRegex(ValueError,'RIP role layout'):TOOL.rip_roles(malformed,1000,{8:('cache',8)},known,mapping)
        with self.assertRaisesRegex(ValueError,'subfield relocation'):
            TOOL.rip_roles(rows,1000,{8:('cache',8)},known,{200:2000,208:1208})


class BoundaryTests(unittest.TestCase):
    def test_fixture_requires_exact_unwind_entry(self):
        image=SimpleNamespace(pe=SimpleNamespace(base=0),roots={0:(100,120)},containing=lambda at:0 if 100<=at<120 else None)
        TOOL.concrete(image,100)
        for at in (101,99,120):
            with self.subTest(at=at),self.assertRaises(ValueError):TOOL.concrete(image,at)

    def test_named_import_pins_dll_and_name(self):
        image=SimpleNamespace(data=b'')
        for result in (dict(name='iswspace',dll='other.dll'),dict(name='other',dll='api-ms-win-crt-string-l1-1-0.dll')):
            with patch.object(TOOL,'load',return_value=SimpleNamespace(import_at=lambda *args:result)):
                with self.assertRaisesRegex(ValueError,'import identity'):TOOL.named_import(image,123,'iswspace','api-ms-win-crt-string-l1-1-0.dll')

    def test_crt_thunk_is_six_bytes_with_named_import_and_consistent_slot_mapping(self):
        old,new=object(),object();mapping={};common=load('update-native-archive-wire');reads=[]
        def raw(image,at,size):reads.append(size);return b'\xff\x25'+struct.pack('<i',100)
        with patch.object(TOOL,'load',return_value=common),patch.object(TOOL,'image_bytes',side_effect=raw),\
                patch.object(TOOL,'named_import',side_effect=lambda image,slot,name,dll:dict(slot=hex(slot),name=name,dll=dll)):
            result=TOOL.import_thunk(old,new,1000,2000,'memmove',mapping)
            self.assertEqual(reads,[6,6]);self.assertEqual(mapping,{1106:2106});self.assertEqual(result['kind'],'named-import-thunk')
        with patch.object(TOOL,'image_bytes',return_value=b'\x90'*6):
            with self.assertRaisesRegex(ValueError,'six-byte'):TOOL.import_thunk(old,new,1000,2000,'memmove',{})


class TransferTests(unittest.TestCase):
    def setUp(self):
        self.old,self.new=object(),object();self.common=load('update-native-archive-wire')

    def fixture(self,family):
        c=baseline(family);roles=TOOL.root_roles(family,c);known={};self.memory={};mapping={};rows={}
        if family=='version-nm-device':
            known.update({k:int(c[k],16) for k in ('cache','log_level','log_enabled')})
            known.update({'storage'+str(i):int(v,16) for i,v in enumerate(c['storage_arguments'])})
            specs={'wrapper':{},'getter':TOOL.NM_RIPS}
            literal={'diagnostic_name':b'class FString __cdecl Netmarble::Service::FDeviceInfo::GetNMDeviceKey(void)\0',
                'empty':b'\0\0','diagnostic_format':'%s\0'.encode('utf-16le')}
            data=[('cache',16,None),('log_level',1,None),('log_enabled',1,b'\1')]+[('storage'+str(i),16,None) for i in range(3)]
        elif family=='version-cpu':
            known.update({k:int(c[k],16) for k in ('vendor','brand','space_slot')});specs=TOOL.CPU_RIPS
            literal={k:(v+'\0').encode('utf-16le') for k,v in dict(unknown='Unknown',separator='|',underscore='_',empty='',format_three='%s|%s|%s',format_two='%s|%s').items()}
            data=[('vendor',13,bytes(13)),('brand',64,bytes(64))]
        else:
            known.update({k:int(c[k],16) for k in ('guard','cache','tls_index','cookie')});specs={'windows':TOOL.WINDOWS_RIPS}
            known.update(system_info_slot=int(c['imports']['GetNativeSystemInfo']['slot'],16),version_slot=int(c['imports']['GetVersionExW']['slot'],16))
            literal={k:(v+'\0').encode('utf-16le') for k,v in dict(bits='64bit',format='%d.%d.%d.%d.%d.%s').items()}
            data=[('guard',4,None),('cache',256,None),('tls_index',4,None),('cookie',8,bytes.fromhex('32a2df2d992b0000'))]
        known.update({k:0x2000000000+n*0x100 for n,k in enumerate(literal)})
        for role,at in roles.items():
            by_offset={}
            for offset in TOOL.CALL_ROLES[family][role]:
                target=c['call_sites'][hex(at+offset)]
                by_offset[offset]=dict(address=at+offset,call=True,direct_target=int(target,16) if target.startswith('0x') else None,
                    operands=target,rip_references=[])
            for offset,(name,delta) in specs[role].items():
                row=by_offset.setdefault(offset,dict(address=at+offset,call=False,direct_target=None,operands='',rip_references=[]))
                row['rip_references']=[known[name]+delta]
            rows[at]=[by_offset[n] for n in sorted(by_offset)]
            mapping[at]=at+0x1000
        for group in rows.values():
            for row in group:
                for at in [row['address'],row['direct_target'],*row['rip_references']]:
                    if at is not None:mapping[at]=at+0x1000
        for at in [*known.values(),int(c['helpers']['memcpy'],16)]:mapping[at]=at+0x1000
        for role,size,raw in data+[(k,len(v),v) for k,v in literal.items()]:
            value=dict(storage='pe-zero-fill',size=size,section='.data') if raw is None else dict(storage='file',bytes=raw.hex())
            self.memory[(self.old,known[role],size)]=value;self.memory[(self.new,mapping[known[role]],size)]=copy.deepcopy(value)
        for at,group in list(rows.items()):
            rows[mapping[at]]=[{**r,'address':mapping[r['address']],'direct_target':mapping[r['direct_target']] if r['direct_target'] is not None else None,
                'rip_references':[mapping[ref] for ref in r['rip_references']]} for r in group]
        self.family,self.context,self.mapping,self.rows,self.known=family,c,mapping,rows,known
        return c

    def transfer(self):
        bindings=SimpleNamespace(rows=lambda native,image,at:self.rows[at])
        with patch.object(TOOL,'concrete'),patch.object(TOOL,'load',return_value=SimpleNamespace(pair_rows=lambda *args:None,add_link=self.common.add_link)),\
                patch.object(TOOL,'data_input',side_effect=lambda image,at,size:copy.deepcopy(self.memory[(image,at,size)])),\
                patch.object(TOOL,'named_import',return_value={'identity':'checked'}),patch.object(TOOL,'import_thunk',return_value={'kind':'checked-thunk'}):
            return TOOL.transfer(self.family,None,bindings,self.old,self.new,self.context,self.mapping)

    def test_all_families_relocate_without_mutating_baseline_or_copying_metadata(self):
        for family in TOOL.FIELDS:
            self.fixture(family);before=copy.deepcopy(self.context);current,detail=self.transfer()
            self.assertEqual(self.context,before);self.assertFalse(set(current)&TOOL.METADATA)
            self.assertEqual(set(detail['roots']),set(TOOL.root_roles(family,before)))
            if family=='version-cpu':self.assertEqual(current['fixtures']['space'],'0x28006000')

    def test_unknown_rip_and_changed_exact_literal_stop_transfer(self):
        self.fixture('version-cpu');at=int(self.context['functions']['formatter'],16)
        self.rows[at].append(dict(address=at+999,call=False,rip_references=[self.known['empty']]))
        with self.assertRaisesRegex(ValueError,'RIP role layout'):self.transfer()
        self.fixture('version-cpu');key=(self.new,self.mapping[self.known['unknown']],16)
        self.memory[key]=dict(storage='file',bytes='ff'*16)
        with self.assertRaisesRegex(ValueError,'typed data changed: unknown'):self.transfer()

    def test_missing_seed_callee_role_mismatch_and_fixture_alias_are_blockers(self):
        self.fixture('version-nm-device');self.mapping.pop(int(self.context['wrapper'],16))
        with self.assertRaisesRegex(ValueError,'caller-constrained'):self.transfer()
        self.fixture('version-cpu');self.context['fixtures']['wide']=self.context['fixtures']['ascii']
        with self.assertRaisesRegex(ValueError,'callee role linkage'):self.transfer()
        self.fixture('version-cpu');self.mapping[int(self.context['fixtures']['free'],16)]=self.mapping[int(self.context['fixtures']['ascii'],16)]
        with self.assertRaisesRegex(ValueError,'fixtures/roots alias'):self.transfer()

    def test_file_data_cannot_silently_replace_a_proven_bss_role(self):
        self.fixture('version-windows')
        for image,at in ((self.old,self.known['guard']),(self.new,self.mapping[self.known['guard']])):
            self.memory[(image,at,4)]=dict(storage='file',bytes='00'*4)
        with self.assertRaisesRegex(ValueError,'typed data changed: guard'):self.transfer()


if __name__=='__main__':unittest.main()
