"""Pure writer inheritance: controlled metadata/instruction fixtures, no native."""
import copy
import importlib.util
from pathlib import Path
import struct
import unittest

HERE = Path(__file__).parent/'resource-tools/vampir'
spec = importlib.util.spec_from_file_location('contract_writer_inheritance_v1', HERE/'contract-writer-inheritance-v1.py')
RULE = importlib.util.module_from_spec(spec); spec.loader.exec_module(RULE)

FIELDS = {
    'game-version': [['string',16],['u32',32],['string',40],['string',56],['string',72],
        ['string',88],['string',104],['string',120],['string',136],['u32',152],
        ['string',160],['string',176],['u32',192]],
    'game-login': [['string',16],['string',32],['string',48],['string',64],['u32',80],
        ['string',88],['string',104],['string',120],['string',136],['u8',152],['u8',153],
        ['string',160],['u32',176],['string',184],['string',200],['string',216],
        ['string',232],['u32',248],['string',256],['string',272],['u32',288],
        ['u8',292],['u64',296],['bool',304],['bool',305]]}
SLOTS = {'u32':0xc8,'u8':0xe0,'u64':0xb8,'bool':0xf0}


def rows(origin, helper, fields):
    result = []; at = origin
    def add(raw, mnemonic, operands='', *, call=False, branch=False, target=None):
        nonlocal at
        result.append(dict(address=at, bytes=raw.hex(), mnemonic=mnemonic, operands=operands,
            call=call, branch=branch, direct_target=target, rip_references=[]))
        at += len(raw)
    add(b'\x53','push','rbx')
    for kind, _ in fields:
        if kind == 'string':
            add(b'\xe8'+struct.pack('<i',helper-at-5),'call',hex(helper),call=True,target=helper)
        else:
            add(b'\xff\x90'+struct.pack('<i',SLOTS[kind]),'call',
                'qword ptr [rax + '+hex(SLOTS[kind])+']',call=True)
    add(b'\x84\xc0','test','al, al')
    add(b'\x74\x07','je',hex(at+9),branch=True,target=at+9)
    add(b'\xb8\x01\x00\x00\x00','mov','eax, 1')
    add(b'\x5b','pop','rbx'); add(b'\xc3','ret')
    add(b'\x31\xc0','xor','eax, eax')
    add(b'\x5b','pop','rbx'); add(b'\xc3','ret')
    return result


def fixture(contract='game-version'):
    fields=copy.deepcopy(FIELDS[contract]); size=208 if contract=='game-version' else 320
    old=dict(schema=1,source_sha256='a'*64,bindings={'string-writer':'0x8000'},
        packets={contract:dict(writer='0x1000',table='0xa000',fields=fields,object_size=size)})
    new=copy.deepcopy(old);new['source_sha256']='b'*64;new['bindings']['string-writer']='0x9000'
    new['packets'][contract].update(writer='0x2000',table='0xb000')
    cases=[dict(poison=p,fail_at=f,calls=len(fields) if f==-1 else f+1,result=int(f==-1),guards=True)
        for p in (0,85,170,255) for f in range(-1,len(fields))]
    report=dict(schema=1,source_sha256='a'*64,method='bounded_native',network_used=False,profile_activated=False,
        binding=dict(writer='0x1000',constructor='0xc000',packet_table='0xa000',string_helper='0x8000',table_slot=16),
        fields=copy.deepcopy(fields),cases=cases,evidence=[dict(path='F:/fixture/details.json',sha256='c'*64)])
    before=rows(0x1000,0x8000,fields);after=rows(0x2000,0x9000,fields)
    mapping={hex(a['address']):hex(b['address']) for a,b in zip(before,after)}
    mapping.update({'0x8000':'0x9000','0xa000':'0xb000'})
    return [report,old,new,contract,before,after,mapping]


class WriterInheritanceTests(unittest.TestCase):
    def reject(self, data):
        with self.assertRaises(ValueError): RULE.verify(*data)

    def test_version_and_login_counts_distinguish_static_from_target_execution(self):
        for contract,count in (('game-version',56),('game-login',104)):
            with self.subTest(contract=contract):
                data=fixture(contract);unchanged=copy.deepcopy(data)
                result=RULE.verify(*data)
                self.assertEqual(result['method'],'static_inheritance')
                self.assertEqual(result['inherited_cases'],count)
                self.assertEqual(result['inherited_success_controls'],4)
                self.assertEqual(result['inherited_failure_cases'],count-4)
                self.assertEqual(result['target_native_cases'],0)
                self.assertFalse(result['network_used']);self.assertFalse(result['runtime_activated'])
                self.assertFalse(result['profile_activated']);self.assertEqual(data,unchanged)

    def test_returned_fields_do_not_mutate_inputs(self):
        data=fixture();result=RULE.verify(*data);result['fields'][0][1]=999
        self.assertEqual(data[0]['fields'][0][1],16)

    def test_reordered_case_list_is_still_the_same_complete_matrix(self):
        data=fixture();data[0]['cases'].reverse()
        self.assertEqual(RULE.verify(*data)['inherited_cases'],56)

    def test_missing_duplicate_or_extra_cases_rejected(self):
        for mode in ('missing','duplicate','extra'):
            with self.subTest(mode=mode):
                data=fixture()
                if mode=='missing':data[0]['cases'].pop()
                elif mode=='duplicate':data[0]['cases'][-1]=copy.deepcopy(data[0]['cases'][0])
                else:data[0]['cases'].append(copy.deepcopy(data[0]['cases'][0]))
                self.reject(data)

    def test_case_result_calls_poison_position_and_guard_must_match(self):
        for key,value in (('guards',False),('guards',1),('calls',True),('calls',1),
                ('result',False),('result',0),('poison',1),('poison',True),('fail_at',99),('fail_at',True)):
            with self.subTest(key=key,value=value):
                data=fixture();data[0]['cases'][0][key]=value;self.reject(data)

    def test_report_flags_source_method_schema_and_evidence_are_exact(self):
        for key,value in (('source_sha256','d'*64),('method','static'),('schema',True),
                ('network_used',0),('profile_activated',True),('runtime_activated',True),('evidence',[])):
            with self.subTest(key=key):
                data=fixture();data[0][key]=value;self.reject(data)
        data=fixture();data[0]['evidence'][0]['sha256']='short';self.reject(data)

    def test_unknown_or_untyped_contract_and_source_rejected(self):
        for value in ('other',None,[]):
            data=fixture();data[3]=value;self.reject(data)
        for value in ('short',None):
            data=fixture();data[1]['source_sha256']=value;self.reject(data)
        data=fixture();data[1]=None;self.reject(data)

    def test_baseline_binding_writer_table_helper_or_slot_mismatch(self):
        for key,value in (('writer','0x1001'),('packet_table','0xa001'),
                ('string_helper','0x8001'),('table_slot',24),('table_slot',True),('constructor','not-address')):
            with self.subTest(key=key):
                data=fixture();data[0]['binding'][key]=value;self.reject(data)

    def test_report_field_order_and_target_layout_change_rejected(self):
        data=fixture();data[0]['fields'][0],data[0]['fields'][2]=data[0]['fields'][2],data[0]['fields'][0];self.reject(data)
        data=fixture();data[2]['packets'][data[3]]['object_size']=216;self.reject(data)
        data=fixture();data[2]['packets'][data[3]]['fields'][0][1]=24;self.reject(data)

    def test_missing_fields_unsupported_kind_bounds_overlap_and_bool_offset_rejected(self):
        changes=[lambda p:p['fields'].pop(),lambda p:p['fields'][0].__setitem__(0,'unknown'),
            lambda p:p['fields'][0].__setitem__(0,[]),lambda p:p['fields'][0].__setitem__(1,1),
            lambda p:p['fields'][0].__setitem__(1,True),lambda p:p['fields'][0].__setitem__(1,32),
            lambda p:p.__setitem__('object_size',1024)]
        for change in changes:
            data=fixture();change(data[1]['packets'][data[3]]);self.reject(data)

    def test_canonical_address_and_every_selected_relocation_required(self):
        for key in ('0x1000','0xa000','0x8000'):
            data=fixture();data[6].pop(key);self.reject(data)
        data=fixture();data[6][hex(data[4][1]['address'])]='0x2002';self.reject(data)
        data=fixture();data[6]['0x01000']=data[6].pop('0x1000');self.reject(data)
        data=fixture();data[6]['0xa000']='0xb001';self.reject(data)

    def test_omitted_changed_extra_and_noncontiguous_rows_rejected(self):
        data=fixture();data[5].pop();self.reject(data)
        data=fixture();data[5].append(copy.deepcopy(data[5][-1]));self.reject(data)
        data=fixture();data[5][0]['address']+=1;self.reject(data)
        data=fixture();data[5][0]['bytes']='90';self.reject(data)
        data=fixture();data[5][0]['operands']='rdi';self.reject(data)

    def test_instruction_bytes_flags_and_mnemonic_are_not_trusted_blindly(self):
        for key,value in (('bytes','53ff'),('bytes','ZZ'),('bytes','53'*16),('call',1),
                ('branch',1),('mnemonic','call'),('direct_target',0x5000),('rip_references',[0xa000])):
            with self.subTest(key=key):
                data=fixture();data[4][0][key]=value;self.reject(data)

    def test_unknown_direct_helper_or_wrong_relative_call_bytes_rejected(self):
        data=fixture();call=data[5][1];call['direct_target']=0x9001
        call['operands']='0x9001';call['bytes']=(b'\xe8'+struct.pack('<i',0x9001-call['address']-5)).hex()
        self.reject(data)
        data=fixture();data[5][1]['bytes']='e800000000';self.reject(data)
        data=fixture();data[5][1]['bytes']='ff9000000000';self.reject(data)

    def test_string_cannot_become_indirect_or_scalar_direct(self):
        data=fixture();data[5][1].update(direct_target=None,bytes='ff90c8000000',operands='qword ptr [rax + 0xc8]');self.reject(data)
        data=fixture();call=next(r for r in data[5] if r['call'] and r['direct_target'] is None)
        call.update(direct_target=0x9000,bytes=(b'\xe8'+struct.pack('<i',0x9000-call['address']-5)).hex(),operands='0x9000')
        self.reject(data)

    def test_scalar_slot_register_kind_and_dispatch_flags_rejected(self):
        for mutate in (lambda r:r.update(bytes='ff90e0000000',operands='qword ptr [rax + 0xe0]'),
                lambda r:r.update(bytes='ff91c8000000',operands='qword ptr [rcx + 0xc8]'),
                lambda r:r.update(operands='qword ptr [rax + 0xe0]'),
                lambda r:r.update(branch=True),lambda r:r.update(rip_references=[0x4000])):
            data=fixture();call=next(r for r in data[5] if r['call'] and r['direct_target'] is None)
            mutate(call);self.reject(data)

    def test_each_scalar_slot_is_checked_in_login_model(self):
        for kind in ('u32','u8','u64','bool'):
            data=fixture('game-login');calls=[r for r in data[5] if r['call']]
            index=next(i for i,f in enumerate(data[0]['fields']) if f[0]==kind)
            calls[index]['bytes']='ff9001000000';self.reject(data)

    def test_internal_branch_target_mapping_bytes_and_external_tail_rejected(self):
        for mutate in (lambda r:r.update(direct_target=0x9999),lambda r:r.update(direct_target=None),
                lambda r:r.update(bytes='7406'),lambda r:r.update(direct_target=r['direct_target']-1),
                lambda r:r.update(branch=False)):
            data=fixture();branch=next(r for r in data[5] if r['branch']);mutate(branch);self.reject(data)

    def test_unknown_rip_data_and_missing_call_rejected(self):
        data=fixture();data[4][0]['rip_references']=[0xa000];data[5][0]['rip_references']=[0xb000];self.reject(data)
        data=fixture();call=data[4][1];call['call']=False;call['mnemonic']='nop';call['direct_target']=None;self.reject(data)

    def test_helper_or_table_cannot_overlap_writer(self):
        data=fixture();data[1]['bindings']['string-writer']='0x1000';self.reject(data)
        data=fixture();data[2]['packets'][data[3]]['table']='0x2000';self.reject(data)


if __name__=='__main__':
    unittest.main()
