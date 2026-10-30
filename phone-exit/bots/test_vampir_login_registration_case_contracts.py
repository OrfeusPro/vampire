"""Strict registration-helper oracle and pre-mutation fixture guards, without native replay."""
import copy
import struct
import unittest
from unittest.mock import Mock,patch
from test_vampir_update_contracts import load

C=load('login-registration-case-contracts')
V=load('verify-login-registration-context')
H=load('verify-login-registration-harness')


def context():return dict(format='login-registration-v1',packet_bytes=352,packet_allocation_bytes=344)


def report():
    r=dict(schema=1,method='bounded_native',cases=C.expected_rows())
    for flag in ('network_used','profile_activated','runtime_activated','native_owner_used','native_window_used',
        'native_packet_constructor_used','native_handler_used','native_insert_backend_used','native_name_getter_used',
        'native_utf8_conversion_used','native_dispatch_used','session_executed'):r[flag]=False
    for flag in ('native_registration_helper_used','native_id_getter_used','name_outparam_unchanged','actual_ownership_unknown'):r[flag]=True
    return r


class RegistrationContractTests(unittest.TestCase):
    def test_exact_34_unique_cases_partition_six_fast_and_28_diagnostics(self):
        rows=C.scenarios();self.assertEqual(len(rows),34);self.assertEqual(C.case_count(),34)
        self.assertEqual([sum(bool(s['insert_status'])==flag for s in rows) for flag in (True,False)],[6,28])
        self.assertEqual(len({C.canonical(r) for r in rows}),34)
        C.validate_report(report(),context())

    def test_fast_nonzero_statuses_use_actual_id_once_and_skip_diagnostics_and_free(self):
        for row in C.expected_rows()[:6]:
            self.assertIn(row['scenario']['insert_status'],(1,2,255))
            self.assertEqual([e['action'] for e in row['events']],['native_id','insert','security'])
            self.assertEqual(row['native_id_calls'],1);self.assertFalse(row['current_pair_freed'])
            self.assertFalse(row['original_packet_freed'])

    def test_diagnostic_current_pair_output_independent_from_original_packet(self):
        for row in C.expected_rows()[6:]:
            insert=next(e for e in row['events'] if e['action']=='insert')
            self.assertEqual(insert['original_packet'],'input_packet')
            self.assertEqual(insert['original_handler'],'input_handler')
            self.assertTrue(insert['input_captured_before_output'])
            self.assertEqual(row['current_pair_freed'],row['scenario']['current_pair_nonnull'])
            self.assertFalse(row['original_packet_freed'])
            frees=[e for e in row['events'] if e['call_offset']==358]
            if frees:self.assertEqual(frees[0]['origin'],'insert_out_pointer_preserved_by_name_fixture')

    def test_name_fixture_external_descriptor_does_not_claim_actual_outparam_or_ownership(self):
        for row in C.expected_rows()[6:]:
            e=next(e for e in row['events'] if e['action']=='name')
            self.assertEqual(e['returned_descriptor'],'external_fixture');self.assertTrue(e['name_outparam_unchanged'])
        for flag in ('name_outparam_unchanged','actual_ownership_unknown'):
            r=report();r[flag]=False
            with self.assertRaises(ValueError):C.validate_report(r,context())

    def test_positive_count_null_pointer_skips_length_conversion_and_logs_null(self):
        rows=[r for r in C.expected_rows() if r['scenario']['name_variant']=='null_pointer']
        for r in rows:
            actions=[e['action'] for e in r['events']]
            self.assertNotIn('utf8_length',actions);self.assertNotIn('utf8_convert',actions)
            self.assertIsNone(next(e for e in r['events'] if e['action']=='log')['utf8_hex'])

    def test_zero_count_fallback_and_nonnull_empty_have_distinct_descriptors_but_same_empty_log(self):
        rows=C.expected_rows();zero=next(r for r in rows if r['scenario']['name_variant']=='zero_count_fallback')
        empty=next(r for r in rows if r['scenario']['name_variant']=='nonnull_empty')
        za=next(e for e in zero['events'] if e['action']=='name');ea=next(e for e in empty['events'] if e['action']=='name')
        self.assertEqual((za['descriptor_count'],za['descriptor_pointer']),(0,'ignored_nonnull'))
        self.assertEqual((ea['descriptor_count'],ea['descriptor_pointer']),(1,'name_buffer'))
        for r in (zero,empty):
            length=next(e for e in r['events'] if e['action']=='utf8_length')
            self.assertEqual((length['utf16_units'],length['utf8_bytes']),(0,0))
            self.assertEqual(next(e for e in r['events'] if e['action']=='log')['utf8_hex'],'')

    def test_native_scan_units_and_fixture_utf8_length_differ_for_unicode(self):
        row=next(r for r in C.expected_rows() if r['scenario']['name_variant']=='unicode')
        length=next(e for e in row['events'] if e['action']=='utf8_length')
        self.assertEqual((length['utf16_units'],length['utf8_bytes']),(4,9))
        convert=next(e for e in row['events'] if e['action']=='utf8_convert')
        self.assertEqual((convert['utf16_units_with_nul'],convert['capacity']),(5,10))

    def test_128_byte_capacity_is_stack_and_129_is_allocated_and_freed(self):
        for variant,allocated in (('ascii127',False),('ascii128',True)):
            row=next(r for r in C.expected_rows() if r['scenario']['name_variant']==variant)
            self.assertIs(row['diagnostic_allocated'],allocated);self.assertIs(row['diagnostic_freed'],allocated)
            convert=next(e for e in row['events'] if e['action']=='utf8_convert')
            self.assertEqual(convert['capacity'],128+int(allocated))
            self.assertEqual(convert['destination'],'heap' if allocated else 'stack')
            self.assertEqual(any(e['call_offset']==343 for e in row['events']),allocated)

    def test_every_diagnostic_calls_real_id_twice_with_id_four(self):
        for row in C.expected_rows()[6:]:
            calls=[e for e in row['events'] if e['action']=='native_id']
            self.assertEqual([e['call_offset'] for e in calls],[59,290])
            self.assertEqual([e['packet_id'] for e in calls],[4,4])

    def test_missing_duplicate_and_reordered_cases_rejected(self):
        for modify in (lambda r:r['cases'].pop(),lambda r:r['cases'].__setitem__(0,r['cases'][1]),lambda r:r['cases'].reverse()):
            r=report();modify(r)
            with self.assertRaises(ValueError):C.validate_report(r,context())

    def test_status_byte_and_poison_types_are_exact(self):
        for key,value in (('insert_status',True),('poison',85.0),('current_pair_nonnull',1)):
            r=report();r['cases'][0]['scenario'][key]=value
            with self.assertRaises(ValueError):C.validate_report(r,context())

    def test_exact_event_args_call_sites_and_order_required(self):
        for modify in (lambda r:r['cases'][0]['events'][0].__setitem__('packet_id',5),
            lambda r:r['cases'][0]['events'][1].__setitem__('owner_offset',16),
            lambda r:r['cases'][0]['events'][1].__setitem__('call_offset',90),
            lambda r:r['cases'][0]['events'].reverse()):
            r=report();modify(r)
            with self.assertRaises(ValueError):C.validate_report(r,context())

    def test_name_boundary_and_cleanup_origin_cannot_be_weakened(self):
        for modify in (lambda r:r['cases'][6]['events'][2].__setitem__('name_outparam_unchanged',False),
            lambda r:r['cases'][-1]['events'][-2].__setitem__('origin','original_packet')):
            r=report();modify(r)
            with self.assertRaises(ValueError):C.validate_report(r,context())

    def test_memory_and_abi_guards_required(self):
        for key in ('packet_unchanged','handler_unchanged','owner_unchanged','name_buffer_unchanged','guards','abi'):
            r=report();r['cases'][0][key]=False
            with self.assertRaises(ValueError):C.validate_report(r,context())

    def test_no_service_dispatch_or_online_scope_can_be_claimed(self):
        for flag in ('network_used','profile_activated','runtime_activated','native_owner_used','native_window_used',
            'native_packet_constructor_used','native_handler_used','native_insert_backend_used','native_name_getter_used',
            'native_utf8_conversion_used','native_dispatch_used','session_executed'):
            for value in (True,0,None):
                r=report();r[flag]=value
                with self.assertRaises(ValueError):C.validate_report(r,context())

    def test_required_native_components_and_context_extents(self):
        for flag in ('native_registration_helper_used','native_id_getter_used'):
            r=report();r[flag]=False
            with self.assertRaises(ValueError):C.validate_report(r,context())
        for change in (dict(packet_bytes=344),dict(packet_allocation_bytes=352),dict(format='legacy-reviewed-registration')):
            with self.assertRaises(ValueError):C.validate_report(report(),dict(context(),**change))

    def test_schema_and_method_reject_weak_types(self):
        for change in (dict(schema=True),dict(method='static')):
            with self.assertRaises(ValueError):C.validate_report(dict(report(),**change),context())

    def test_insertion_original_tuple_is_captured_before_fixture_output_mutation(self):
        packet,handler=0x28001000,0x28003000
        pair=bytearray(struct.pack('<QQ',packet,handler));entry=struct.pack('<H',4)+bytes(6)+bytes(pair)
        captured=V.insertion_input(bytes(pair),entry,packet,handler)
        pair[:8]=bytes(8);pair[8]=255
        self.assertTrue(captured['input_captured_before_output']);self.assertEqual(captured['original_packet'],'input_packet')
        with self.assertRaises(ValueError):V.insertion_input(bytes(pair),entry,packet,handler)

    def test_insertion_guard_rejects_wrong_id_or_pointer_tuple(self):
        packet,handler=0x28001000,0x28003000;pair=struct.pack('<QQ',packet,handler)
        entry=struct.pack('<H',4)+bytes(6)+pair
        for other_pair,other_entry in ((bytes(16),entry),(pair,bytes(24)),(pair,entry[:-1]),(pair,struct.pack('<H',5)+entry[2:])):
            with self.assertRaises(ValueError):V.insertion_input(other_pair,other_entry,packet,handler)

    def test_harness_rejects_extra_roots_and_self_declared_native_scope_before_source_access(self):
        base=dict(family='login-registration',transfer_proof={'proof':True},functions={'register':'0x140001000'},
            leaves={'0x140002000':'b804000000c3'},exports={'run-x':'a'*64})
        with patch.object(H,'load',side_effect=AssertionError('No source access')):
            for context_,roots in ((base,{0x140001000,0x140003000}),(dict(base,function_budget=32),{0x140001000}),
                (dict(base,family='unknown'),{0x140001000}),(dict(base,transfer_proof=None),{0x140001000})):
                with self.assertRaises(ValueError):H.admit(context_,'root',roots,{0x140002000:'b804000000c3'},base['exports'])

    def test_call_site_guard_distinguishes_three_byte_virtual_and_five_byte_direct_calls(self):
        start=0x1467cebc0;target=0x1467b77e0
        calls={hex(start+59):'qword ptr [rax + 0x28]',hex(start+126):'qword ptr [rax + 0x38]',hex(start+91):hex(target)}
        for name,offset,size in (('native_id',59,3),('name_getter',126,3),('insert',91,5)):
            self.assertEqual(V.call_site(start+offset+size,start,name,target,calls),offset)
            with self.assertRaises(ValueError):V.call_site(start+offset+(5 if size==3 else 3),start,name,target,calls)
        with self.assertRaises(ValueError):V.call_site(start+126+3,start,'native_id',target,calls)
        with self.assertRaises(ValueError):V.call_site(start+91+5,start,'insert',target+1,calls)


if __name__=='__main__':unittest.main()
