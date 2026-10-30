"""Guard the new same-packet composition oracle without executing native code."""
import copy
import struct
import unittest
from unittest.mock import Mock
from test_vampir_update_contracts import load

C = load('login-composition-case-contracts')
V = load('verify-login-composition-context')


def context(): return dict(format='login-response-composition-v1', packet_bytes=352)


def report():
    result = dict(schema=1, method='bounded_native', packet_bytes=352, cases=C.expected_rows(), operations=C.ORDER)
    for flag in ('network_used', 'profile_activated', 'runtime_activated', 'native_dispatch_used',
                 'native_post_state_used', 'native_continuation_used', 'session_executed'): result[flag] = False
    for flag in ('same_packet_reader_used', 'native_handler_used', 'native_gate_used', 'native_strings',
                 'native_buffer_construction', 'native_scalars_used', 'native_nested_used'): result[flag] = True
    return result


class CompositionContractTests(unittest.TestCase):
    def test_exact_matrix_partition_is_48_full_28_partial_and_one_tail(self):
        rows = C.scenarios()
        self.assertEqual(C.case_count(), 77)
        self.assertEqual([sum(r['kind']==kind for r in rows) for kind in ('full','truncated','trailing')], [48,28,1])
        self.assertEqual(len({C.canonical(row) for row in rows}), 77)
        C.validate_report(report(), context())

    def test_wire_order_and_default_body_have_all_20_scalars_and_eight_strings(self):
        body, values, ends = C.encode({})
        self.assertEqual(len(body), 116)
        self.assertEqual(len(C.ORDER),28)
        self.assertEqual(sum(kind=='string' for kind,_ in C.ORDER),8)
        self.assertEqual(len(values),28)
        self.assertEqual(ends[-1],116)
        self.assertEqual(body[:4],bytes(4))
        self.assertEqual(body[4:13],struct.pack('<H',7)+b'fixture')
        self.assertEqual(values[0x130],0xfedcba98)
        self.assertEqual(values[0x134],0x89abcdef)
        self.assertEqual(values[0x58],C.BASE)
        self.assertEqual(values[0x120],C.BASE+7)

    def test_trailing_unicode_and_integer_fields_are_on_wire(self):
        spec = C.scenarios()[40]
        body,values,ends = C.encode(spec['scenario'])
        start = ends[24]
        text = 'новая🙂'.encode('utf-8')
        self.assertEqual(body[start:start+2+len(text)],struct.pack('<H',len(text))+text)
        self.assertEqual(body[-8:],struct.pack('<II',0x89abcdef,0x12345678))
        self.assertEqual(values[0x140],'новая🙂')
        self.assertEqual(C.expected_case(spec)['reader']['strings']['0x140'],'новая🙂')

    def test_partial_cases_end_one_byte_before_each_logical_field_finishes(self):
        _,_,ends = C.encode({}); rows=C.scenarios()[48:76]
        self.assertEqual([r['cut'] for r in rows],[end-1 for end in ends])
        self.assertEqual(len({r['cut'] for r in rows}),28)
        for i,row in enumerate(rows):
            expected=C.expected_case(row)
            self.assertEqual(expected['reader']['operations'],[[k,hex(at)] for k,at in C.ORDER[:i+1]])
            self.assertEqual(expected['reader']['consumed'],row['cut'])
            self.assertIsNone(expected['handler'])
            self.assertIs(expected['handler_invoked'],False)

    def test_tail_uses_reader_consumption_and_same_packet(self):
        row=C.expected_rows()[-1]
        self.assertEqual((row['reader']['size'],row['reader']['consumed']),(121,116))
        self.assertIs(row['handler_invoked'],True)
        self.assertIs(row['same_packet_pointer'],True)

    def test_missing_duplicate_or_reordered_cases_are_rejected(self):
        for mutate in (lambda r:r['cases'].pop(),lambda r:r['cases'].__setitem__(0,r['cases'][1]),
                       lambda r:r['cases'].reverse()):
            r=report();mutate(r)
            with self.assertRaises(ValueError): C.validate_report(r,context())

    def test_rejected_reader_cannot_invoke_or_fabricate_handler(self):
        for key,value in (('handler_invoked',True),('handler',C.expected_rows()[0]['handler']),('same_packet_pointer',True)):
            r=report();r['cases'][48][key]=value
            with self.assertRaises(ValueError): C.validate_report(r,context())

    def test_same_packet_reseed_and_changed_buffers_are_rejected(self):
        for key,value in (('same_packet_pointer',False),('packet_reseeded',True),('source_buffers_unchanged',False),
                          ('packet_unchanged_by_handler',False),('archive_unchanged_by_handler',False)):
            r=report();r['cases'][0][key]=value
            with self.assertRaises(ValueError): C.validate_report(r,context())

    def test_cursor_and_field_projections_are_exact(self):
        for mutate in (lambda r:r['cases'][0]['reader'].__setitem__('consumed',115),
                       lambda r:r['cases'][48]['reader'].__setitem__('consumed',0),
                       lambda r:r['cases'][0]['reader']['scalar_values'].__setitem__('0x130',0),
                       lambda r:r['cases'][40]['reader']['strings'].__setitem__('0x140','wrong')):
            r=report();mutate(r)
            with self.assertRaises(ValueError): C.validate_report(r,context())

    def test_logical_kind_destination_and_operation_count_are_exact(self):
        for mutate in (lambda r:r['cases'][0]['reader']['operations'][0].__setitem__(0,'u16'),
                       lambda r:r['cases'][0]['reader']['operations'][0].__setitem__(1,'0x14'),
                       lambda r:r['cases'][48]['reader']['operations'].append(['string','0x18'])):
            r=report();mutate(r)
            with self.assertRaises(ValueError): C.validate_report(r,context())

    def test_wire_u64_observes_native_time_wrappers_at_their_packet_destination(self):
        packet=0x28001000
        for offset in (0x58,0xb0,0xf0,0x100,0x110,0x120):
            self.assertEqual(V.native_method('u64',offset),'time')
            self.assertTrue(V.logical_entry_matches('time',packet+offset,'u64',offset,packet))
            self.assertFalse(V.logical_entry_matches('u64',packet+offset,'u64',offset,packet))
            self.assertFalse(V.logical_entry_matches('time',0x28037fd0,'u64',offset,packet))
        for offset in (0x68,0x80):
            self.assertEqual(V.native_method('u64',offset),'u64')
            self.assertTrue(V.logical_entry_matches('u64',packet+offset,'u64',offset,packet))
            self.assertFalse(V.logical_entry_matches('time',packet+offset,'u64',offset,packet))
        with self.assertRaises(ValueError): V.native_method('u64',0x88)

    def test_all_other_wire_fields_keep_exact_native_method_and_destination(self):
        packet=0x28001000
        for kind,offset in C.ORDER:
            if kind=='u64': continue
            method='u32' if kind=='raw32' else kind
            self.assertEqual(V.native_method(kind,offset),method)
            self.assertTrue(V.logical_entry_matches(method,packet+offset,kind,offset,packet))
            self.assertFalse(V.logical_entry_matches('time',packet+offset,kind,offset,packet))
            self.assertFalse(V.logical_entry_matches(method,packet+offset+1,kind,offset,packet))
        with self.assertRaises(ValueError): V.native_method('unreviewed',0x10)

    def test_handler_observations_reuse_the_complete_checked_oracle(self):
        r=report();r['cases'][0]['handler']['state']['qwords']['0x38']+=1
        with self.assertRaises(ValueError): C.validate_report(r,context())
        r=report();r['cases'][40]['handler']['events'][3]['returned']=1
        with self.assertRaises(ValueError): C.validate_report(r,context())

    def test_weak_numeric_types_and_guard_flags_are_not_equal_to_native_values(self):
        for key,value in (('returned',True),('size',116.0),('guards',1),('abi',1)):
            r=report();r['cases'][0]['reader'][key]=value
            with self.assertRaises(ValueError): C.validate_report(r,context())

    def test_no_dispatch_service_or_session_scope_can_be_claimed(self):
        for flag in ('network_used','profile_activated','runtime_activated','native_dispatch_used',
                     'native_post_state_used','native_continuation_used','session_executed'):
            for value in (True,0,None):
                r=report();r[flag]=value
                with self.assertRaises(ValueError): C.validate_report(r,context())

    def test_every_claimed_native_component_is_required(self):
        for flag in ('same_packet_reader_used','native_handler_used','native_gate_used','native_strings',
                     'native_buffer_construction','native_scalars_used','native_nested_used'):
            r=report();r[flag]=False
            with self.assertRaises(ValueError): C.validate_report(r,context())

    def test_schema_and_context_layout_are_required(self):
        for change in (dict(schema=True),dict(method='static'),dict(packet_bytes=352.0)):
            with self.assertRaises(ValueError): C.validate_report(dict(report(),**change),context())
        for c in (dict(format='other',packet_bytes=352),dict(format='login-response-composition-v1',packet_bytes=320)):
            with self.assertRaises(ValueError): C.validate_report(report(),c)

    def test_protected_memory_rejects_direct_fixture_writes_including_same_bytes(self):
        native=Mock();memory=V.ProtectedMemory(native);memory.protect([(100,10),(200,20)])
        for at,data in ((100,b'x'),(99,b'xx'),(109,b'x'),(205,bytes(2))):
            with self.assertRaises(ValueError): memory.mem_write(at,data)
        native.mem_write.assert_not_called()
        memory.mem_write(110,b'x');native.mem_write.assert_called_once_with(110,b'x')

    def test_protected_memory_native_hook_and_copy_preflight_share_the_same_guard(self):
        memory=V.ProtectedMemory(Mock());memory.protect([(10,5)])
        with self.assertRaises(ValueError): memory.writable(9,2)
        with self.assertRaises(ValueError): memory.writable(14,2)
        memory.writable(15,4);memory.writable(12,0);memory.protect([]);memory.writable(10,5)

    def test_protected_ranges_reject_bad_bounds(self):
        for ranges in ([(-1,2)],[(0,0)],[(True,1)],[(1,1.0)]):
            with self.assertRaises(ValueError): V.ProtectedMemory(Mock()).protect(ranges)


if __name__=='__main__': unittest.main()
