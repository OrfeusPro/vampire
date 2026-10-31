"""Pure dispatcher matrix, native gating and paired-context regressions."""
import copy
from collections import Counter
import importlib.util
from pathlib import Path
import unittest

HERE=Path(__file__).resolve().parent/'resource-tools/vampir'


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


contract=load('login-dispatch-case-contracts');oracle=load('login-dispatch-oracle')


def context():
    return dict(source_sha256='a'*64,family='login-dispatch',format='login-dispatch-v1',
        packet_bytes=352,packet_allocation_bytes=344,owner_bytes=80,node_bytes=40,framing_minimum=5)


def report():
    return dict(schema=1,method='bounded_native',source_sha256='a'*64,
        cases=[oracle.expected_case(spec) for spec in contract.scenarios()],
        framing_precondition='frame_size_at_least_5',initial_context_precondition='active_packet_and_tls_zero',
        **dict.fromkeys(contract.TRUE_FLAGS,True),**dict.fromkeys(contract.FALSE_FLAGS,False))


class DispatchContractTests(unittest.TestCase):
    def test_exact_matrix_groups_and_unique_specs(self):
        rows=contract.scenarios()
        self.assertEqual(len(rows),contract.case_count());self.assertEqual(contract.case_count(),107)
        self.assertEqual(Counter(row['kind'] for row in rows),dict(delivery=81,lookup=16,unknown=8,reuse=2))
        self.assertEqual(len({contract.canonical(row) for row in rows}),107)
        self.assertEqual(Counter(row['group'] for row in rows),dict(composition=77,lookup=16,unknown=8,focused=4,reuse=2))

    def test_proved_child_vectors_are_reused_without_running_verifier(self):
        rows=contract.scenarios()[:77]
        self.assertEqual([row['composition'] for row in rows],contract.COMPOSITION.scenarios())
        for row in rows:
            expected=oracle.expected_case(row);child=contract.COMPOSITION.expected_case(row['composition'])
            self.assertEqual(expected['reader'],child['reader']);self.assertEqual(expected['handler'],child['handler'])
            self.assertEqual(len(contract.frame_body(row)),expected['reader']['size'])

    def test_truncated_readers_never_call_handler_wrapper_or_gate(self):
        rows=[row for row in contract.scenarios() if row['kind']=='delivery' and row['composition']['kind']=='truncated']
        self.assertEqual(len(rows),28)
        for row in rows:
            expected=oracle.expected_case(row);d=expected['dispatch']
            self.assertEqual((d['reader_calls'],d['handler_calls'],d['wrapper_calls'],d['gate_calls']),(1,0,0,0))
            self.assertIsNone(expected['handler']);self.assertEqual(d['active_writes'],[])
            self.assertEqual(d['tls_set_calls'],['owner','null'])
            self.assertEqual(d['name_getter_calls'],1);self.assertTrue(d['name_buffer_freed'])

    def test_success_handler_goes_through_native_wrapper_and_actual_tls(self):
        spec=contract.scenarios()[0];row=oracle.expected_case(spec);d=row['dispatch']
        self.assertEqual((d['dispatch_calls'],d['reader_calls'],d['handler_calls'],d['wrapper_calls']),(1,1,1,1))
        self.assertEqual((d['tls_at_reader'],d['tls_at_handler'],d['tls_after']),('owner','owner','null'))
        self.assertEqual((d['active_at_handler'],d['active_after'],d['active_writes']),('packet','null',['packet','null']))
        self.assertEqual(d['archive']['cleanup_chain'],['reader','buffer','archive','base'])

    def test_native_unknown_and_lookup_miss_diagnostics_are_distinct(self):
        unknown=next(s for s in contract.scenarios() if s['kind']=='unknown')
        lookup=next(s for s in contract.scenarios() if s['kind']=='lookup' and s['label']=='empty')
        for spec,line in ((unknown,0xaf8),(lookup,0xadc)):
            d=oracle.expected_case(spec)['dispatch']
            self.assertEqual(d['diagnostics'],[dict(line=line,packet_id=d['packet_id'],name_hex=None)])
            self.assertEqual(d['reader_calls'],0);self.assertIsNone(d['archive']);self.assertEqual(d['tls_set_calls'],[])

    def test_lookup_collision_and_high_byte_keys_return_the_inserted_handler(self):
        rows=[s for s in contract.scenarios() if s['kind']=='lookup']
        self.assertTrue(any(0x100 in s['keys'] for s in rows))
        high=next(s for s in rows if s['label']=='high_byte')
        self.assertEqual(high['query'],0x104)
        for spec in rows:
            d=oracle.expected_case(spec)['dispatch']
            expected='handler_'+str(spec['keys'].index(spec['query'])) if spec['query'] in spec['keys'] else None
            self.assertEqual(d['lookup_returned_handler'],expected)
            self.assertEqual(d['lookup_calls'],1);self.assertEqual(d['dispatch_calls'],0)

    def test_growth_uses_nine_native_insertions_and_rehash_once(self):
        spec=next(s for s in contract.scenarios() if s['group']=='focused' and s['label']=='growth')
        setup=oracle.expected_setup(spec)
        self.assertEqual((setup['register_calls'],setup['insert_calls'],setup['rehash_calls']),(1,9,1))
        self.assertEqual((setup['packet_constructor_calls'],setup['string_constructor_calls']),(1,1))

    def test_pair_reuses_one_native_registration_and_decoded_packet(self):
        rows=[s for s in contract.scenarios() if s['kind']=='reuse']
        self.assertEqual([s['tls_index'] for s in rows],[0,1])
        for spec in rows:
            row=oracle.expected_case(spec)
            self.assertEqual(row['setup']['register_calls'],1);self.assertEqual(row['setup']['packet_constructor_calls'],1)
            self.assertFalse(row['registry_rebuilt']);self.assertFalse(row['packet_reconstructed'])
            self.assertTrue(row['packet_after_failures_unchanged'])
            self.assertEqual([s['spec']['kind'] for s in row['steps']],['delivery','delivery','unknown'])
            self.assertEqual([s['dispatch']['handler_calls'] for s in row['steps']],[1,0,0])
            self.assertEqual(row['steps'][1]['reader']['size'],0)
            self.assertTrue(all('setup' not in step for step in row['steps']))

    def test_framing_is_explicit_precondition_not_native_short_header_rejection(self):
        value=report();contract.validate_report(value,context())
        for key,bad in [('framing_precondition','native_rejects_short_header'),('initial_context_precondition','arbitrary_stale_active')]:
            wrong=copy.deepcopy(value);wrong[key]=bad
            with self.subTest(key=key),self.assertRaises(ValueError):contract.validate_report(wrong,context())

    def test_current_reference_extents_are_distinct_and_old_owner72_fails(self):
        value=report()
        for key,bad in [('owner_bytes',72),('packet_allocation_bytes',352),('packet_bytes',True),('framing_minimum',0)]:
            wrong=context();wrong[key]=bad
            with self.subTest(key=key),self.assertRaises(ValueError):contract.validate_report(value,wrong)

    def test_external_effects_and_diagnostic_utf8_cannot_be_promoted(self):
        value=report()
        for key in contract.FALSE_FLAGS:
            wrong=copy.deepcopy(value);wrong[key]=True
            with self.subTest(key=key),self.assertRaises(ValueError):contract.validate_report(wrong,context())
        for key in contract.TRUE_FLAGS:
            wrong=copy.deepcopy(value);wrong[key]=False
            with self.subTest(key=key),self.assertRaises(ValueError):contract.validate_report(wrong,context())

    def test_missing_duplicate_reordered_or_wrong_handler_rows_are_rejected(self):
        value=report()
        for change in ('missing','duplicate','reordered','handler','count'):
            wrong=copy.deepcopy(value)
            if change=='missing':wrong['cases'].pop()
            if change=='duplicate':wrong['cases'][-1]=copy.deepcopy(wrong['cases'][0])
            if change=='reordered':wrong['cases'][0],wrong['cases'][1]=wrong['cases'][1],wrong['cases'][0]
            if change=='handler':wrong['cases'][0]['handler']['derived']=0
            if change=='count':wrong['cases'][0]['dispatch']['handler_calls']=True
            with self.subTest(change=change),self.assertRaises(ValueError):contract.validate_report(wrong,context())

    def test_same_packet_wrapper_tls_cleanup_and_native_binding_mutations_fail(self):
        spec=contract.scenarios()[0];value=oracle.expected_case(spec)
        edits=[lambda r:r.update(packet_reseeded=True),lambda r:r.update(registry_unchanged=False),
            lambda r:r['dispatch'].update(wrapper_calls=0),lambda r:r['dispatch'].update(tls_at_handler='foreign'),
            lambda r:r['dispatch'].update(active_after='packet'),lambda r:r['dispatch']['archive'].update(final_cursor='body'),
            lambda r:r['dispatch']['archive']['cleanup_chain'].pop(),lambda r:r['setup'].update(bindings_checked=False)]
        for edit in edits:
            wrong=copy.deepcopy(value);edit(wrong)
            with self.subTest(edit=edit),self.assertRaises(ValueError):oracle.validate_case(wrong,spec)

    def test_reuse_cannot_rebuild_registry_or_reseed_after_success(self):
        spec=contract.scenarios()[-1];value=oracle.expected_case(spec)
        for field in ('registry_rebuilt','packet_reconstructed'):
            wrong=copy.deepcopy(value);wrong[field]=True
            with self.subTest(field=field),self.assertRaises(ValueError):oracle.validate_case(wrong,spec)
        wrong=copy.deepcopy(value);wrong['steps'][1]['packet_reseeded']=True
        with self.assertRaises(ValueError):oracle.validate_case(wrong,spec)


if __name__=='__main__':unittest.main()
