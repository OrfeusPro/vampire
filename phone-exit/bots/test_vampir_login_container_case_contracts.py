"""Pure oracle/admission checks; never execute client code or rebuild knowledge."""
import copy
from collections import Counter
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent/'resource-tools/vampir'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE/(name+'.py'))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


class ContainerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c = load('login-container-case-contracts'); cls.o = load('login-container-oracle')
        cls.scenarios = cls.c.scenarios()

    def spec(self, kind, case=None):
        return next(s for s in self.scenarios if s['kind'] == kind and (case is None or s['case'] == case))

    def report(self):
        context = dict(family='login-container',format='login-container-v1',source_sha256='a'*64,
            packet_bytes=352,packet_allocation_bytes=344,owner_bytes=72,node_bytes=40)
        report = dict(schema=1,method='bounded_native',source_sha256='a'*64,
            cases=[self.o.expected_case(s) for s in self.scenarios],
            **dict.fromkeys(self.c.TRUE_FLAGS,True),**dict.fromkeys(self.c.FALSE_FLAGS,False))
        return context,report

    def test_matrix_is_exact_unique_and_poisoned(self):
        self.assertEqual(Counter(s['kind'] for s in self.scenarios),dict(ctor=68,getter=4,insert=24,rehash=12,fusion=12))
        self.assertEqual(len({self.c.canonical(s) for s in self.scenarios}),120)
        self.assertEqual(self.c.case_count(),120)
        self.assertEqual(Counter(s['poison'] for s in self.scenarios),{85:60,170:60})

    def test_complete_synthetic_report_passes_admission(self):
        context,report = self.report(); self.c.validate_report(report,context)

    def test_null_empty_and_embedded_nul_semantics(self):
        for name in ('null','empty'):
            value=self.o.ctor_expected(self.spec('ctor',name))
            self.assertEqual(value['descriptor'],dict(data='null',num=0,max=0))
            self.assertEqual(value['utf16_hex'],'')
        value=self.o.ctor_expected(self.spec('ctor','embedded_nul'))
        self.assertEqual(value['utf16_hex'],'41000000')
        self.assertEqual(value['descriptor']['num'],2)

    def test_signed_ansi_widening_is_not_utf8(self):
        self.assertEqual(self.o.ctor_expected(self.spec('ctor','signed80'))['utf16_hex'],'80ff0000')
        self.assertEqual(self.o.ctor_expected(self.spec('ctor','signedff'))['utf16_hex'],'ffff0000')
        self.assertEqual(self.o.ctor_expected(self.spec('ctor','signed4'))['utf16_hex'],'80ffffff41000000')

    def test_simd_boundaries_include_nul_and_reserve_capacity(self):
        for size in (1,2,3,14,15,16,17,30,31,32,33):
            for scenario in (s for s in self.scenarios if s['kind']=='ctor' and s['case']=='len'+str(size)):
                value=self.o.ctor_expected(scenario)
                self.assertEqual(value['descriptor']['num'],size+1)
                self.assertEqual(len(bytes.fromhex(value['utf16_hex'])),2*(size+1))
                self.assertEqual(value['descriptor']['max'],size+1 if scenario['capacity']=='exact' else (size+16)//16*16)

    def test_fnv_two_byte_vectors_and_collision_split(self):
        self.assertEqual(self.o.fnv16(4),0x0824f007b4dfe349)
        self.assertEqual([self.o.fnv16(k)&7 for k in (4,12,20,68)],[1,1,1,1])
        self.assertEqual([self.o.fnv16(k)&63 for k in (4,12,20,68)],[9,17,25,9])
        for bad in (-1,65536,True):
            with self.assertRaises(ValueError):self.o.fnv16(bad)

    def test_high_byte_keys_are_hashed_and_graph_checked(self):
        self.assertEqual(self.o.fnv16(0x100),0x08328707b4eb6e3a)
        self.assertEqual(self.o.fnv16(0xffff),0x0a99c907b6f64763)
        self.assertNotEqual(self.o.fnv16(0x104),self.o.fnv16(4))
        self.assertNotEqual(self.o.fnv16(0xffff),self.o.fnv16(255))
        scenario=self.spec('rehash','split')
        self.assertEqual(scenario['keys'],[0x100,0x101,4])
        after=self.o.example_after(scenario);self.o.validate_map(after,scenario)
        correct=self.o.fnv16(0x100)&after['mask'];low_only=self.o.fnv16(0)&after['mask']
        self.assertNotEqual(correct,low_only)
        after['vector']['slots'][2*correct:2*correct+2]=['head','head']
        after['vector']['slots'][2*low_only:2*low_only+2]=['n0','n0']
        with self.assertRaises(ValueError):self.o.validate_map(after,scenario)
        self.assertEqual(self.o.expected_operation(self.spec('insert','higher_load'))['bucket_count'],8)

    def test_duplicate_returns_existing_and_frees_only_candidate(self):
        for name,index in (('duplicate_first',0),('duplicate_middle',1),('duplicate_last',2)):
            scenario=self.spec('insert',name);value=self.o.expected_operation(scenario)
            self.assertEqual(value['returned'],dict(outparam_returned=True,node='n'+str(index),status=0))
            self.assertEqual(value['count'],3)
            self.assertIsNone(value['rehash_requested'])
            self.assertEqual(self.o.expected_events(scenario),[dict(action='node_allocate',bytes=40),
                dict(action='sized_free',allocation='candidate',bytes=40)])

    def test_load_threshold_and_growth_policy(self):
        self.assertEqual(self.o.expected_operation(self.spec('insert','exact_load'))['bucket_count'],8)
        self.assertEqual(self.o.expected_operation(self.spec('insert','growth'))['bucket_count'],64)
        self.assertEqual(self.o.expected_operation(self.spec('insert','growth'))['rehash_requested'],64)
        self.assertEqual(self.o.expected_operation(self.spec('insert','higher_load'))['bucket_count'],8)

    def test_rehash_rounding_and_vector_reuse_preserve_old_extent(self):
        scenario=self.spec('rehash','rounded_shrink');value=self.o.expected_operation(scenario)
        self.assertEqual((value['bucket_count'],value['vector_size'],value['vector_capacity']),(4,16,16))
        self.assertFalse(value['reallocated'])
        after=self.o.example_after(scenario);after['vector']['size']=8;after['vector']['slots']=after['vector']['slots'][:8]
        with self.assertRaises(ValueError):self.o.validate_map(after,scenario)
        value=self.o.expected_operation(self.spec('rehash','minimum'))
        self.assertEqual(value['bucket_count'],2)

    def test_vector_reset_growth_uses_size_even_with_spare_capacity(self):
        scenario=self.spec('rehash','empty_growth');value=self.o.expected_operation(scenario)
        self.assertEqual(scenario['vector_capacity'],32)
        self.assertTrue(value['reallocated'])
        self.assertEqual((value['vector_size'],value['vector_capacity']),(32,32))

    def test_key_payload_and_live_membership_are_checked(self):
        scenario=self.spec('insert','collision_chain');original=self.o.example_after(scenario)
        for mutate in (lambda x:x['nodes'][0].update(packet='different'),lambda x:x['nodes'][0].update(key=65535),
                lambda x:x['nodes'].pop(),lambda x:x['nodes'].append(copy.deepcopy(x['nodes'][0]))):
            value=copy.deepcopy(original);mutate(value)
            with self.assertRaises(ValueError):self.o.validate_map(value,scenario)

    def test_list_cycles_links_and_bucket_ends_are_checked(self):
        scenario=self.spec('insert','collision_chain');original=self.o.example_after(scenario)
        for mutate in (lambda x:x['head'].update(next='missing'),lambda x:x['nodes'][0].update(next=x['nodes'][0]['label']),
                lambda x:x['nodes'][0].update(prev='missing'),lambda x:x['vector']['slots'].__setitem__(2,'head')):
            value=copy.deepcopy(original);mutate(value)
            with self.assertRaises(ValueError):self.o.validate_map(value,scenario)

    def test_node_array_order_is_not_native_iteration_order(self):
        scenario=self.spec('insert','collision_chain');value=self.o.expected_case(scenario)
        value['after']['nodes'].reverse()
        self.o.validate_case(value,scenario)

    def test_valid_global_bucket_order_is_not_overconstrained(self):
        scenario=self.spec('insert','other_bucket');value=self.o.expected_case(scenario);after=value['after']
        ordered=sorted(after['nodes'],key=lambda n:self.o.fnv16(n['key'])&after['mask'],reverse=True)
        labels=['head']+[n['label'] for n in ordered]+['head']
        for i,node in enumerate(ordered):node.update(prev=labels[i],next=labels[i+2])
        after['head'].update(next=labels[1],prev=labels[-2])
        self.o.validate_case(value,scenario)

    def test_collision_member_order_is_not_overconstrained(self):
        scenario=self.spec('insert','collision_chain');value=self.o.expected_case(scenario);after=value['after']
        ordered=list(reversed(after['nodes']));labels=['head']+[n['label'] for n in ordered]+['head']
        for i,node in enumerate(ordered):node.update(prev=labels[i],next=labels[i+2])
        after['head'].update(next=labels[1],prev=labels[-2])
        index=self.o.fnv16(4)&after['mask']
        after['vector']['slots'][2*index:2*index+2]=[labels[1],labels[-2]]
        self.o.validate_case(value,scenario)

    def test_noncontiguous_bucket_members_are_rejected(self):
        scenario=self.spec('insert','collision_growth');value=self.o.example_after(scenario)
        by={n['label']:n for n in value['nodes']};ordered=[n['label'] for n in value['nodes']]
        a,b=[label for label in ordered if self.o.fnv16(by[label]['key'])&value['mask']==9]
        other=next(label for label in ordered if self.o.fnv16(by[label]['key'])&value['mask']!=9)
        ordered.remove(other);ordered.insert(ordered.index(a)+1,other)
        labels=['head']+ordered+['head']
        for i,label in enumerate(ordered):by[label].update(prev=labels[i],next=labels[i+2])
        value['head'].update(next=labels[1],prev=labels[-2])
        with self.assertRaises(ValueError):self.o.validate_map(value,scenario)

    def test_inactive_vector_tail_cannot_point_to_nodes(self):
        scenario=self.spec('rehash','rounded_shrink');value=self.o.example_after(scenario)
        value['vector']['slots'][-1]='n0'
        with self.assertRaises(ValueError):self.o.validate_map(value,scenario)

    def test_fusion_observes_duplicate_name_ownership_separately(self):
        scenario=self.spec('fusion','duplicate_middle');value=self.o.expected_case(scenario)
        self.assertTrue(value['name_descriptor_consumed']);self.assertTrue(value['name_buffer_freed'])
        self.assertFalse(value['payloads_freed'])
        self.assertEqual(value['native_calls'],dict(register=1,insert=1,rehash=0,name_getter=1,string_constructor=1,id_getter=2))
        for key in ('name_descriptor_consumed','name_buffer_freed','payloads_freed'):
            broken=copy.deepcopy(value);broken[key]=not value[key]
            with self.assertRaises(ValueError):self.o.validate_case(broken,scenario)

    def test_matrix_reorder_missing_case_and_duplicate_are_rejected(self):
        context,report=self.report()
        for mode in ('order','missing','duplicate'):
            broken=copy.deepcopy(report)
            if mode=='order':broken['cases'][0],broken['cases'][1]=broken['cases'][1],broken['cases'][0]
            elif mode=='missing':broken['cases'].pop()
            else:broken['cases'][-1]=copy.deepcopy(broken['cases'][0])
            with self.assertRaises(ValueError):self.c.validate_report(broken,context)

    def test_scope_source_and_layout_fail_closed(self):
        context,report=self.report()
        for flag in self.c.TRUE_FLAGS+self.c.FALSE_FLAGS:
            broken=copy.deepcopy(report);broken[flag]=not broken[flag]
            with self.assertRaises(ValueError):self.c.validate_report(broken,context)
        for key in ('packet_bytes','packet_allocation_bytes','owner_bytes','node_bytes'):
            broken=dict(context);broken[key]+=1
            with self.assertRaises(ValueError):self.c.validate_report(report,broken)
        broken=dict(context,source_sha256='b'*64)
        with self.assertRaises(ValueError):self.c.validate_report(report,broken)

    def test_native_counters_events_and_boolean_types_are_strict(self):
        scenario=self.spec('insert','empty');original=self.o.expected_case(scenario)
        for mutate in (lambda x:x['native_calls'].update(insert=True),lambda x:x['native_calls'].update(register=1),
                lambda x:x['events'][0].update(bytes=41),lambda x:x.update(abi=1),
                lambda x:x['returned'].update(status=True),lambda x:x.update(extra='unknown')):
            broken=copy.deepcopy(original);mutate(broken)
            with self.assertRaises(ValueError):self.o.validate_case(broken,scenario)


if __name__ == '__main__': unittest.main()
