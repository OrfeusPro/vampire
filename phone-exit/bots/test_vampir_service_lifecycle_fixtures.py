"""Adversarial lifecycle fixture tests; no native instructions execute."""
import importlib.util
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest

TOOLS = Path(__file__).resolve().parent / 'resource-tools' / 'vampir'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), TOOLS / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


MEMORY, PROVIDERS, HARNESS, RUNTIME = (load('service-lifecycle-' + name)
    for name in ('memory','providers','harness','runtime'))


class RawMemory:
    def __init__(self): self.data = {}
    def mem_read(self, at, size): return bytes(self.data.get(at+i,0) for i in range(size))
    def mem_write(self, at, data): self.data.update({at+i:value for i,value in enumerate(data)})


class LifecycleFixtures(unittest.TestCase):
    def setUp(self):
        self.raw=RawMemory(); self.memory=MEMORY.MemoryPolicy(self.raw)
        self.ledger=MEMORY.Ledger(self.memory,0x1000,0x30000,0x5a)
        self.regs=dict(RCX=0,RDX=0,R8=0,R9=0,RSP=0x8008)
        self.finished=[]
        self.state=dict(ledger=self.ledger,provider_caller=('service.assign',0),backend_serial=0,
            native_allocations=[],native_frees=[],callback_present=True,observer_present=False,
            tables=dict(control=0x7000,callback=0x7100),base_sentinel_offsets=(8,0x98,0xd0,0x118),
            base_allocate_index={},reserve_seen=[],iterator_model={'local':'end','global':'end'})
        self.h=SimpleNamespace(uc=self.memory,finish=self.finished.append,scratch=0x50000)
        self.functions={'backend.constructor':'0x144ab1810','backend.destructor':'0x144ab1b50',
            'backend.reset':'0x1445ec070'}
        self.providers=PROVIDERS.Providers(self.h,dict(fixtures={},functions=self.functions),self.state,
            lambda name:self.regs[name],lambda at,size=8:int.from_bytes(self.memory.mem_read(at,size),'little'),None)

    def backend(self):
        return self.ledger.allocate(800,'backend','backend1')

    def test_foreign_wrong_kind_wrong_size_and_double_free_abort(self):
        at=self.ledger.allocate(24,'control','control1')
        for options in (dict(size=23),dict(kind='backend')):
            with self.assertRaisesRegex(ValueError,'wrong-sized or wrong-kind'):
                self.ledger.release(at,**options)
        self.ledger.release(at,size=24,kind='control')
        with self.assertRaisesRegex(ValueError,'retired'):
            self.ledger.release(at)
        with self.assertRaisesRegex(ValueError,'foreign'):
            self.ledger.release(0xdead)

    def test_retirement_keeps_host_snapshot_but_blocks_native_reads(self):
        at=self.ledger.allocate(24,'control','control1')
        self.memory.mem_write(at+8,struct.pack('<II',0,0))
        self.ledger.release(at)
        self.assertEqual(self.ledger.bytes(at)[8:16],bytes(8))
        with self.assertRaisesRegex(ValueError,'retired'):
            self.memory.readable(at,1,native=True)

    def test_native_read_cannot_reach_object_guard(self):
        at=self.backend()
        self.memory.readable(at,800,native=True)
        with self.assertRaisesRegex(ValueError,'outside'):
            self.memory.readable(at+799,2,native=True)
        with self.assertRaisesRegex(ValueError,'outside'):
            self.memory.readable(at-1,1,native=True)

    def test_source_ring_receiver_resolves_exact_embedded_backend_member(self):
        backend=self.backend()
        self.assertEqual(RUNTIME.source_backend_receiver(self.ledger,
            'backend.string_ring_clear',backend+0x98),backend)

    def test_source_ring_receiver_rejects_other_offsets_including_backend_base(self):
        backend=self.backend()
        for offset in (0,0x90,0x97,0x99,0xa0):
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError,'ring receiver alias'):
                RUNTIME.source_backend_receiver(self.ledger,'backend.string_ring_clear',backend+offset)

    def test_source_ring_receiver_rejects_wrong_typed_extent(self):
        for kind,size in (('backend',784),('backend',816),('service',800)):
            with self.subTest(kind=kind,size=size):
                at=self.ledger.allocate(size,kind,kind+str(size))
                with self.assertRaisesRegex(ValueError,'ring receiver alias/owner'):
                    RUNTIME.source_backend_receiver(self.ledger,'backend.string_ring_clear',at+0x98)

    def test_source_ring_receiver_rejects_foreign_retired_and_partial_spans(self):
        backend=self.backend()
        for pointer in (0xdead,backend+799):
            with self.subTest(pointer=pointer),self.assertRaisesRegex(ValueError,'no live typed owner'):
                RUNTIME.source_backend_receiver(self.ledger,'backend.string_ring_clear',pointer)
        self.ledger.release(backend)
        with self.assertRaisesRegex(ValueError,'no live typed owner'):
            RUNTIME.source_backend_receiver(self.ledger,'backend.string_ring_clear',backend+0x98)

    def test_source_whole_backend_receivers_accept_only_exact_live_typed_base(self):
        backend=self.backend()
        roles=('backend.constructor','backend.base_constructor','backend.deleting',
            'backend.destructor','backend.base_destructor','backend.reset')
        for role in roles:
            with self.subTest(role=role):
                self.assertEqual(RUNTIME.source_backend_receiver(self.ledger,role,backend),backend)
                with self.assertRaisesRegex(ValueError,'foreign, retired, wrong-sized or wrong-kind'):
                    RUNTIME.source_backend_receiver(self.ledger,role,backend+0x98)
        self.ledger.release(backend)
        with self.assertRaisesRegex(ValueError,'retired'):
            RUNTIME.source_backend_receiver(self.ledger,roles[0],backend)

    def test_source_whole_backend_receiver_rejects_wrong_type_size_and_unknown_role(self):
        for kind,size in (('backend',784),('service',800)):
            with self.subTest(kind=kind,size=size):
                at=self.ledger.allocate(size,kind,kind+str(size))
                with self.assertRaisesRegex(ValueError,'wrong-sized or wrong-kind'):
                    RUNTIME.source_backend_receiver(self.ledger,'backend.reset',at)
        with self.assertRaisesRegex(ValueError,'receiver role'):
            RUNTIME.source_backend_receiver(self.ledger,'backend.unknown',self.backend())

    def test_guard_corruption_is_detected_before_free(self):
        at=self.backend();self.raw.mem_write(at+800,b'X')
        with self.assertRaisesRegex(ValueError,'guard changed'):
            self.ledger.release(at)

    def test_unknown_storage_mutation_is_detected(self):
        at=self.backend();before={at:self.ledger.bytes(at)}
        self.memory.mem_write(at+799,b'X')
        with self.assertRaisesRegex(ValueError,'unknown owner bytes'):
            MEMORY.verify_preserved(self.ledger,before,[(at,8)],0x5a)
        MEMORY.verify_preserved(self.ledger,before,[(at+799,1)],0x5a)

    def test_new_owner_poison_is_checked_outside_source_writes(self):
        at=self.backend();self.memory.mem_write(at+50,b'X')
        with self.assertRaisesRegex(ValueError,'unknown owner bytes'):
            MEMORY.verify_preserved(self.ledger,{},[(at,8)],0x5a)

    def test_fixture_write_history_tracks_only_scoped_output(self):
        at=self.backend();before=len(self.memory.fixture_writes)
        self.providers.put(at+20,b'abc')
        self.assertEqual(self.memory.fixture_writes[before:],[(at+20,3)])
        self.providers.new_owner(16,'sentinel','ambient')
        self.assertEqual(self.memory.fixture_writes[before:],[(at+20,3)])

    def test_live_owner_audit_rejects_leaked_fixture_managed_sentinel(self):
        at=self.backend();sentinel=self.ledger.allocate(16,'sentinel','backend1.sentinel8')
        with self.assertRaisesRegex(ValueError,'leaked or missing'):
            MEMORY.verify_live_owners(self.ledger,{'backend1'},set(),{})
        MEMORY.verify_live_owners(self.ledger,{'backend1'},{'backend1.sentinel8'},{})
        self.ledger.release(sentinel)
        MEMORY.verify_live_owners(self.ledger,{'backend1'},set(),{})

    def test_live_fixture_audit_rejects_wrong_kind_even_when_name_matches(self):
        at=self.ledger.allocate(16,'callback','global')
        with self.assertRaisesRegex(ValueError,'fixture owner kind'):
            MEMORY.verify_live_owners(self.ledger,set(),set(),{'global':'global_container'})

    def test_allocate_provider_does_not_initialize_native_backend_fields(self):
        self.regs['RCX']=800
        self.providers.allocate();at=self.finished[-1]
        self.assertEqual(self.ledger.record(at)['kind'],'backend')
        self.assertEqual(self.memory.mem_read(at,800),b'\x5a'*800)
        self.assertEqual(self.state['native_allocations'],[800])

    def test_allocate_provider_rejects_unmodelled_extent(self):
        self.regs['RCX']=784
        with self.assertRaisesRegex(ValueError,'size differs'):
            self.providers.allocate()

    def test_native_sized_free_does_not_change_control_counters(self):
        at=self.ledger.allocate(24,'control','control1')
        self.memory.mem_write(at,struct.pack('<QIIQ',0x7000,7,9,0))
        self.state['provider_caller']=('control.deleting',0)
        self.regs.update(RCX=at,RDX=24)
        self.providers.sized_free()
        self.assertEqual(self.ledger.bytes(at)[8:16],struct.pack('<II',7,9))
        self.assertEqual(self.state['native_frees'],[dict(owner='control1',size=24)])

    def test_native_free_rejects_foreign_source_kind(self):
        at=self.backend();self.state['provider_caller']=('control.deleting',0)
        self.regs.update(RCX=at,RDX=800)
        with self.assertRaisesRegex(ValueError,'caller/kind'):
            self.providers.sized_free()

    def test_callback_provider_only_writes_explicit_output_alias(self):
        at=self.backend();self.memory.mem_write(at+0x308,bytes(12))
        before=bytes(self.memory.mem_read(at,800))
        self.regs.update(RCX=48,RDX=at+0x308)
        self.providers.callback_allocate();callback=self.finished[-1]
        after=bytes(self.memory.mem_read(at,800))
        self.assertEqual(after[:0x308],before[:0x308]);self.assertEqual(after[0x314:],before[0x314:])
        self.assertEqual(after[0x308:0x314],struct.pack('<QI',callback,1))
        self.assertEqual(self.memory.mem_read(callback,48),b'\x5a'*48)
        self.assertEqual(self.state['native_allocations'],[])

    def test_callback_allocator_rejects_foreign_output_alias(self):
        at=self.backend();self.regs.update(RCX=48,RDX=at+0x300)
        with self.assertRaisesRegex(ValueError,'output alias'):
            self.providers.callback_allocate()

    def test_absent_callback_provider_leaves_native_output_unchanged(self):
        at=self.backend();self.state['callback_present']=False
        self.memory.mem_write(at+0x308,bytes(12));self.regs.update(RCX=48,RDX=at+0x308)
        self.providers.callback_allocate()
        self.assertEqual(self.finished[-1],0);self.assertEqual(self.memory.mem_read(at+0x308,12),bytes(12))

    def test_callback_destroy_does_not_dereference_retired_service(self):
        service=self.ledger.allocate(240,'service','service');self.ledger.release(service)
        callback=self.ledger.allocate(48,'callback','backend1.callback')
        self.memory.mem_write(callback,struct.pack('<QQQQQQ',0x7100,0,0,service,0,0))
        self.state['provider_caller']=('backend.destructor',0);self.regs.update(RCX=callback,RDX=0)
        self.providers.callback_destroy();self.assertEqual(self.finished[-1],0)

    def test_callback_resize_does_not_fake_pointer_or_count_updates(self):
        at=self.backend();self.memory.mem_write(at+0x308,struct.pack('<QI',123,1))
        self.state['provider_caller']=('backend.destructor',0)
        self.regs.update(RCX=at+0x308,RDX=0,R8=0,R9=16)
        self.providers.callback_resize();self.assertEqual(self.memory.mem_read(at+0x308,12),struct.pack('<QI',123,1))

    def test_observer_provider_preserves_native_container_and_backend_fields(self):
        at=self.backend();self.state['provider_caller']=('backend.constructor',0)
        before=self.memory.mem_read(at,800);self.regs['RCX']=at+0x200
        self.providers.observer_init();after=self.memory.mem_read(at,800)
        self.assertEqual(after[:0x200],before[:0x200]);self.assertEqual(after[0x218:],before[0x218:])
        self.assertEqual(after[0x208:0x210],struct.pack('<Q',0xabc001))

    def test_unmodelled_registration_remove_aborts(self):
        with self.assertRaisesRegex(ValueError,'unmodelled'):
            self.providers.iterator_remove()

    ITERATOR_SITES=(
        ('backend.constructor',0x198,(0x88,0x70,0x58),0x208),
        ('backend.constructor',0x272,(0xa0,0x28,0x40),0x220),
        ('backend.destructor',0xb3,(0x58,0x28,0x40),0x220),
        ('backend.destructor',0x144,(0x58,0x28,0x40),0x208),
        ('backend.reset',0x68,(0x58,0x28,0x40),0x40),
        ('backend.reset',0xfe,(0x58,0x28,0x40),0x58))

    def iterator_setup(self,source=None,stack=None):
        role,site,aliases,pair_offset=source or self.ITERATOR_SITES[0]
        backend=self.backend()
        self.state.update(provider_caller=(role,int(self.functions[role],16)+site),cleanup_find='end')
        self.state['global_container']=self.ledger.allocate(128,'global_container','global')
        container=(backend+8 if pair_offset==0x208 else self.state['global_container']+0x10
            if pair_offset==0x220 else backend+(0xd0 if pair_offset==0x40 else 0x118))
        stack=self.h.scratch+0x38008 if stack is None else stack
        self.regs.update(RSP=stack,R9=backend+pair_offset,
            **dict(zip(('RCX','RDX','R8'),(stack+offset for offset in aliases))))
        self.memory.mem_write(container,struct.pack('<Q',0x12345678))
        self.memory.mem_write(container+0x18,struct.pack('<QQ',4,3))
        self.memory.mem_write(self.regs['RDX'],struct.pack('<QQQ',0x12345678,0,4))
        self.memory.mem_write(self.regs['R8'],struct.pack('<QQQ',0x12345678,0,7))
        return backend

    def reject_iterator_before_reads(self,message):
        writes=list(self.memory.fixture_writes)
        self.providers.number=lambda *args: self.fail('Iterator read happened before argument validation')
        with self.assertRaisesRegex(ValueError,message):
            self.providers.iterator_find()
        self.assertEqual(self.memory.fixture_writes,writes)
        self.assertEqual(self.finished,[])

    def test_iterator_source_aliases_accept_all_six_exact_callsite_frames(self):
        for source in self.ITERATOR_SITES:
            with self.subTest(source=source[:2]):
                self.setUp();self.iterator_setup(source)
                self.providers.iterator_find()
                self.assertEqual(self.finished,[self.regs['RCX']])
                self.assertEqual(self.memory.mem_read(self.regs['RCX'],24),
                    struct.pack('<QQQ',0x12345678,0,7))

    def test_iterator_foreign_control_output_cannot_clobber_counters(self):
        self.iterator_setup()
        control=self.ledger.allocate(24,'control','control1')
        self.memory.mem_write(control,struct.pack('<QIIQ',0x7000,5,7,0))
        before=self.ledger.bytes(control);self.regs['RCX']=control
        self.reject_iterator_before_reads('stack span')
        self.assertEqual(self.ledger.bytes(control),before)
        self.ledger.check_guards()

    def test_iterator_foreign_input_spans_are_rejected_before_reads(self):
        for register in ('RDX','R8'):
            with self.subTest(register=register):
                self.setUp();backend=self.iterator_setup();self.regs[register]=backend
                self.reject_iterator_before_reads('stack span')

    def test_iterator_wrong_stack_aliases_are_rejected_before_reads(self):
        for register in ('RCX','RDX','R8'):
            with self.subTest(register=register):
                self.setUp();self.iterator_setup();self.regs[register]+=1
                self.reject_iterator_before_reads('source stack aliases')

    def test_iterator_unknown_source_callsite_is_rejected_before_reads(self):
        self.iterator_setup();role,site=self.state['provider_caller']
        self.state['provider_caller']=(role,site+1)
        self.reject_iterator_before_reads('callsite')

    def test_iterator_source_callsite_cannot_use_another_pair_offset(self):
        backend=self.iterator_setup();self.regs['R9']=backend+0x220
        self.reject_iterator_before_reads('source pair alias')

    def test_iterator_full_stack_spans_enforce_inclusive_lower_exclusive_upper(self):
        for source in self.ITERATOR_SITES:
            with self.subTest(source=source[:2],boundary='exact upper'):
                self.setUp()
                upper=self.h.scratch+0x3f000
                self.iterator_setup(source,upper-max(source[2])-24)
                self.providers.iterator_find()
                self.assertEqual(self.finished,[self.regs['RCX']])
            with self.subTest(source=source[:2],boundary='one byte past upper'):
                self.setUp()
                upper=self.h.scratch+0x3f000
                self.iterator_setup(source,upper-max(source[2])-23)
                self.reject_iterator_before_reads('stack span')
        self.setUp();self.iterator_setup(stack=self.h.scratch+0x30000)
        self.providers.iterator_find()
        self.assertEqual(self.finished,[self.regs['RCX']])
        self.setUp();self.iterator_setup(stack=self.h.scratch+0x30000-1)
        self.reject_iterator_before_reads('stack span')

    def test_entry_gate_prohibits_provider_driven_hidden_native_calls(self):
        roles={role:index for index,role in enumerate(HARNESS.ROLES,100)}
        gate=HARNESS.EntrySequence(roles);gate.begin_case(['service.publisher','service.assign'])
        gate.enter(roles['service.publisher'])
        with self.assertRaisesRegex(ValueError,'nested'):
            gate.enter(roles['backend.constructor'])
        gate.finish(True)
        with self.assertRaisesRegex(ValueError,'Undeclared'):
            gate.enter(roles['backend.constructor'])
        gate.enter(roles['service.assign']);gate.finish(True)
        self.assertEqual(gate.phase,'complete')

    def test_provider_cannot_shadow_inside_dispatch_capsule(self):
        with self.assertRaisesRegex(ValueError,'shadows'):
            HARNESS.check_fixture_address(0x105,[(0x100,0x115)])


if __name__=='__main__': unittest.main()
