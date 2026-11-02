"""Source-only lifecycle entry orchestration and actual bounded observations."""
import copy
import importlib.util
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def require(ok, message):
    if not ok:
        raise ValueError(message)


def source_backend_receiver(ledger, role, receiver):
    if role == 'backend.string_ring_clear':
        # Both base_destructor CALL and reset's terminal JMP pass the
        # embedded ring descriptor, not the containing backend object's base.
        base, row = ledger.owner(receiver, 40)
        require(row['kind'] == 'backend' and row['size'] == 800 and receiver - base == 0x98,
                'Lifecycle source ring receiver alias/owner differs')
        return base
    require(role in ('backend.constructor', 'backend.base_constructor', 'backend.deleting',
            'backend.destructor', 'backend.base_destructor', 'backend.reset'),
            'Lifecycle source backend receiver role differs')
    ledger.record(receiver, 800, 'backend')
    return receiver


def install(h, context, contract):
    import unicorn
    memory = load('service-lifecycle-memory')
    policy = memory.MemoryPolicy(h.uc); h.uc = policy
    functions = {key: int(at, 16) for key, at in context['functions'].items()}
    dispatch = int(next(iter(context['leaves'])), 16)
    native = load('build-native-entry-code')
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    decoder.detail = True
    source_rows, returns, edges = {}, {}, {}
    for function in h.fragments:
        role = next(key for key, at in functions.items() if at == int(function['address'], 16))
        for row in function['instructions']:
            at, raw = int(row['address'], 16), bytes.fromhex(row['bytes'])
            ins = next(decoder.disasm(raw, at))
            direct = ins.operands[0].imm if ins.operands and ins.operands[0].type == native.X86_OP_IMM else None
            source_rows[at] = (role, raw, ins)
            if ins.mnemonic == 'call':
                returns[at + ins.size] = (role, at, direct)
            if ins.mnemonic in ('call', 'jmp'):
                edges[at] = (role, at, direct, ins.mnemonic)
    leafraw = bytes.fromhex(context['leaves'][hex(dispatch)])
    for ins in decoder.disasm(leafraw, dispatch):
        source_rows[ins.address] = ('control.dispatch', bytes(ins.bytes), ins)
    state = {}
    entry_roles = {at: role for role, at in functions.items()}; entry_roles[dispatch] = 'control.dispatch'
    globals_ = {key: int(row['address'], 16) for key, row in context['source_globals'].items()}
    tables = {key: int(at, 16) for key, at in context['table_roles'].items()}

    def reg(name):
        return policy.reg_read(getattr(h.x, 'UC_X86_REG_' + name))

    def number(at, size=8, *, host=False):
        data = policy.snapshot(at, size) if host else policy.mem_read(at, size)
        return int.from_bytes(data, 'little')

    def caller(address):
        previous = state.get('previous_native')
        edge = edges.get(previous)
        require(edge is not None, 'Lifecycle provider was not reached from source edge')
        role, at, direct, kind = edge
        require(direct is None or direct == address, 'Lifecycle provider direct target differs')
        if kind == 'call':
            found = returns.get(number(reg('RSP')))
            require(found is not None and found[:2] == (role, at),
                    'Lifecycle provider source return address differs')
        return role, at

    providers = load('service-lifecycle-providers').Providers(h, context, state, reg, number, caller)
    providers.install()
    for at_text, text in context['source_tables'].items():
        at, raw = int(at_text, 16), bytes.fromhex(text)
        for page in range(at & ~4095, ((at + len(raw) - 1) & ~4095) + 4096, 4096):
            h.map_source(page)
        require(bytes(policy.mem_read(at, len(raw))) == raw, 'Lifecycle source table bytes differ')
    for item in context['source_globals'].values():
        at = int(item['address'], 16); h.map_source(at)
        if item['storage'] == 'file':
            require(bytes(policy.mem_read(at, item['size_bytes'])) == bytes.fromhex(item['bytes']),
                    'Lifecycle source global file bytes differ')
        else:
            # PE virtual tail is explicitly declared zero-fill storage.
            require(item['storage'] == 'zero_fill', 'Lifecycle source global storage differs')

    def read_hook(machine, access, address, size, value, unused):
        if h.call_active:
            policy.readable(address, size, native=True)

    def write_hook(machine, access, address, size, value, unused):
        if not h.call_active:
            return
        policy.writable(address, size, native=True)
        row = source_rows.get(state.get('previous_native'))
        if row and row[1].startswith(b'\xf0'):
            base, owner = state['ledger'].owner(address, size)
            require(owner['kind'] in ('control', 'observer_control') and size == 4
                    and address - base in (8, 12), 'Lifecycle atomic target width/owner differs')
            state['atomic_transitions'].append(dict(control=owner['name'],
                field='strong' if address - base == 8 else 'weak',
                before=number(address, 4), after=value & 0xffffffff))
        # Track actual source writes so unknown bytes must retain their input
        # poison outside native/provider-owned writes; no expected output fills.
        if row:
            state['native_writes'].append((address, size))
    policy.hook_add(unicorn.UC_HOOK_MEM_READ, read_hook)
    policy.hook_add(unicorn.UC_HOOK_MEM_WRITE, write_hook)

    def observe(machine, address, size, unused):
        if not h.call_active or not state.get('running'):
            return
        if address in state.get('constructor_returns', {}):
            backend = state['constructor_returns'].pop(address)
            require(reg('RAX') == backend, 'Lifecycle native constructor return alias differs')
            check_constructor(backend)
        if address in entry_roles:
            role = entry_roles[address]
            state['calls'][role] += 1
            if role.startswith('backend.'):
                state['current_backend'] = source_backend_receiver(state['ledger'], role, reg('RCX'))
                if role == 'backend.constructor':
                    state['constructor_returns'][number(reg('RSP'))] = reg('RCX')
                if role == 'backend.reset':
                    require(number(reg('RCX') + 0x148, 4) == 0,
                            'Lifecycle socket provider path is outside bounded scope')
            elif role.startswith('service.'):
                state['ledger'].record(reg('RCX'), 240, 'service')
            elif role in ('control.dispatch', 'control.deleting'):
                state['ledger'].record(reg('RCX'), 24, 'control')
        if address in source_rows:
            state['previous_native'] = address
    policy.hook_add(unicorn.UC_HOOK_CODE, observe)
    abi = {name: 0xfedcba9876543210 + i for i, name in enumerate(
        ('RBX', 'RSI', 'RDI', 'RBP', 'R12', 'R13', 'R14', 'R15'))}
    abi.update({'XMM' + str(i): 0x123456789abcdef0fedcba9876543210 + i for i in range(6, 16)})

    def top(role, receiver, second=0, *, virtual_slot=None):
        require(state['top_roles'][len(state['entries'])] == role, 'Lifecycle top entry order differs')
        target = functions[role]
        if virtual_slot is not None:
            actual = number(number(receiver) + virtual_slot)
            require(actual == target, 'Lifecycle source vtable dispatch target differs')
            target = actual
        policy.mem_write(h.scratch + 0x30000, bytes([state['stack_poison']]) * 0xf000)
        for name, value in abi.items():
            policy.reg_write(getattr(h.x, 'UC_X86_REG_' + name), value)
        before = {at: state['ledger'].bytes(at) for at in state['ledger'].records}
        native_cursor, fixture_cursor = len(state['native_writes']), len(policy.fixture_writes)
        state.update(previous_native=None, running=True)
        try:
            result = h.call(target, receiver, second)
        finally:
            state['running'] = False
        require(reg('RSP') == h.return_stack and all(reg(name) == value for name, value in abi.items()),
                'Lifecycle native Win64 preserved registers/stack differ')
        state['ledger'].check_guards()
        allowed = state['native_writes'][native_cursor:] + policy.fixture_writes[fixture_cursor:]
        memory.verify_preserved(state['ledger'],before,allowed,state['allocator_poison'])
        state['entries'].append(role)
        return result

    def new_owner(size, kind, name):
        return state['ledger'].allocate(size, kind, name)

    def put(at, raw):
        policy.mem_write(at, raw)

    def backend_seed(name='backend1'):
        state['backend_serial'] = max(state['backend_serial'], int(name.removeprefix('backend')))
        return new_owner(800, 'backend', name)

    def control_seed(name, backend, strong=1, weak=1):
        pointer = new_owner(24, 'control', name)
        put(pointer, struct.pack('<QIIQ', tables['control'], strong, weak, backend))
        return pointer

    def object_number(pointer, offset, size=8):
        raw = state['ledger'].bytes(pointer)
        return int.from_bytes(raw[offset:offset + size], 'little')

    def check_constructor(backend):
        ledger = state['ledger']; ledger.record(backend, 800, 'backend')
        require(number(backend) == tables['backend_primary']
                and number(backend + 0x38) == tables['derived_secondary38']
                and number(backend + 0x50) == tables['derived_secondary50']
                and number(backend + 0x200) == tables['derived_observer200']
                and number(backend + 0x218) == tables['derived_observer218'],
                'Lifecycle constructor source vtable fields differ')
        fields = [(0x30,1,1),(0x80,8,0),(0x88,8,15),(0x90,2,0),(0x94,4,0),
            (0xa0,8,0),(0xa8,8,0),(0xb0,8,0),(0xb8,8,0),
            (0xc0,4,0),(0xd8,8,0),(0xe0,8,0),(0xe8,8,0),(0xf0,8,0),(0xf8,1,0),
            (0x100,8,0),(0x108,4,2),(0x120,8,0),(0x128,8,0),(0x130,8,0),(0x138,8,0),
            (0x140,1,0),(0x148,4,0),(0x14c,1,1),(0x158,4,2),(0x15c,4,200),
            (0x160,8,1),(0x168,4,30000),(0x16c,1,0),(0x1e8,8,0),(0x1f0,8,15),
            (0x1f8,1,1),(0x1fc,4,3),
            (0x230,8,0),(0x238,8,0),(0x240,2,0),(0x248,8,0),
            (0x270,4,0),(0x278,8,0),(0x280,8,0),(0x288,4,0),(0x290,8,0),(0x298,8,0),
            (0x2a0,4,0),(0x2a4,2,1),(0x2a6,1,0),(0x2a8,4,0),(0x2b0,4,0),
            (0x2b4,4,0x3f800000),(0x2b8,4,0),(0x2c0,8,0),(0x2d0,8,0),
            (0x300,1,0),(0x308,8,0),(0x310,4,0)]
        require(all(number(backend + offset, size) == value for offset,size,value in fields),
                'Lifecycle constructor source scalar fields differ')
        require(bytes(policy.mem_read(backend+0x70,16)) == bytes(16)
                and bytes(policy.mem_read(backend+0x1d8,16)) == bytes(16)
                and all(bytes(policy.mem_read(backend+offset,24)) == bytes(24)
                    for offset in (0x178,0x198,0x1b8)),
                'Lifecycle constructor source zero vectors/string data differ')
        for offset,key in ((0xc8,'base_containerc8'),(0x110,'base_container110'),
                (0x68,'base_string'),(0x170,'base_vector'),(0x190,'base_vector'),(0x1b0,'base_vector')):
            require(number(backend+offset)==tables[key], 'Lifecycle constructor embedded source vtable differs')
        for offset in (8, 0x98, 0xd0, 0x118):
            sentinel = number(backend + offset)
            ledger.record(sentinel, 16, 'sentinel')
            require(number(sentinel) == backend + offset and number(sentinel + 8) == 0,
                    'Lifecycle native sentinel backlink/initial state differs')

    def assignment_snapshot(service):
        backend, control = number(service + 0x10), number(service + 0x18)
        ledger = state['ledger']; ledger.record(backend, 800, 'backend'); ledger.record(control, 24, 'control')
        callback = None
        pointer = number(backend + 0x308)
        if pointer:
            ledger.record(pointer, 48, 'callback')
            require(number(pointer) == tables['callback'] and number(pointer + 0x20) == tables['callback_handler'],
                    'Lifecycle actual callback vtable/literal copy differs')
            callback = dict(table='callback', service=ledger.name(number(pointer + 0x18)),
                token=number(pointer + 0x10), literal='callback.literal', zero_dword=number(pointer + 0x28,4),
                unknown_dword=number(pointer + 0x2c,4), unwritten_qword=number(pointer + 8))
        require(number(control + 0x10) == backend and number(control) == tables['control'],
                'Lifecycle assigned source control/backend link differs')
        return dict(backend=ledger.name(backend), control=ledger.name(control),
            service_backend=ledger.name(number(service + 0x10)), service_control=ledger.name(number(service + 0x18)),
            backlink=ledger.name(number(backend + 0x230)), strong=number(control + 8,4),
            weak=number(control + 12,4), service_d8=number(service + 0xd8,1),
            backend_state=number(backend + 0x108,4), backend_busy=number(backend + 0xc0,4),
            backend_socket=number(backend + 0x148,4), callback=callback)

    def registration_effect(backend):
        ledger = state['ledger']; local = backend + 8; global_ = state['global_container'] + 0x10
        counts = [number(at + 0x20) for at in (local, global_)]
        pair_written = []
        weak = []
        for container, pair_offset in ((local,0x208),(global_,0x220)):
            count = number(container + 0x20)
            if count:
                index = number(container + 0x18) & (number(container + 0x10) - 1)
                node = number(number(container + 8) + index * 8)
                require(bytes(policy.mem_read(node,16)) == bytes(policy.mem_read(backend + pair_offset,16)),
                        'Lifecycle native inserted observer pair differs')
                pair_written.append(True)
            else:
                pair_written.append(False)
            observer = number(backend + pair_offset + 8)
            weak.append(number(observer + 12,4) if observer else None)
        return dict(local_insert=counts[0] != 0, global_insert=counts[1] != 0,
            reserve=list(state['reserve_seen']), local_count=counts[0], global_count=counts[1],
            local_pair_written=pair_written[0], global_pair_written=pair_written[1],
            local_observer_weak=weak[0], global_observer_weak=weak[1], source_fields_checked=True)

    def seed_queues_ring(backend, spec):
        capacities = {'all_empty':[0,0,0],'first_nonempty':[16,0,0],
            'all_three_nonempty':[16,24,32]}[spec['queues']]
        state['queue_inputs'] = []
        for index,(offset,capacity,length) in enumerate(zip((0x178,0x198,0x1b8),capacities,(3,5,7))):
            if not capacity:
                state['queue_inputs'].append((0,b'')); continue
            pointer = new_owner(capacity, 'queue', 'backend1.queue' + str(index))
            raw = bytes((i * 37 + 11) & 255 for i in range(capacity))
            put(pointer,raw); put(backend + offset,struct.pack('<QQQ',pointer,pointer+length,pointer+capacity))
            state['queue_inputs'].append((pointer,raw))
        if spec['string_ring'] != 'empty':
            map_ = new_owner(32,'ring_map','backend1.ring.map'); put(map_,bytes(32))
            node3 = new_owner(32,'ring_node','backend1.ring.node3')
            node0 = new_owner(32,'ring_node','backend1.ring.node0')
            heap = new_owner(18,'ring_heap','backend1.ring.heap')
            put(heap,b'abcdefghijklmnopq\0')
            put(node3,b'a\0b\0'+bytes(12)+struct.pack('<QQ',3,15))
            put(node0,struct.pack('<QQQQ',heap,0,17,17))
            put(map_,struct.pack('<QQQQ',node0,0,0,node3))
            put(backend+0xa0,struct.pack('<QQQQ',map_,4,3,2))

    def reset_snapshot(backend):
        sizes,caps,begins,bytes_ok = [],[],True,True
        for offset,(pointer,raw) in zip((0x178,0x198,0x1b8),state['queue_inputs']):
            begin,end,limit = struct.unpack('<QQQ',policy.mem_read(backend+offset,24))
            sizes.append(end-begin); caps.append(limit-begin); begins &= begin == pointer
            bytes_ok &= not pointer or bytes(policy.mem_read(pointer,len(raw))) == raw
        return dict(queue_sizes=sizes,queue_capacities=caps,queue_bytes_preserved=bool(bytes_ok),
            queue_begins_preserved=bool(begins),ring_count=number(backend+0xb8),
            ring_start=number(backend+0xb0),ring_map=bool(number(backend+0xa0)),
            ring_capacity=number(backend+0xa8),busy=number(backend+0xc0,4),
            state=number(backend+0x108,4),socket=number(backend+0x148,4))

    def declared_roles(spec):
        group=spec['group']
        if group=='assignment_lifecycle':
            roles=['service.publisher']+['service.assign']*(1 if spec['old_backend']=='none' else 2)
            roles+=['service.deleting']
            if spec['old_backend']=='shared_reference': roles+=['control.move_release']
            return roles
        if group=='control_move_release':
            return (['backend.constructor'] if spec['destination']=='A' else [])+['control.move_release']
        if group=='deleting_flags':
            return (['backend.constructor'] if spec['entry']=='backend.deleting' else [])+[spec['entry']]
        if group=='reset_and_ring_ownership':
            return ['backend.constructor','backend.reset','backend.reset','backend.deleting']
        require(group=='constructor_registration_branches','Lifecycle group unknown')
        return ['backend.constructor','backend.deleting']

    def run_round(spec, poison):
        require(spec['cleanup_find']=='end','Lifecycle cleanup registration input model differs')
        policy.reset(); state.clear()
        static_reads=[(h.scratch+0x30000,0xf000)]+[(int(at,16),len(bytes.fromhex(raw)))
            for at,raw in context['source_tables'].items()]+[(at,8) for at in globals_.values()]
        static_writes=[(h.scratch+0x30000,0xf000),(globals_['singleton'],8)]
        state.update(**poison, calls=dict.fromkeys(contract.CALL_KEYS,0), entries=[],
            native_allocations=[],native_frees=[],atomic_transitions=[],native_writes=[],
            backend_serial=0,current_backend=None,base_allocate_index={},base_sentinel_offsets=(8,0x98,0xd0,0x118),
            callback_present=spec.get('callback_model','absent')!='absent',
            observer_present=spec.get('observer_control','null')!='null',
            iterator_model={'local':'found','global':'found','reset_d0':'end','reset_118':'end'},
            last_find_kind=None,reserve_seen=[],tables=tables,running=False,constructor_returns={},
            cleanup_find=spec['cleanup_find'])
        if 'iterator_fixture' in spec:
            state['iterator_model'].update(local=spec['iterator_fixture']['local'],global_=spec['iterator_fixture']['global_'])
            state['iterator_model']['global']=spec['iterator_fixture']['global_']
        ledger=memory.Ledger(policy,h.scratch+0x50000,h.scratch+0x1e0000,poison['allocator_poison'],static_reads,static_writes)
        state['ledger']=ledger
        put(globals_['singleton'],bytes(8))
        global_ = new_owner(64,'global_container','global')
        put(global_,bytes(64)); state['global_container']=global_
        head = new_owner(16,'fixture_sentinel','global.head'); put(head,bytes(16))
        put(global_+0x10,struct.pack('<Q',head))
        if spec.get('iterator_fixture',{}).get('name')=='both_insert_mixed':
            providers.initialize_registration_storage(global_+0x10,'global.input',4)
        state['top_roles']=declared_roles(spec); h.begin_case(state['top_roles'])
        group=spec['group']
        if group=='assignment_lifecycle':
            service=new_owner(240,'service','service'); top('service.publisher',service)
            require(number(globals_['singleton'])==service and number(service)==tables['service_primary'],
                    'Lifecycle native publisher singleton/vtable differs')
            assignments=[]; old_control=None; external=None
            count=1 if spec['old_backend']=='none' else 2
            for index in range(count):
                if index and spec['old_backend']=='shared_reference':
                    old_control=number(service+0x18)
                    # Explicit input models an independently held external strong
                    # owner, before the next source assignment begins.
                    put(old_control+8,struct.pack('<I',2))
                    external=new_owner(8,'pointer_slot','external');put(external,struct.pack('<Q',old_control))
                top('service.assign',service,virtual_slot=8)
                assignments.append(assignment_snapshot(service))
            top('service.deleting',service,spec['service_delete_flags'],virtual_slot=0)
            if external:
                nullslot=new_owner(8,'pointer_slot','external.null');put(nullslot,bytes(8))
                require(top('control.move_release',external,nullslot)==external,
                        'Lifecycle external native release return alias differs')
            raw=ledger.bytes(service)
            effects=dict(assignments=assignments,singleton_after=ledger.name(number(globals_['singleton'])),
                service_backend_after=ledger.name(int.from_bytes(raw[0x10:0x18],'little')),
                service_control_after=ledger.name(int.from_bytes(raw[0x18:0x20],'little')),
                service_vptr_after='service.base',service_freed=ledger.records[service]['retired'])
            require(int.from_bytes(raw[:8],'little')==tables['service_base'],'Lifecycle final service base vptr differs')
        elif group=='control_move_release':
            backend=0
            if spec['destination']=='A':
                backend=backend_seed();top('backend.constructor',backend);check_constructor(backend)
            controls={}
            if spec['destination']:
                controls[spec['destination']]=control_seed(spec['destination'],backend,spec['old_strong'],spec['old_weak'])
            if spec['source']=='B': controls['B']=control_seed('B',0)
            destination=new_owner(8,'pointer_slot','destination')
            source=destination if spec['source']=='same_slot' else new_owner(8,'pointer_slot','source')
            old=controls.get(spec['destination'],0)
            put(destination,struct.pack('<Q',old))
            if source!=destination: put(source,struct.pack('<Q',controls.get(spec['source'],0)))
            result=top('control.move_release',destination,source)
            effects=dict(destination=ledger.name(number(destination)),source=ledger.name(number(source)),
                return_destination_alias=result==destination,old_strong=object_number(old,8,4) if old else 0,
                old_weak=object_number(old,12,4) if old else 0,
                old_backend_disposed=bool(backend and ledger.records[backend]['retired']),
                old_control_freed=bool(old and ledger.records[old]['retired']))
        elif group=='deleting_flags':
            if spec['entry']=='backend.deleting':
                target=backend_seed();top('backend.constructor',target);check_constructor(target)
                result=top(spec['entry'],target,spec['flags'],virtual_slot=0)
                raw=ledger.bytes(target);require(int.from_bytes(raw[:8],'little')==tables['base_initial'],
                    'Lifecycle backend final root vptr differs');final='backend.root_base'
            else:
                target=control_seed('control1',0);result=top(spec['entry'],target,spec['flags'],virtual_slot=8)
                raw=ledger.bytes(target);require(int.from_bytes(raw[:8],'little')==tables['control_base'],
                    'Lifecycle control final base vptr differs');final='control.base'
            effects=dict(entry=spec['entry'],flags=spec['flags'],returned_alias=result==target,
                freed=ledger.records[target]['retired'],final_table=final)
        elif group=='reset_and_ring_ownership':
            backend=backend_seed();top('backend.constructor',backend);check_constructor(backend)
            seed_queues_ring(backend,spec); snapshots=[]
            for index in range(2):
                top('backend.reset',backend);snapshots.append(reset_snapshot(backend))
            top('backend.deleting',backend,1,virtual_slot=0)
            effects=dict(snapshots=snapshots,queue_storage_native_free=any(
                event['owner'].startswith('backend1.queue') for event in state['native_frees']))
        else:
            backend=backend_seed();top('backend.constructor',backend);check_constructor(backend)
            effects=registration_effect(backend)
            top('backend.deleting',backend,1,virtual_slot=0)
        require(h.entries.phase=='complete' and len(state['entries'])==len(state['top_roles']),
                'Lifecycle declared native entry sequence incomplete')
        ledger.check_guards()
        retained=[]
        if group=='assignment_lifecycle' and not spec['service_delete_flags'] & 1:
            require(not ledger.records[service]['retired'],'Lifecycle retained service storage was freed')
            retained.append(dict(owner='service',reason='destructed_storage'))
        elif group=='control_move_release':
            if old and not ledger.records[old]['retired']:
                retained.append(dict(owner=ledger.name(old),reason='strong_reference'
                    if object_number(old,8,4) else 'external_weak_reference'))
            if backend and not ledger.records[backend]['retired']:
                retained.append(dict(owner='backend1',reason='strong_reference'))
            if spec['source']=='B':
                require(not ledger.records[controls['B']]['retired'],'Lifecycle moved destination control was freed')
                retained.append(dict(owner='B',reason='moved_destination_owner'))
        elif group=='deleting_flags' and not spec['flags'] & 1:
            require(not ledger.records[target]['retired'],'Lifecycle flag0 storage was freed')
            retained.append(dict(owner=ledger.name(target),reason='destructed_storage'))
        elif group=='constructor_registration_branches' and state['observer_present']:
            for locality in ('local','global'):
                name='backend1.'+locality+'_observer';at=ledger.by_name[name]
                ledger.record(at,24,'observer_control')
                retained.append(dict(owner=name,reason='external_weak_reference'))
        retained_names={row['owner'] for row in retained}
        allowed_children=set()
        for row in retained:
            if row['reason']=='strong_reference' and row['owner'].startswith('backend'):
                allowed_children.update(row['owner']+'.sentinel'+format(offset,'x')
                    for offset in (8,0x98,0xd0,0x118))
        fixture_names={'global':'global_container','global.head':'fixture_sentinel'}
        if group=='control_move_release':
            fixture_names['destination']='pointer_slot'
            if spec['source']!='same_slot': fixture_names['source']='pointer_slot'
        if group=='assignment_lifecycle' and spec['old_backend']=='shared_reference':
            fixture_names.update({'external':'pointer_slot','external.null':'pointer_slot'})
        if group=='constructor_registration_branches' and spec['iterator_fixture']['global_']=='end':
            name='global.input.map' if spec['iterator_fixture']['name']=='both_insert_mixed' else 'backend1.global.map'
            fixture_names[name]='registration_map';fixture_names['backend1.global.node']='registration_node'
        memory.verify_live_owners(ledger,retained_names,allowed_children,fixture_names)
        retained_fixtures=[dict(owner=name,kind=fixture_names[name]) for name in sorted(fixture_names)]
        # All retained objects are explicit ambient owners (external refs,
        # service flag0, weak controls, and opaque registration global storage).
        # No synthetic teardown is reported as a native free or counter change.
        return dict(**copy.deepcopy(poison),entries=list(state['entries']),calls=copy.deepcopy(state['calls']),
            effects=effects,native_allocations=list(state['native_allocations']),
            native_frees=copy.deepcopy(state['native_frees']),atomic_transitions=copy.deepcopy(state['atomic_transitions']),
            retained_owners=retained,
            retained_fixture_owners=retained_fixtures,
            **dict.fromkeys(contract.ROUND_CHECKS,True))

    def run(spec):
        contract.validate_spec(spec)
        require(not h.call_active,'Lifecycle case begins during native execution')
        return dict(spec=copy.deepcopy(spec),observation=dict(rounds=[run_round(spec,p) for p in spec['rounds']]))
    return run
