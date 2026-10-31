"""Whole native container insertion/rehash and real name descriptor ownership."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE/(name+'.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


def call_site(return_address, functions, calls, target, *, indirect=None):
    """A concrete return address must identify exactly one reviewed call site."""
    site = return_address-(3 if indirect else 5)
    wanted = indirect if indirect else hex(target)
    found = [(role, site-int(functions[role], 16)) for role, entries in calls.items()
        if entries.get(hex(site)) == wanted]
    if len(found) != 1: raise ValueError('Container concrete caller/operand differs')
    return found[0]


def vector_reset_plan(begin, end, capacity_end, requested, fresh):
    """Synthetic storage boundary; reuse fills the old range without truncation."""
    if (any(type(n) is not int for n in (begin, end, capacity_end, requested, fresh))
            or begin <= 0 or begin % 8 or fresh <= 0 or fresh % 8 or not begin <= end <= capacity_end or (end-begin) % 8
            or (capacity_end-begin) % 8 or requested < 4 or requested > 128 or requested % 2):
        raise ValueError('Container vector reset bound differs')
    old_size = (end-begin)//8
    if old_size >= requested:
        return dict(begin=begin, end=end, capacity_end=capacity_end, filled=old_size, reallocated=False)
    return dict(begin=fresh, end=fresh+requested*8, capacity_end=fresh+requested*8,
        filled=requested, reallocated=True)


def signed_units(data):
    """Only an assertion helper; output bytes always come from native memory."""
    return b''.join(struct.pack('<H', (byte if byte < 128 else byte-256) & 0xffff) for byte in data)


def verify(context, root):
    contract = load('login-container-case-contracts'); oracle = load('login-container-oracle')
    roots = {int(at, 16) for at in context['functions'].values()}
    h = load('verify-login-container-harness').make_harness(context, context['exports'], roots,
        leaves={int(at, 16): code for at, code in context['leaves'].items()}, root=root)
    h.uc = load('verify-login-container-harness').MemoryPolicy(h.uc)
    uc, x = h.uc, h.x
    import unicorn
    functions = {role: int(at, 16) for role, at in context['functions'].items()}
    id_getter = int(context['bindings']['id_getter'], 16)
    fixtures = {int(at, 16): role for role, at in context['fixtures'].items()}
    if len(fixtures) != 13 or set(fixtures) & (roots | {id_getter}):
        raise ValueError('Container fixture aliases native code')
    packet, owner, handler, descriptor, source_buffer, name_heap, entry, outpair, candidate, head, nodes = [
        h.scratch+n for n in (0x1000,0x2000,0x3000,0x4000,0x5001,0x6002,0x7000,0x8000,0x9000,0xa000,0xb000)]
    previous = h.scratch+0x4800
    vector_a, vector_b = h.scratch+0x10000, h.scratch+0x18000
    mapping = owner+8
    state, events, immutable, boxes = {}, [], [], []

    def require(ok, message):
        if not ok: raise ValueError(message)
    def reg(name): return uc.reg_read(getattr(x, 'UC_X86_REG_'+name))
    def put(at, fmt, *values): uc.mem_write(at, struct.pack('<'+fmt, *values))
    def number(at, size=8): return int.from_bytes(uc.mem_read(at, size), 'little')
    def source_page(at):
        page = at & ~4095
        if not any(low <= page <= high for low, high, _ in uc.mem_regions()):
            uc.mem_map(page, 4096); offset = h.image.offset(page-h.image.pe.base)
            uc.mem_write(page, h.raw[offset:offset+4096])
    def map_source(at, size):
        for page in range(at & ~4095, (at+size-1 & ~4095)+4096, 4096): source_page(page)
    table = int(context['bindings']['packet_table'], 16)
    map_source(table, 0x40)
    require(number(table+0x28) == id_getter and number(table+0x38) == functions['name_getter'],
        'Container packet virtual slots differ')
    cookie = int(context['globals']['cookie'], 16); map_source(cookie, 8); cookie_value = number(cookie)
    source_regions = [(table, 0x40), (cookie, 8)]
    literals = {}
    for role, value in dict(context['literals'], **context['extra_data']).items():
        at, data = int(value['address'], 16), bytes.fromhex(value['bytes'])
        map_source(at, len(data)); require(bytes(uc.mem_read(at, len(data))) == data, 'Container typed source bytes differ')
        literals[role] = at; source_regions.append((at, len(data)))
    packet_name = bytes.fromhex(context['extra_data']['packet_name']['bytes'])
    require(packet_name == b'PktLoginResult\0', 'Container source packet name differs')

    def box(at, size, poison):
        require(size > 0 and not any(at-16 < old+length+16 and at+size+16 > old-16 for old, length in boxes),
            'Container fixture boxes overlap')
        uc.mem_write(at-16, b'\xa5'*16+bytes([poison])*size+b'\xa6'*16); boxes.append((at, size))
    def protect(at, size):
        immutable.append((at, uc.snapshot(at, size))); uc.protect([(at, size)])
    def native_windows():
        values = [(h.scratch+0x28000, 0x10200)]
        if state['kind'] in ('ctor','getter'): values.append((descriptor, 16))
        else:
            values += [(mapping+0x10,8),(mapping+0x30,16),(head,16),(outpair,16)]
            values += [(at,16) for label,at in state['node_at'].items() if label not in ('head','candidate')]
            if state['candidate_allocated']: values.append((candidate,40))
            if state['vector']:
                begin, end, _ = state['vector']; values.append((begin, end-begin))
            if state.get('insert_pair'): values.append((state['insert_pair'],16))
        if state['name_capacity']: values.append((name_heap, state['name_capacity']*2))
        uc.native_allow(values)
    def label_node(at):
        require(at in state['node_label'], 'Container native node pointer is foreign')
        return state['node_label'][at]
    def label_payload(at):
        require(at in state['payload_labels'], 'Container native payload pointer is foreign')
        return state['payload_labels'][at]
    def descriptor_value(at):
        data, num, maximum = struct.unpack('<QII', bytes(uc.mem_read(at,16)))
        require(data in (0,name_heap) and num <= maximum <= 256, 'Container native name descriptor extent differs')
        require((data == 0) == (num == maximum == 0), 'Container native name null descriptor differs')
        raw = bytes(uc.mem_read(data,num*2)) if num else b''
        return dict(data='name_heap' if data else 'null',num=num,max=maximum), raw
    def observe_insert_result(at, returned):
        pointer = number(at); flag = number(at+8,1)
        require(returned == at and flag in (0,1), 'Container native insert outparam/result differs')
        return dict(outparam_returned=True,node=label_node(pointer),status=flag)
    def snapshot_map():
        count = number(mapping+0x10); bucket_count = number(mapping+0x38); mask = number(mapping+0x30)
        begin, end, cap = (number(mapping+off) for off in (0x18,0x20,0x28))
        require(0 <= count <= 9 and 2 <= bucket_count <= 64 and begin in (vector_a,vector_b)
            and begin <= end <= cap <= begin+128*8 and (end-begin)%8 == 0 and (cap-begin)%8 == 0,
            'Container native map/vector extent differs')
        visited = []; at = number(head)
        while at != head:
            require(at in state['node_label'] and at not in visited and len(visited) < 9,
                'Container native list cycle/foreign node differs')
            require(at != candidate or state['candidate_allocated'] and not state['candidate_freed'],
                'Container native list contains retired candidate')
            visited.append(at); at = number(at)
        result = []
        for at in visited:
            result.append(dict(label=label_node(at),key=number(at+0x10,2),packet=label_payload(number(at+0x18)),
                handler=label_payload(number(at+0x20)),next=label_node(number(at)),prev=label_node(number(at+8))))
        return dict(count=count,bucket_count=bucket_count,mask=mask,
            load_factor_bits=f'{number(mapping,4):08x}',head=dict(next=label_node(number(head)),prev=label_node(number(head+8))),
            vector=dict(size=(end-begin)//8,capacity=(cap-begin)//8,
                slots=[label_node(number(at)) for at in range(begin,end,8)]),nodes=result)

    def fixture(machine, role):
        a,b,c,d = (reg(name) for name in ('RCX','RDX','R8','R9'))
        stack = reg('RSP'); require(stack & 15 == 8, 'Container fixture Win64 stack alignment differs')
        caller, offset = call_site(number(stack), context['functions'], context['call_sites'],
            int(context['fixtures'][role],16))
        writes = []
        if role in ('diagnostic_allocate','name_grow','name_failure','container_failure'):
            raise ValueError('Container unexpected growth/fatal/diagnostic heap boundary: '+role)
        if role == 'bucket_reset':
            require(caller == 'rehash' and offset == 87 and a == mapping+0x18 and c == head,
                'Container vector storage fixture caller/arguments differ')
            require(not state['vector_reset'], 'Container repeated vector reset differs')
            begin,end,cap = (number(mapping+off) for off in (0x18,0x20,0x28))
            plan = vector_reset_plan(begin,end,cap,b,vector_b)
            writes = [(plan['begin'],plan['filled']*8)]
            if plan['reallocated']: writes.append((mapping+0x18,24))
        elif role == 'name_reserve':
            require(caller == 'string_constructor' and offset == 90 and a == state['name_descriptor']
                and b == len(state['ansi'])+1 and state['ansi'] and bytes(uc.mem_read(a,16)) == bytes(16)
                and not state['name_capacity'], 'Container fresh reserve fixture caller/descriptor differs')
            capacity = b if state['scenario']['capacity'] == 'exact' else (b+15)//16*16
            require(capacity == state['prepared_name_capacity'], 'Container name heap prepared extent differs')
            writes = [(a,8),(a+12,4)]
        elif role == 'utf8_convert':
            require(caller == 'register' and offset == 275 and (b&0xffffffff,c,d&0xffffffff) == (15,name_heap,15)
                and a == stack+0x68, 'Container UTF8 conversion fixture caller/arguments differ')
            writes = [(a,15)]
        uc.begin_fixture(writes)
        try:
            if role == 'node_allocate':
                require(caller == 'insert' and offset == 44 and a == 40 and not state['candidate_allocated'],
                    'Container node allocation fixture caller/size differs')
                state['candidate_allocated'] = True; native_windows()
                events.append(dict(action='node_allocate',bytes=40)); h.finish(candidate)
            elif role == 'node_free':
                require(caller == 'insert' and offset == 196 and a == candidate and b == 40
                    and state['candidate_allocated'] and not state['candidate_freed'],
                    'Container sized-free fixture ownership differs')
                state['candidate_freed'] = True; uc.retire(candidate,40)
                events.append(dict(action='sized_free',allocation='candidate',bytes=40)); h.finish()
            elif role == 'bucket_reset':
                uc.mem_write(plan['begin'],struct.pack('<Q',head)*plan['filled'])
                if plan['reallocated']:
                    put(mapping+0x18,'QQQ',plan['begin'],plan['end'],plan['capacity_end'])
                    uc.retire(begin,cap-begin)
                state['vector'] = (plan['begin'],plan['end'],plan['capacity_end']); state['vector_reset'] = True
                native_windows()
                if plan['filled'] > b: uc.protect([(plan['begin']+b*8,(plan['filled']-b)*8)])
                events.append(dict(action='vector_reset',slots=b,reallocated=plan['reallocated'])); h.finish(a)
            elif role == 'name_reserve':
                put(a,'Q',name_heap); put(a+12,'I',capacity)
                state['name_capacity'] = capacity; native_windows()
                events.append(dict(action='reserve',requested=b,capacity=capacity)); h.finish()
            elif role == 'utf8_length':
                require(caller == 'register' and offset == 193 and (a,b,c&0xffffffff) == (0,name_heap,14)
                    and bytes(uc.mem_read(name_heap,30)) == signed_units(packet_name),
                    'Container UTF8 length fixture input differs')
                events.append(dict(action='utf8_length',utf16_units=14,utf8_bytes=14)); h.finish(14)
            elif role == 'utf8_convert':
                require(bytes(uc.mem_read(name_heap,30)) == signed_units(packet_name), 'Container native name text changed')
                uc.mem_write(a,packet_name); state['utf8_pointer'] = a
                events.append(dict(action='utf8_convert',utf16_units_with_nul=15,capacity=15,utf8_hex=packet_name[:-1].hex())); h.finish()
            elif role == 'log':
                require(caller == 'register' and offset == 321 and (a,b&0xffffffff,c,d&0xffffffff) ==
                    (literals['log_owner'],0xb27,literals['log_format'],4) and number(stack+0x28) == state['utf8_pointer']
                    and bytes(uc.mem_read(state['utf8_pointer'],15)) == packet_name, 'Container diagnostic logger input differs')
                events.append(dict(action='log',packet_id=4,line=0xb27,utf8_hex=packet_name[:-1].hex())); h.finish()
            elif role == 'free':
                require(caller == 'register' and offset == 358 and a == name_heap and state['name_capacity']
                    and not state['name_freed'] and state['name_consumed'], 'Container name free ownership/repetition differs')
                state['name_freed'] = True; uc.retire(name_heap,state['name_capacity']*2)
                events.append(dict(action='free',allocation='name_heap')); h.finish()
            elif role == 'security':
                require(caller == 'register' and offset == 370 and a == cookie_value, 'Container native stack cookie differs')
                events.append(dict(action='security')); h.finish(reg('RAX'))
            else: raise ValueError('Container unreviewed fixture '+role)
        finally: uc.end_fixture()

    for at, role in fixtures.items(): h.add_fixture(at, lambda machine, role=role: fixture(machine, role))
    reverse_functions = {at:role for role,at in functions.items()}

    def trace(machine, at, size, unused):
        if at in reverse_functions:
            role = reverse_functions[at]; stack = reg('RSP'); return_address = number(stack)
            if role == state['top'] and return_address == h.stop and not state['top_entered']:
                state['top_entered'] = True
            else:
                indirect = 'qword ptr [rax + 0x38]' if role == 'name_getter' else None
                call_site(return_address,context['functions'],context['call_sites'],at,indirect=indirect)
            require(stack & 15 == 8, 'Container native Win64 entry stack alignment differs')
            state['native_calls'][role] += 1
            if role == 'insert':
                pair, incoming = reg('RDX'),reg('R8')
                require(reg('RCX') == mapping and number(incoming,2) == state['scenario']['key']
                    and number(incoming+8) == packet and number(incoming+16) == handler,
                    'Container native insertion input tuple differs')
                state['insert_pair'] = pair; native_windows()
            elif role == 'name_getter':
                require(reg('RCX') == packet, 'Container native name getter receiver differs')
                state['name_descriptor'] = reg('RDX')
                if state['kind'] == 'fusion':
                    require(state['captured_insert'] and state['captured_insert']['status'] == 0
                        and state['name_descriptor'] == state['insert_pair']
                        and bytes(uc.mem_read(state['name_descriptor'],16)) == state['insert_preimage'],
                        'Container name getter did not consume the observed insert outpair')
            elif role == 'string_constructor':
                require(reg('RCX') == state['name_descriptor'] and reg('RDX') == state['source_pointer'],
                    'Container native string constructor input pointers differ')
        elif at == id_getter:
            caller, offset = call_site(number(reg('RSP')),context['functions'],context['call_sites'],at,
                indirect='qword ptr [rax + 0x28]')
            require(caller == 'register' and offset in (59,290) and reg('RCX') == packet,
                'Container actual ID getter receiver/caller differs')
            state['native_calls']['id_getter'] += 1
        if at == functions['insert']+80:
            require(number(candidate+0x10,2) == state['scenario']['key'] and number(candidate+0x18) == packet
                and number(candidate+0x20) == handler, 'Container native candidate key/payload construction differs')
            protect(candidate+0x10,24)
        if at == functions['register']+96:
            state['captured_insert'] = observe_insert_result(state['insert_pair'],reg('RAX'))
            state['insert_preimage'] = bytes(uc.mem_read(state['insert_pair'],16))
        if at == functions['register']+129:
            observed, raw = descriptor_value(state['name_descriptor'])
            require(observed['data'] == 'name_heap' and observed['num'] == 15 and raw == signed_units(packet_name),
                'Container real getter did not produce the packet name descriptor')
            state['name_consumed'] = True; protect(name_heap,state['name_capacity']*2)

    uc.hook_add(unicorn.UC_HOOK_CODE,trace)
    uc.hook_add(unicorn.UC_HOOK_MEM_WRITE,lambda machine,access,at,size,value,unused: uc.writable(at,size,native=True))
    uc.hook_add(unicorn.UC_HOOK_MEM_READ,lambda machine,access,at,size,value,unused: uc.readable(at,size))
    abi = {name:0x1122334400000000+i for i,name in enumerate(('RBX','RBP','RSI','RDI','R12','R13','R14','R15'))}
    abi.update({'XMM'+str(i):0x123456789abcdef0fedcba9876543210+i for i in range(6,16)})

    def run(scenario):
        uc.reset(); events.clear(); immutable.clear(); boxes.clear(); state.clear()
        kind, poison = scenario['kind'],scenario['poison']
        state.update(kind=kind,scenario=dict(scenario),top=dict(ctor='string_constructor',getter='name_getter',
            insert='insert',rehash='rehash',fusion='register')[kind],top_entered=False,
            native_calls=dict.fromkeys(oracle.CALL_ROLES,0),candidate_allocated=False,candidate_freed=False,
            vector_reset=False,name_capacity=0,name_freed=False,name_consumed=False,insert_pair=None,
            captured_insert=None,node_at={'head':head,'candidate':candidate},node_label={head:'head',candidate:'candidate'},
            payload_labels={packet:'packet_input',handler:'handler_input'},name_descriptor=descriptor,
            vector=None,utf8_pointer=None)
        uc.mem_write(h.scratch+0x28000,bytes([poison])*0x10200)
        for at,size in ((packet,344),(owner,72),(handler,8),(descriptor,16),(previous,32),(entry,24),(outpair,16),
                (candidate,40),(head,40),(vector_a,128*8),(vector_b,128*8)):
            box(at,size,poison)
        put(packet,'Q',table); put(handler,'Q',int(context['bindings']['handler_table'],16))
        put(descriptor,'Q',previous)
        state['source_pointer'] = 0 if kind == 'ctor' and scenario['source_hex'] is None else source_buffer
        source = bytes.fromhex(scenario['source_hex'])+b'\0' if kind == 'ctor' and scenario['source_hex'] is not None else b'\0'
        if kind in ('getter','fusion'):
            state['source_pointer'] = literals['packet_name']; source = packet_name
        state['ansi'] = source.split(b'\0',1)[0]
        requested = len(state['ansi'])+1 if state['ansi'] else 0
        mode = scenario.get('capacity')
        state['prepared_name_capacity'] = requested if mode == 'exact' else (requested+15)//16*16 if requested else 0
        box(source_buffer,len(source),poison); uc.mem_write(source_buffer,source)
        box(name_heap,max(2,state['prepared_name_capacity']*2),poison)
        if kind in ('insert','rehash','fusion'):
            seed = oracle.seed(scenario)
            for i,node in enumerate(seed['nodes']):
                at = nodes+int(node['label'][1:])*0x100
                state['node_at'][node['label']] = at; state['node_label'][at] = node['label']; box(at,40,poison)
                for role,offset,size in (('packet',0,32),('handler',0x40,16)):
                    payload = h.scratch+0x21000+int(node['label'][1:])*0x100+offset
                    box(payload,size,poison); state['payload_labels'][payload] = node[role]; protect(payload,size)
            payload_at = {label:at for at,label in state['payload_labels'].items()}
            for node in seed['nodes']:
                at = state['node_at'][node['label']]
                put(at,'QQ',state['node_at'][node['next']],state['node_at'][node['prev']])
                put(at+0x10,'H',node['key']); put(at+0x18,'QQ',payload_at[node['packet']],payload_at[node['handler']])
                protect(at+0x10,24)
            put(head,'QQ',state['node_at'][seed['head']['next']],state['node_at'][seed['head']['prev']])
            put(mapping,'I',int(seed['load_factor_bits'],16)); put(mapping+8,'Q',head); put(mapping+0x10,'Q',seed['count'])
            put(mapping+0x18,'QQQ',vector_a,vector_a+seed['vector']['size']*8,vector_a+seed['vector']['capacity']*8)
            put(mapping+0x30,'QQ',seed['mask'],seed['bucket_count'])
            uc.mem_write(vector_a,b''.join(struct.pack('<Q',state['node_at'][label]) for label in seed['vector']['slots']))
            state['vector'] = (vector_a,vector_a+seed['vector']['size']*8,vector_a+seed['vector']['capacity']*8)
            put(entry,'H',scenario.get('key',4)); put(entry+8,'QQ',packet,handler)
            for at,size in ((owner,8),(mapping,8),(mapping+8,8),(head+16,24),(entry,24)):
                protect(at,size)
        for at,size in ((packet,344),(handler,8),(previous,32),(source_buffer,len(source))): protect(at,size)
        for at,size in source_regions: protect(at,size)
        native_windows()
        for name,value in abi.items(): uc.reg_write(getattr(x,'UC_X86_REG_'+name),value)
        for name in ('RAX','RCX','RDX','R8','R9','R10','R11'):
            uc.reg_write(getattr(x,'UC_X86_REG_'+name),int.from_bytes(bytes([poison])*8,'little'))
        if kind == 'ctor': receiver=descriptor; uc.reg_write(x.UC_X86_REG_RDX,state['source_pointer'])
        elif kind == 'getter': receiver=packet; uc.reg_write(x.UC_X86_REG_RDX,descriptor)
        elif kind == 'insert':
            receiver=mapping; uc.reg_write(x.UC_X86_REG_RDX,outpair); uc.reg_write(x.UC_X86_REG_R8,entry)
        elif kind == 'rehash': receiver=mapping; uc.reg_write(x.UC_X86_REG_RDX,scenario['requested'])
        else:
            receiver=owner; uc.reg_write(x.UC_X86_REG_RDX,packet); uc.reg_write(x.UC_X86_REG_R8,handler)
        result = h.call(functions[state['top']],receiver,budget=100000)
        require(state['top_entered'] and all(reg(name) == value for name,value in abi.items()) and reg('RSP') == h.return_stack,
            'Container whole native ABI/return differs')
        require(all(uc.snapshot(at,len(data)) == data for at,data in immutable), 'Container protected input bytes changed')
        require(all(uc.snapshot(at-16,16) == b'\xa5'*16 and uc.snapshot(at+size,16) == b'\xa6'*16 for at,size in boxes),
            'Container allocation/object canary differs')
        row = dict(scenario=dict(scenario),events=list(events),native_calls=dict(state['native_calls']),
            abi=True,guards=True,protected_inputs=True,fixture_writes_bounded=True)
        if kind in ('ctor','getter'):
            observed, raw = descriptor_value(descriptor)
            require(result == descriptor and state['name_capacity'] == observed['max'], 'Container native descriptor return/capacity differs')
            spare = uc.snapshot(name_heap+observed['num']*2,(observed['max']-observed['num'])*2)
            require(spare == bytes([poison])*len(spare), 'Container native constructor writes reserved spare capacity')
            row.update(descriptor=observed,utf16_hex=raw.hex(),spare_unchanged=True,old_pointer_freed=False,outparam_returned=True)
        else:
            row.update(after=snapshot_map(),returned=None if kind == 'rehash' else observe_insert_result(outpair,result)
                if kind == 'insert' else state['captured_insert'])
            if kind == 'fusion': row.update(name_descriptor_consumed=state['name_consumed'],
                name_buffer_freed=state['name_freed'],payloads_freed=False)
        oracle.validate_case(row,scenario)
        return row

    report = dict(schema=1,source_sha256=context['source_sha256'],method='bounded_native',
        cases=[run(s) for s in contract.scenarios()],runtime=load('update-native-harness').runtime_inputs(),evidence=h.evidence,
        **dict.fromkeys(contract.TRUE_FLAGS,True),**dict.fromkeys(contract.FALSE_FLAGS,False),
        limits=['Five whole native roots and the actual ID4 leaf execute; owner/window, packet constructor, handler and dispatch do not.',
            'Node allocation/sized free, vector storage reset and fresh FString reserve are explicit storage fixtures; native OS allocators are not executed.',
            'The native name getter consumes the observed insertion outpair, constructs a fresh signed-ANSI UTF16 descriptor, and diagnostic cleanup frees that name allocation only.',
            'FString grow/fatal/negative-length and OOM outcomes are not admitted by the bounded matrix. UTF8 conversion, logger and security effects remain fixtures.'])
    contract.validate_report(report,context)
    return report


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--context',type=Path,required=True)
    parser.add_argument('--root',type=Path,default=Path('F:/PhoneExit Resources/Vampir')); args=parser.parse_args()
    result=verify(json.loads(args.context.read_text('utf-8')),args.root)
    result['context_sha256']=hashlib.sha256(args.context.read_bytes()).hexdigest()
    path=load('research-workflow').snapshot(args.root,'native-login-container-checks',result)
    print(json.dumps(dict(report=str(path),cases=len(result['cases']))))
