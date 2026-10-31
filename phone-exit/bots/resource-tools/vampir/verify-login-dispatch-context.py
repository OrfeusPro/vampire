"""Native registration-to-reader-to-handler delivery, lookup and TLS cleanup."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def require(ok,message):
    if not ok:raise ValueError(message)


def check_frame(frame):
    if not isinstance(frame,bytes) or not 5<=len(frame)<=4096:raise ValueError('Dispatch framing precondition differs')
    return frame


def release_exact(policy,address,size):
    """Cleanup may mutate this archive; all other protected ranges stay intact."""
    policy.readonly=[span for span in policy.readonly if span!=(address,address+size)]


def node_layout(base,count):
    require(type(count) is int and 0<=count<=9,'Dispatch node layout count differs')
    return [(base+i*0x80,40) for i in range(count)]


def tls_vector_values(index,block):
    require(type(index) is int and index in (0,1) and type(block) is int and block>0,'Dispatch TLS provider layout differs')
    return (block,0) if index==0 else (0,block)


def verify(context,root):
    core=load('portable-native-family');contract=load('login-dispatch-case-contracts')
    composition=core.checked(Path(root),context['composition_context'],'generated-native-contexts')
    container=core.checked(Path(root),context['container_context'],'generated-native-contexts')
    reader=core.checked(Path(root),composition['reader_context'],'generated-native-contexts')
    handler=core.checked(Path(root),composition['handler_context'],'generated-native-contexts')
    gate=core.checked(Path(root),handler['gate_context'],'generated-native-contexts')
    functions={key:int(at,16) for key,at in context['functions'].items()}
    h=load('verify-login-dispatch-harness').make_harness(context,context['exports'],set(functions.values()),
        leaves={int(at,16):value for at,value in context['leaves'].items()},root=root)
    policy=load('verify-login-dispatch-harness').MemoryPolicy
    h.uc=policy(h.uc);uc,x=h.uc,h.x
    import unicorn
    packet,owner,head,vector0,vector1,entry,outpair=[h.scratch+at for at in (0x1000,0x2000,0x7000,0x7200,0x7800,0x8800,0x8900)]
    handler_object=h.scratch+0xf600;mapping=owner+8;name_heap=h.scratch+0x60000
    tls_base=h.scratch+0x90000;tls_vector=h.scratch+0x91000;tls_block=h.scratch+0xa0000
    tls_location=tls_block+0x100cc0
    bind={key:int(at,16) for key,at in context['bindings'].items()}
    method={key:int(at,16) for key,at in reader['input']['functions'].items()}
    packet_functions={key:int(at,16) for key,at in reader['functions'].items()}
    cfunctions={key:int(at,16) for key,at in container['functions'].items()}
    state={};read_state={};step={};boxes=[];registry=[];payloads=[]
    setup_counts={};pointer_labels={};nodes=[];bindings_checked=[]
    phase={'value':'setup'}

    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def put(at,fmt,*values):uc.mem_write(at,struct.pack('<'+fmt,*values))
    def number(at,size=8):return int.from_bytes(uc.mem_read(at,size),'little')
    def snapshot(at,size):return uc.snapshot(at,size)
    def map_source(at,size):
        for page in range(at&~4095,((at+size-1)&~4095)+4096,4096):
            if any(lo<=page<=hi for lo,hi,_ in uc.mem_regions()):continue
            uc.mem_map(page,4096)
            try:off=h.image.offset(page-h.image.pe.base)
            except ValueError:continue
            uc.mem_write(page,h.raw[off:off+4096])
    def box(at,size,poison):
        require(size>0 and not any(at-16<old+length+16 and at+size+16>old-16 for old,length in boxes),'Dispatch fixture boxes overlap')
        uc.mem_write(at-16,b'\xa5'*16+bytes([poison])*size+b'\xa6'*16);boxes.append((at,size))
    def native_allow():
        regions=[(h.scratch+0x30000,0x8200),(h.scratch+0xa000-16,0x5700),(h.scratch+0x10000,0x20000),
            (tls_location,8),(owner+0x48,8)]
        regions.extend((int(at,16),8) for at in handler['globals'].values())
        if phase['value']=='setup':regions.extend([(packet,344),(mapping+0x10,8),(mapping+0x18,40),(head,16),(outpair,16),(vector0,1024),(vector1,1024)])
        regions.extend((at,40 if phase['value']=='setup' else 16) for at in nodes)
        if phase['value']=='reader':regions.append((packet,344))
        if state.get('archive'):regions.append((state['archive'],64))
        if state.get('name_capacity'):regions.append((name_heap,state['name_capacity']*2))
        if state.get('name_descriptor'):regions.append((state['name_descriptor'],16))
        uc.native_allow(regions)
    def guards():
        require(all(snapshot(at-16,16)==b'\xa5'*16 and snapshot(at+size,16)==b'\xa6'*16 for at,size in boxes),'Dispatch fixture canary changed')
        require(all(snapshot(at,len(value))==value for at,value in registry+payloads),'Dispatch registry or opaque payload changed')

    map_source(bind['packet_table'],0x40);map_source(bind['handler_table'],0x18)
    require(number(bind['packet_table']+0x20)==packet_functions['reader']
        and number(bind['packet_table']+0x28)==bind['id_getter']
        and number(bind['packet_table']+0x38)==cfunctions['name_getter'],'Dispatch packet virtual slots differ')
    require(number(bind['handler_table']+8)==bind['wrapper'] and number(bind['handler_table']+16)==int(handler['functions']['handler'],16),'Dispatch handler virtual slots differ')
    source_ro=[(bind['packet_table'],0x40),(bind['handler_table'],0x18)]
    globals_={key:int(at,16) for key,at in context['globals'].items()}
    for role in ('cookie','archive_flags'):
        size=8 if role=='cookie' else 4;map_source(globals_[role],size);source_ro.append((globals_[role],size))
    require(snapshot(globals_['cookie'],8).hex()==context['source_initial']['cookie']
        and snapshot(globals_['archive_flags'],4).hex()=='01000000','Dispatch source globals differ')
    map_source(globals_['tls_index'],4)
    literals={}
    for key,item in context['literals'].items():
        at=int(item['address'],16);raw=bytes.fromhex(item['bytes']);map_source(at,len(raw))
        require(snapshot(at,len(raw))==raw,'Dispatch literal source differs');literals[key]=at;source_ro.append((at,len(raw)))
    for at in context['cleanup_vtables'].values():map_source(int(at,16),8);source_ro.append((int(at,16),8))
    for item in container['extra_data'].values():
        at=int(item['address'],16);raw=bytes.fromhex(item['bytes']);map_source(at,len(raw));source_ro.append((at,len(raw)))
    empty_source=literals['packet_empty_ansi'];require(snapshot(empty_source,1)==b'\0','Dispatch empty constructor ANSI source differs')
    name_literal=int(container['extra_data']['packet_name']['address'],16)
    packet_name=b'PktLoginResult\0'

    # All concrete caller sites are derived from the checked target source.
    returns={}
    cs=h.image
    decoder=load('build-native-entry-code').capstone.Cs(load('build-native-entry-code').capstone.CS_ARCH_X86,load('build-native-entry-code').capstone.CS_MODE_64)
    for role,sites in context['call_sites'].items():
        for text,target in sites.items():
            at=int(text,16);off=cs.offset(at-cs.pe.base);insn=next(decoder.disasm(h.raw[off:off+15],at))
            require(insn.mnemonic=='call','Dispatch call metadata is not CALL')
            require(at+insn.size not in returns,'Dispatch call returns overlap');returns[at+insn.size]=(role,at-functions[role],target)
    def caller(address):
        result=returns.get(number(reg('RSP')))
        require(result is not None,'Dispatch concrete fixture caller absent')
        role,offset,target=result
        if target.startswith('0x'):require(int(target,16)==address,'Dispatch concrete direct callee differs')
        return role,offset

    copy=int(context['helpers']['memcpy'],16)
    def copy_fixture(machine):
        caller(copy);a,b,count=(reg(k) for k in ('RCX','RDX','R8'))
        require(0<=count<=4096 and all(h.scratch<=at<=h.scratch+0x200000-count for at in (a,b)),'Dispatch bounded memcpy extent differs')
        uc.begin_fixture([(a,count)] if count else [])
        try:
            if count:uc.mem_write(a,bytes(uc.mem_read(b,count)))
            h.finish(a)
        finally:uc.end_fixture()
    h.add_fixture(copy,copy_fixture)
    load('login-result-string-fixtures').install(load,h,reader['input'],read_state,packet,
        [at for kind,at in contract.COMPOSITION.ORDER if kind=='string'])
    reader_hooks=dict(h.fixtures);h.fixtures.clear()
    services=load('login-dispatch-handler-fixtures').install(load,h,handler,gate,packet,
        handler_table=bind['handler_table'],native_name_constructor=cfunctions['string_constructor'],packet_extent=344)
    handler_hooks=dict(h.fixtures);h.fixtures.clear()
    fixture_names={int(at,16):key for key,at in container['fixtures'].items()}

    def custom_fixture(address):
        role,offset=caller(address);name=fixture_names.get(address)
        a,b,c,d=(reg(k) for k in ('RCX','RDX','R8','R9'));stack=reg('RSP')
        require(stack&15==8,'Dispatch fixture Win64 alignment differs')
        writes=[]
        if name=='bucket_reset':
            require(role=='container.rehash' and offset==87 and a==mapping+0x18 and c==head and 4<=b<=128 and b%2==0,'Dispatch vector reset arguments differ')
            begin,end,cap=(number(mapping+off) for off in (0x18,0x20,0x28));old=(end-begin)//8
            fresh=old<b;dest=vector1 if fresh else begin;filled=b if fresh else old
            writes=[(dest,filled*8)]+([(mapping+0x18,24)] if fresh else [])
        elif name=='name_reserve':
            require(role=='container.string_constructor' and offset==90 and a==state['name_descriptor'] and b==15
                and snapshot(a,16)==bytes(16) and not state['name_capacity'],'Dispatch diagnostic reserve arguments differ')
            writes=[(a,8),(a+12,4)]
        elif name=='utf8_convert':
            require(role=='dispatch' and offset==0x1db and (b,c,d&0xffffffff)==(15,name_heap,15) and a==stack+0x98,'Dispatch diagnostic UTF8 arguments differ')
            writes=[(a,15)]
        uc.begin_fixture(writes)
        try:
            if name=='node_allocate':
                require(role=='container.insert' and offset==44 and a==40 and phase['value']=='setup','Dispatch node allocation caller differs')
                at=h.scratch+0x9000+len(nodes)*0x80;require(len(nodes)<9,'Dispatch node bound')
                nodes.append(at);native_allow();h.finish(at)
            elif name=='bucket_reset':
                uc.mem_write(dest,struct.pack('<Q',head)*filled)
                if fresh:
                    put(mapping+0x18,'QQQ',dest,dest+b*8,dest+b*8);uc.retire(begin,cap-begin)
                native_allow();h.finish(a)
            elif name=='name_reserve':
                put(a,'Q',name_heap);put(a+12,'I',15);state['name_capacity']=15;native_allow();h.finish()
            elif name=='utf8_length':
                require(role=='dispatch' and offset==0x172 and (a,b,c&0xffffffff)==(0,name_heap,14)
                    and snapshot(name_heap,30)==b''.join(bytes([ch,0]) for ch in packet_name),'Dispatch diagnostic length differs')
                h.finish(14)
            elif name=='utf8_convert':
                uc.mem_write(a,packet_name);state['diagnostic_utf8']=a;h.finish()
            elif name=='free':
                require(role=='dispatch' and offset==0x224 and a==name_heap and state['name_capacity']==15 and not state['name_freed'],'Dispatch diagnostic free ownership differs')
                state['name_freed']=True;uc.retire(name_heap,30);h.finish()
            elif name=='log':
                require(role in ('dispatch','lookup') and a==literals['dispatch_name' if role=='dispatch' else 'lookup_name'],'Dispatch logger receiver differs')
                code=b&0xffffffff;packet_id=d&0xffffffff
                format_=literals['unknown_format'] if code in (0xaf8,0xadc) else literals['read_failure_format']
                require(c==format_ and code in (0xaf8,0xadc,0xb0b),'Dispatch diagnostic format/line differs')
                text=None
                if code==0xb0b:
                    pointer=number(stack+0x28);require(pointer==state['diagnostic_utf8'] and snapshot(pointer,15)==packet_name,'Dispatch diagnostic name differs');text=packet_name[:-1].hex()
                step['dispatch']['diagnostics'].append(dict(line=code,packet_id=packet_id,name_hex=text));h.finish()
            elif name=='security':
                require(role in ('dispatch','container.register') and a==number(globals_['cookie']),'Dispatch security argument differs');h.finish(reg('RAX'))
            else:raise ValueError('Dispatch unexpected storage/failure boundary '+str(name))
        finally:uc.end_fixture()

    fixture_addresses=set(reader_hooks)|set(handler_hooks)|set(fixture_names)
    require(not fixture_addresses & (set(functions.values())|{int(at,16) for at in context['leaves']}),'Dispatch fixture shadows native code')
    def route(address):
        def execute(machine):
            role,_=caller(address)
            if address==copy:copy_fixture(machine)
            elif role.startswith('composition.input.'):
                hook=reader_hooks.get(address);require(hook is not None,'Dispatch undeclared reader fixture')
                a=reg('RCX');writes=[(h.scratch+0x10000,0x18000),(h.scratch+0x30000,0x8200),(packet,344)]
                uc.begin_fixture(writes)
                try:hook(machine)
                finally:uc.end_fixture()
                if address in (int(reader['input']['string_fixtures']['free'],16),int(reader['input']['string_fixtures']['cpp_free'],16)):
                    require(a in read_state['string_freed'],'Dispatch reader free not observed');uc.retire(a,read_state['allocations'][a])
            elif role.startswith('composition.handler.'):
                hook=handler_hooks.get(address);require(hook is not None,'Dispatch undeclared handler fixture')
                uc.begin_fixture([(h.scratch+0xa000-16,0x5700),(h.scratch+0x28000,0x10200)]+[(int(at,16),8) for at in handler['globals'].values()])
                try:hook(machine)
                finally:uc.end_fixture()
            else:custom_fixture(address)
        return execute
    for address in fixture_addresses:h.add_fixture(address,route(address))

    # Native entry/return tracing supplies actual observations, never expected rows.
    reverse={at:key for key,at in functions.items()}
    cleanup={bind['cleanup'+str(i)]:name for i,name in enumerate(('reader','buffer','archive','base'))}
    logical_targets={method[key]:key for key in ('u16','u32','u64','time','bool','string')}
    order=contract.COMPOSITION.ORDER
    def position():
        at=state['archive'];value=number(at+0x30)-state['body_pointer'];require(0<=value<=len(state['body']),'Dispatch reader cursor bound');return value
    def capture_reader():
        returned=reg('RAX')&255;row=dict(returned=returned,size=len(state['body']),consumed=position(),operations=list(state['operations']),guards=True,abi=True,scalar_values={},strings={})
        if returned:
            for kind,offset in order:
                if kind=='string':
                    at,num,cap=struct.unpack('<QII',snapshot(packet+offset,16));require(num==cap and 0<=num<=1024,'Dispatch reader FString descriptor differs')
                    raw=bytes(uc.mem_read(at,num*2)) if num else b'';require(not num or raw[-2:]==b'\0\0','Dispatch string NUL differs')
                    row['strings'][hex(offset)]=raw[:-2].decode('utf-16le') if num else ''
                else:row['scalar_values'][hex(offset)]=number(packet+offset,contract.COMPOSITION.WIDTH[kind])
        step['reader']=row;step['dispatch']['archive']['consumed']=row['consumed']
        state['packet_after_read']=snapshot(packet,344)
        uc.protect([(packet,344)])
        for at,size in read_state['allocations'].items():
            if at not in read_state.get('string_freed',set()):uc.protect([(at,size)])
        phase['value']='dispatch';native_allow()
    def trace(machine,at,size,unused):
        role=reverse.get(at)
        if role:
            if phase['value']=='setup':
                key={'composition.packet.constructor':'packet_constructor_calls','container.register':'register_calls','container.insert':'insert_calls',
                    'container.rehash':'rehash_calls','container.string_constructor':'string_constructor_calls'}.get(role)
                if key:setup_counts[key]+=1
            if role=='container.string_constructor':
                if phase['value']=='setup':require(reg('RCX')==packet+0x140 and reg('RDX')==empty_source,'Dispatch native empty trailing constructor differs')
                else:
                    require(reg('RCX')==state['name_descriptor'] and reg('RDX')==name_literal,'Dispatch native diagnostic name constructor differs')
                    step['dispatch']['name_constructor_calls']+=1
            elif role=='container.name_getter':
                require(phase['value']!='setup' and reg('RCX')==packet,'Dispatch name getter receiver differs')
                state['name_descriptor']=reg('RDX');step['dispatch']['name_getter_calls']+=1;native_allow()
            elif role=='dispatch':step['dispatch']['dispatch_calls']+=1
            elif role=='lookup':step['dispatch']['lookup_calls']+=1
            elif role=='composition.input.constructor' and phase['value']!='setup':
                state['archive']=reg('RCX');require(reg('RDX')==state['body_pointer'] and reg('R8')==len(state['body']) and reg('R9')==1 and number(reg('RSP')+0x28,1)==0,'Dispatch native archive constructor args differ')
                step['dispatch']['archive']=dict(flags=1,fifth_arg=0,source_offset=5,size=len(state['body']),consumed=None,cleanup_chain=[],final_buffer=None,final_length=None,final_cursor=None,final_swap=None,final_vptr_checked=False);native_allow()
            elif role=='composition.packet.reader':
                require(reg('RCX')==packet and reg('RDX')==state['archive'] and number(tls_location)==owner,'Dispatch native reader args/TLS differ')
                step['dispatch']['reader_calls']+=1;step['dispatch']['tls_at_reader']='owner';phase['value']='reader';native_allow()
            elif role=='composition.handler.handler':
                require(reg('RCX')==handler_object and reg('RDX')==0x12345678 and reg('R8')==packet and number(owner+0x48)==packet and number(tls_location)==owner,'Dispatch native handler tuple/context differs')
                step['dispatch']['handler_calls']+=1;step['dispatch']['tls_at_handler']='owner';step['dispatch']['active_at_handler']='packet'
                phase['value']='handler';uc.protect([(state['archive'],64)]);native_allow()
                uc.begin_fixture([(h.scratch+0xa000-16,0x5700),(h.scratch+0x28000,0x8000)]+[(int(at,16),8) for at in handler['globals'].values()])
                try:services['prepare'](state['spec']['composition']['scenario'])
                finally:uc.end_fixture()
            elif role=='composition.handler.gate':step['dispatch']['gate_calls']+=1
        if phase['value']=='reader' and at in logical_targets and reg('RDX')-packet in {offset for _,offset in order}:
            count=len(state['operations']);require(count<len(order),'Dispatch reader operations exceed contract');kind,offset=order[count]
            require(load('verify-login-composition-context').logical_entry_matches(logical_targets[at],reg('RDX'),kind,offset,packet),'Dispatch logical reader method/destination differs')
            state['operations'].append([kind,hex(offset)])
        if at==bind['wrapper']:
            require(reg('RCX')==handler_object and reg('RDX')==0x12345678 and reg('R8')==packet,'Dispatch native wrapper tuple differs');step['dispatch']['wrapper_calls']+=1
        elif at==bind['tls']:
            value=reg('RCX');require(value in (owner,0),'Dispatch TLS setter receiver differs');step['dispatch']['tls_set_calls'].append('owner' if value else 'null')
        elif at in cleanup:
            require(reg('RCX')==state['archive'],'Dispatch cleanup archive pointer differs');step['dispatch']['archive']['cleanup_chain'].append(cleanup[at])
        if at==bind['dispatch']+0x10b:capture_reader()
        if at==bind['dispatch']+0x245:
            services['leave']();phase['value']='dispatch'
            release_exact(uc,state['archive'],64)
            native_allow()
    def memory(machine,access,at,size,value,unused):
        uc.writable(at,size,native=True)
        if at==owner+0x48:
            require(size==8 and value in (packet,0),'Dispatch active packet native write differs');step['dispatch']['active_writes'].append('packet' if value else 'null')
    uc.hook_add(unicorn.UC_HOOK_CODE,trace)
    uc.hook_add(unicorn.UC_HOOK_MEM_WRITE,memory)
    uc.hook_add(unicorn.UC_HOOK_MEM_READ,lambda machine,access,at,size,value,unused:uc.readable(at,size))
    abi={name:0x1122334400000000+i for i,name in enumerate(('RBX','RBP','RSI','RDI','R12','R13','R14','R15'))}
    abi.update({'XMM'+str(i):0x123456789abcdef0fedcba9876543210+i for i in range(6,16)})
    def call(at,receiver,**arguments):
        for name,value in abi.items():uc.reg_write(getattr(x,'UC_X86_REG_'+name),value)
        for name,value in arguments.items():uc.reg_write(getattr(x,'UC_X86_REG_'+name),value)
        result=h.call(at,receiver,budget=1500000)
        require(all(reg(name)==value for name,value in abi.items()) and reg('RSP')==h.return_stack,'Dispatch whole call Win64 ABI differs')
        return result

    def reset(spec):
        uc.reset();state.clear();step.clear();boxes.clear();registry.clear();payloads.clear();nodes.clear();pointer_labels.clear();bindings_checked.clear();read_state.clear()
        state.update(spec=spec,archive=None,name_descriptor=None,name_capacity=0,name_freed=False)
        phase['value']='setup';setup_counts.clear();setup_counts.update(dict.fromkeys(('packet_constructor_calls','register_calls','insert_calls','rehash_calls','string_constructor_calls'),0))
        poison=spec['poison'];uc.mem_write(h.scratch+0x28000,bytes([poison])*0x10200)
        for at,size in ((packet,344),(owner,80),(handler_object,8),(head,40),(vector0,1024),(vector1,1024),(entry,24),(outpair,16),(name_heap,30)):
            box(at,size,poison)
        for at,size in node_layout(h.scratch+0x9000,9):box(at,size,poison)
        put(owner,'Q',0);put(owner+0x48,'Q',0);put(handler_object,'Q',bind['handler_table'])
        put(mapping,'f',1.0);put(mapping+8,'QQQQQQQ',head,0,vector0,vector0+128,vector0+128,7,8)
        put(head,'QQ',head,head);uc.mem_write(vector0,struct.pack('<Q',head)*16)
        put(tls_base+0x58,'Q',tls_vector);put(tls_vector,'QQ',*tls_vector_values(spec['tls_index'],tls_block));put(tls_location,'Q',0)
        put(globals_['tls_index'],'I',spec['tls_index']);uc.reg_write(x.UC_X86_REG_GS_BASE,tls_base)
        read_state.update(body=b'',heap=h.scratch+0x10000,allocations={},strings={},string_freed=set())
        native_allow()
        for at,size in source_ro+[(globals_['tls_index'],4),(tls_base+0x58,8),(tls_vector,16),(handler_object,8)]:uc.protect([(at,size)])
    def insert(key,index):
        at_packet=h.scratch+0x8000+index*0x40;at_handler=at_packet+0x20
        uc.mem_write(at_packet,bytes(16));uc.mem_write(at_handler,bytes(16));payloads.extend([(at_packet,snapshot(at_packet,16)),(at_handler,snapshot(at_handler,16))]);uc.protect([(at_packet,16),(at_handler,16)])
        put(entry,'H',key);put(entry+8,'QQ',at_packet,at_handler)
        result=call(cfunctions['insert'],mapping,RDX=outpair,R8=entry)
        node=number(outpair);require(result==outpair and number(outpair+8,1)==1 and node in nodes and number(node+0x10,2)==key and (number(node+0x18),number(node+0x20))==(at_packet,at_handler),'Dispatch native inserted binding differs')
        pointer_labels[at_handler]='handler_'+str(index);bindings_checked.append(node)
    def setup(spec):
        reset(spec)
        if spec['kind']=='lookup':
            for i,key in enumerate(spec['keys']):insert(key,i)
        else:
            require(call(packet_functions['constructor'],packet)==packet,'Dispatch packet constructor result differs')
            before=spec.get('before_keys',[])
            for i,key in enumerate(before):insert(key,i)
            call(cfunctions['register'],owner,RDX=packet,R8=handler_object)
            found=[at for at in nodes if number(at+0x10,2)==4]
            require(len(found)==1 and (number(found[0]+0x18),number(found[0]+0x20))==(packet,handler_object),'Dispatch native registration binding differs')
            bindings_checked.append(found[0]);pointer_labels[handler_object]='handler_input'
            for i,key in enumerate(spec.get('after_keys',[]),len(before)):insert(key,i)
        require(number(owner+0x48)==number(tls_location)==0,'Dispatch initial context precondition differs')
        for at,size in [(mapping,64),(head,40)]+[(at,40) for at in nodes]+[(number(mapping+0x18),number(mapping+0x28)-number(mapping+0x18))]:
            registry.append((at,snapshot(at,size)));uc.protect([(at,size)])
        uc.protect([(owner,8)])
        return dict(setup_counts,bindings_checked=len(bindings_checked)==len(nodes),initial_active_null=True,initial_tls_null=True)
    def run_step(spec,index=0):
        state.update(spec=spec,body=b'' if spec['kind']=='lookup' else contract.frame_body(spec),archive=None,operations=[],name_descriptor=None,name_capacity=0,name_freed=False,diagnostic_utf8=None)
        packet_id=spec['query'] if spec['kind']=='lookup' else spec.get('packet_id',4)
        step.clear();step.update(spec=spec,reader=None,handler=None,dispatch=dict(packet_id=packet_id,found=False,dispatch_calls=0,lookup_calls=0,reader_calls=0,handler_calls=0,wrapper_calls=0,gate_calls=0,
            tls_set_calls=[],tls_at_reader=None,tls_at_handler=None,tls_after=None,active_at_handler=None,active_after=None,active_writes=[],archive=None,diagnostics=[],name_getter_calls=0,name_constructor_calls=0,name_buffer_freed=False,lookup_returned_handler=None),
            registry_unchanged=True,packet_unchanged_by_handler=True,source_buffers_unchanged=True,abi=True,guards=True,fixture_writes_bounded=True,packet_reseeded=False)
        phase['value']='dispatch';native_allow()
        if spec['kind']=='lookup':
            returned=call(bind['lookup'],owner,RDX=packet_id)
            require(returned==0 or returned in pointer_labels,'Dispatch lookup returned foreign handler')
            step['dispatch']['lookup_returned_handler']=pointer_labels.get(returned);step['dispatch']['found']=bool(returned)
        else:
            frame=check_frame(bytes(3)+struct.pack('<H',packet_id)+state['body']);frame_at=h.scratch+0x50000+index*0x2000
            box(frame_at,len(frame),spec['poison']);uc.mem_write(frame_at,frame);uc.protect([(frame_at,len(frame))]);state['body_pointer']=frame_at+5
            call(bind['dispatch'],owner,RDX=0x12345678,R8=frame_at,R9=len(frame))
            require(snapshot(frame_at,len(frame))==frame,'Dispatch changed the source frame')
            step['dispatch']['found']=bool(step['dispatch']['reader_calls'])
            if step['dispatch']['handler_calls']:step['handler']=services['finish']()
            if state['archive']:
                at=state['archive'];require(number(at)==int(context['cleanup_vtables']['cleanup3'],16) and number(at+0x20)==number(at+0x28,4)==number(at+0x30)==number(at+0x38,1)==0,'Dispatch native archive cleanup result differs')
                step['dispatch']['archive'].update(final_buffer='null',final_length=0,final_cursor='null',final_swap=0,final_vptr_checked=True)
            step['dispatch']['name_buffer_freed']=state['name_freed']
        require(number(tls_location)==number(owner+0x48)==0,'Dispatch final context differs')
        step['dispatch']['tls_after']='null';step['dispatch']['active_after']='null';guards()
        return json.loads(json.dumps(step))
    cases=[]
    for spec in contract.scenarios():
        setup_row=setup(spec)
        if spec['kind']=='reuse':
            steps=[];preserved=None
            for i,child in enumerate(contract.reuse_steps(spec)):
                row=run_step(child,i);steps.append(row)
                if i==0:preserved=snapshot(packet,344)
                else:require(snapshot(packet,344)==preserved,'Dispatch failure/unknown changed the decoded packet')
            row=dict(spec=spec,setup=setup_row,steps=steps,shared_owner=True,shared_packet=True,registry_rebuilt=False,packet_reconstructed=False,packet_after_failures_unchanged=True,abi=True,guards=True)
        else:row=dict(run_step(spec),setup=setup_row)
        require(contract.canonical(row)==contract.canonical(contract.expected_case(spec)),'Dispatch observed scenario differs: '+spec['label'])
        cases.append(row)
    report=dict(schema=1,source_sha256=context['source_sha256'],method='bounded_native',cases=cases,
        runtime=load('update-native-harness').runtime_inputs(),evidence=h.evidence,
        framing_precondition='frame_size_at_least_5',initial_context_precondition='active_packet_and_tls_zero',
        **dict.fromkeys(contract.TRUE_FLAGS,True),**dict.fromkeys(contract.FALSE_FLAGS,False),
        limits=['29 whole native roots and12 leaves execute over exact current-SHA sources; framing>=5 and initially null active/TLS are explicit caller preconditions.',
            'Native registry construction, lookup, dispatcher, reader, wrapper, handler/gate, TLS setter/reset and archive cleanup run without coordinator-controlled handler gating.',
            'OS TLS provider, allocation/free/vector reset/reserve, SDK/UI/clock/services and diagnostic UTF8 are declared fixtures. Real networking, whole session, OOM/SEH and malformed maps remain outside scope.'])
    contract.validate_report(report,context);return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--context',type=Path,required=True);p.add_argument('--root',type=Path,default=Path('F:/PhoneExit Resources/Vampir'))
    args=p.parse_args();c=json.loads(args.context.read_text('utf-8'));r=verify(c,args.root);r['context_sha256']=hashlib.sha256(args.context.read_bytes()).hexdigest()
    path=load('research-workflow').snapshot(args.root,'native-login-dispatch-checks',r);print(json.dumps(dict(report=str(path),cases=len(r['cases']))))
