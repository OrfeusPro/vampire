"""Whole native registration helper with explicit insertion/name/service fixtures."""
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


def insertion_input(raw_pair,raw_entry,packet,handler):
    """Capture original pointers before the insertion fixture mutates its output."""
    if (len(raw_pair)!=16 or len(raw_entry)!=24 or struct.unpack('<QQ',raw_pair)!=(packet,handler)
            or struct.unpack_from('<H',raw_entry)[0]!=4 or struct.unpack_from('<QQ',raw_entry,8)!=(packet,handler)):
        raise ValueError('Registration original insertion tuple differs')
    return dict(key=4,original_packet='input_packet',original_handler='input_handler',input_captured_before_output=True)


def call_site(return_address,start,name,target,calls):
    indirect={'name_getter':'qword ptr [rax + 0x38]','native_id':'qword ptr [rax + 0x28]'}
    site=return_address-(3 if name in indirect else 5)
    expected=indirect[name] if name in indirect else hex(target)
    if calls.get(hex(site))!=expected: raise ValueError('Registration fixture concrete caller differs')
    return site-start


def verify(context,root):
    contract=load('login-registration-case-contracts')
    start=int(context['functions']['register'],16);getter=int(context['bindings']['id_getter'],16)
    h=load('verify-login-registration-harness').make_harness(context,context['exports'],{start},
        leaves={int(at,16):code for at,code in context['leaves'].items()},root=root)
    uc,x=h.uc,h.x
    import unicorn
    packet,owner,handler,descriptor,name_buffer,current_pair,temp=[h.scratch+n for n in
        (0x1000,0x2000,0x3000,0x4000,0x5000,0x7000,0x8000)]
    allocation=context['packet_allocation_bytes']
    if type(allocation)is not int or allocation!=344: raise ValueError('Registration packet allocation extent differs')
    labels={int(at,16):name for name,at in context['fixtures'].items()}
    calls=context['call_sites']['register']
    if len(labels)!=8 or getter in labels or start in labels: raise ValueError('Registration fixture aliases native code')
    cookie=int(context['globals']['cookie'],16)
    literals={name:int(value['address'],16) for name,value in context['literals'].items()}
    state={};events=[]

    def require(ok,message):
        if not ok: raise ValueError(message)
    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def put(at,fmt,*values):uc.mem_write(at,struct.pack('<'+fmt,*values))
    def qword(at):return int.from_bytes(uc.mem_read(at,8),'little')
    def map_source(at):
        page=at&~4095
        if not any(low<=page<=high for low,high,_ in uc.mem_regions()):
            uc.mem_map(page,4096);offset=h.image.offset(page-h.image.pe.base);uc.mem_write(page,h.raw[offset:offset+4096])
    table=int(context['bindings']['packet_table'],16);map_source(table);map_source(table+0x40)
    require(qword(table+0x28)==getter and qword(table+0x38)==int(context['fixtures']['name_getter'],16),
        'Registration packet virtual slots differ')
    map_source(cookie)
    for name,value in context['literals'].items():
        at=int(value['address'],16);data=bytes.fromhex(value['bytes']);map_source(at);map_source(at+len(data)-1)
        require(bytes(uc.mem_read(at,len(data)))==data,'Registration literal bytes differ')
    cookie_value=qword(cookie)

    def read_utf16(at,limit=256):
        values=[]
        for i in range(limit):
            pair=bytes(uc.mem_read(at+2*i,2))
            if pair==b'\0\0':return b''.join(values).decode('utf-16le')
            values.append(pair)
        raise ValueError('Registration UTF16 fixture scan bound')
    def read_utf8(at,limit=512):
        if not at:return None
        values=[]
        for i in range(limit):
            byte=bytes(uc.mem_read(at+i,1))
            if byte==b'\0':return b''.join(values)
            values.append(byte)
        raise ValueError('Registration diagnostic UTF8 fixture bound')

    def fixture(machine,name):
        a,b,c,d=(reg(n) for n in ('RCX','RDX','R8','R9'))
        stack=reg('RSP');offset=call_site(qword(stack),start,name,int(context['fixtures'][name],16),calls)
        if name=='insert':
            require(offset==91 and a==owner+8 and (b,c)==(stack+0x38,stack+0x50),'Registration insert receiver/out/input arguments differ')
            captured=insertion_input(bytes(uc.mem_read(b,16)),bytes(uc.mem_read(c,24)),packet,handler)
            state['pair_address']=b
            put(b,'Q',current_pair if state['current_pair_nonnull'] else 0);put(b+8,'B',state['insert_status'])
            state['pair_after_insert']=bytes(uc.mem_read(b,16))
            events.append(contract.event('insert',offset,owner_offset=8,**captured,
                output_pointer='current_pair_fixture' if state['current_pair_nonnull'] else 'null',output_status=state['insert_status']))
            h.finish(0xfedcba98);return
        if name=='name_getter':
            # The actual virtual getter is not executed. This fixture deliberately
            # returns a separate descriptor and preserves the insertion output.
            require(offset==126 and a==packet and b==stack+0x38,
                'Registration name fixture receiver/out/caller differs')
            require(bytes(uc.mem_read(b,16))==state['pair_after_insert'],'Registration insertion output changed before name fixture')
            events.append(contract.event('name',offset,descriptor_count=state['name']['count'],descriptor_pointer=state['name']['pointer'],
                returned_descriptor='external_fixture',name_outparam_unchanged=True))
            h.finish(descriptor);return
        if name=='utf8_length':
            text=state['name']['text'];units=len(text.encode('utf-16le'))//2
            source=literals['empty_utf16'] if state['name_variant']=='zero_count_fallback' else name_buffer
            require(offset==193 and (a,b,c&0xffffffff)==(0,source,units) and read_utf16(b)==text,
                'Registration native UTF16 scan/length fixture arguments differ')
            events.append(contract.event('utf8_length',offset,utf16_units=units,utf8_bytes=len(text.encode('utf-8'))))
            h.finish(len(text.encode('utf-8')));return
        if name=='diagnostic_allocate':
            size=len(state['name']['text'].encode('utf-8'))+1
            require(offset==241 and a==reg('RBP')-0x20 and (b,c&0xffffffff,d&0xffffffff)==(0,size,1) and qword(a)==0 and size>128,
                'Registration diagnostic allocation fixture arguments differ')
            uc.mem_write(temp-16,b'\xa5'*16+b'\x5a'*size+b'\xa6'*16);state['temp_size']=size
            put(a,'Q',temp);events.append(contract.event('diagnostic_allocate',offset,bytes=size,stride=1));h.finish();return
        if name=='utf8_convert':
            text=state['name']['text'];data=text.encode('utf-8');units=len(text.encode('utf-16le'))//2
            source=literals['empty_utf16'] if state['name_variant']=='zero_count_fallback' else name_buffer
            heap=len(data)+1>128;target=temp if heap else stack+0x68
            require(offset==275 and (a,b&0xffffffff,c,d&0xffffffff)==(target,len(data)+1,source,units+1),
                'Registration UTF8 conversion fixture arguments differ')
            uc.mem_write(a,data+b'\0');state['diagnostic_pointer']=a
            events.append(contract.event('utf8_convert',offset,utf16_units_with_nul=units+1,capacity=len(data)+1,
                destination='heap' if heap else 'stack',utf8_hex=data.hex()));h.finish();return
        if name=='log':
            pointer=qword(stack+0x28);expected=state['name']['text']
            require(offset==321 and (a,b&0xffffffff,c,d&0xffffffff)==(literals['log_owner'],0xb27,literals['log_format'],4),
                'Registration diagnostic logger arguments differ')
            data=read_utf8(pointer)
            require(data==(None if expected is None else expected.encode('utf-8')),
                'Registration diagnostic pointer/text differs')
            events.append(contract.event('log',offset,packet_id=4,line=0xb27,utf8_hex=None if data is None else data.hex()));h.finish();return
        if name=='free':
            role='diagnostic_temporary' if offset==343 else 'current_pair_fixture' if offset==358 else None
            expected=temp if role=='diagnostic_temporary' else current_pair if role else -1
            require(a==expected and role not in state['freed'] and a not in (packet,handler,owner),
                'Registration free fixture ownership/repetition differs')
            require((role=='diagnostic_temporary' and state['temp_size']) or (role=='current_pair_fixture' and state['current_pair_nonnull']),
                'Registration free fixture missing allocation')
            state['freed'].add(role);events.append(contract.event('free',offset,allocation=role,
                origin='diagnostic_allocation_fixture' if role=='diagnostic_temporary' else 'insert_out_pointer_preserved_by_name_fixture'))
            h.finish();return
        if name=='security':
            require(offset==370 and a==cookie_value,'Registration stack cookie fixture differs')
            events.append(contract.event('security',offset,cookie_checked=True));h.finish(reg('RAX'));return
        raise ValueError('Registration unknown fixture')

    # Name is an indirect CALL; the direct-call guard belongs inside its branch.
    for at,name in labels.items():
        if name=='name_getter':
            def indirect(machine,name=name):
                return fixture(machine,name)
            h.add_fixture(at,indirect)
        else:h.add_fixture(at,lambda machine,name=name:fixture(machine,name))

    def trace(machine,at,size,unused):
        if at==getter:
            offset=call_site(qword(reg('RSP')),start,'native_id',getter,calls)
            require(offset in (59,290) and reg('RCX')==packet,
                'Registration actual ID getter caller/receiver differs')
            events.append(contract.event('native_id',offset,packet_id=4))
    uc.hook_add(unicorn.UC_HOOK_CODE,trace)
    abi={name:0x1122334400000000+i for i,name in enumerate(('RBX','RBP','RSI','RDI','R12','R13','R14','R15'))}
    abi.update({'XMM'+str(i):0x123456789abcdef0fedcba9876543210+i for i in range(6,16)})

    def run(scenario):
        state.clear();state.update(scenario);state.update(freed=set(),temp_size=0)
        state['name']=None if scenario['name_variant'] is None else contract.name_values(scenario['name_variant'])
        events.clear();poison=scenario['poison']
        uc.mem_write(h.scratch+0x30000,bytes([poison])*0x8000)
        for at,size in ((packet,allocation),(owner,64),(handler,8),(descriptor,16),(name_buffer,1024),(current_pair,32)):
            uc.mem_write(at-16,b'\xa5'*16+bytes([poison])*size+b'\xa6'*16)
        put(packet,'Q',table)
        if state['name'] is not None:
            name=state['name'];text=name['text'];pointer=0 if name['pointer']=='null' else name_buffer
            if text is not None:uc.mem_write(name_buffer,text.encode('utf-16le')+b'\0\0')
            put(descriptor,'QII',pointer,name['count'],name['count'])
        observed={at:bytes(uc.mem_read(at-16,size+32)) for at,size in
            ((packet,allocation),(owner,64),(handler,8),(descriptor,16),(name_buffer,1024),(current_pair,32))}
        for name,value in abi.items():uc.reg_write(getattr(x,'UC_X86_REG_'+name),value)
        uc.reg_write(x.UC_X86_REG_RDX,packet);uc.reg_write(x.UC_X86_REG_R8,handler)
        h.call(start,owner,budget=30000)
        require(all(reg(name)==value for name,value in abi.items()) and reg('RSP')==h.scratch+0x38008,'Registration helper ABI differs')
        require(all(bytes(uc.mem_read(at-16,len(data)))==data for at,data in observed.items()),
            'Registration input fixture or canary changed')
        if state['temp_size']:
            require(bytes(uc.mem_read(temp-16,16))==b'\xa5'*16 and bytes(uc.mem_read(temp+state['temp_size'],16))==b'\xa6'*16,
                'Registration diagnostic allocation canary differs')
        return dict(scenario=dict(scenario),events=list(events),native_id_calls=sum(e['action']=='native_id' for e in events),
            diagnostic_allocated=bool(state['temp_size']),diagnostic_freed='diagnostic_temporary' in state['freed'],
            current_pair_freed='current_pair_fixture' in state['freed'],original_packet_freed=False,
            packet_unchanged=True,handler_unchanged=True,owner_unchanged=True,name_buffer_unchanged=True,guards=True,abi=True)
    report=dict(schema=1,source_sha256=context['source_sha256'],method='bounded_native',cases=[run(s) for s in contract.scenarios()],
        runtime=load('update-native-harness').runtime_inputs(),evidence=h.evidence,
        network_used=False,profile_activated=False,runtime_activated=False,native_owner_used=False,native_window_used=False,
        native_packet_constructor_used=False,native_handler_used=False,native_insert_backend_used=False,native_name_getter_used=False,
        native_utf8_conversion_used=False,native_dispatch_used=False,session_executed=False,
        native_registration_helper_used=True,native_id_getter_used=True,name_outparam_unchanged=True,actual_ownership_unknown=True,
        limits=['One whole native registration helper and actual ID4 leaf execute; owner/window are static bindings only.',
            'Insertion is a fixture with independently controlled output pointer/status; real container insertion and dispatch remain unproved.',
            'Name fixture returns an external descriptor without changing RDX outparam. Free of the current-pair slot is not proof of original packet or real getter ownership.',
            'UTF8 length/conversion, allocation/free, logger/security and name getter effects are bounded fixtures; no OOM or live/runtime claim.'])
    contract.validate_report(report,context);return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--context',type=Path,required=True)
    parser.add_argument('--root',type=Path,default=Path('F:/PhoneExit Resources/Vampir'));args=parser.parse_args()
    result=verify(json.loads(args.context.read_text('utf-8')),args.root)
    result.update(context_sha256=hashlib.sha256(args.context.read_bytes()).hexdigest())
    path=load('research-workflow').snapshot(args.root,'native-login-registration-checks',result)
    print(json.dumps(dict(report=str(path),cases=len(result['cases']))))
