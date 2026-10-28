"""Whole Version prepare/constructor with explicit input, string and send fixtures."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from importlib.util import spec_from_file_location, module_from_spec

HERE=Path(__file__).resolve().parent
STRING_OFFSETS=(0x10,0x28,0x38,0x48,0x58,0x68,0x78,0x88,0xa0,0xb0)


def load(name):
    spec=spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify(context,root):
    prepare,constructor,table,wrapper_table,send=[int(context[k],16) for k in
        ('prepare','constructor','packet_table','wrapper_table','send')]
    nm=context.get('native_nm')
    system=context.get('native_system')
    combiners=context.get('native_combiners')
    platform=context.get('native_platform')
    functions={prepare,constructor};exports=dict(context['exports'])
    if nm:
        functions.update(int(nm[k],16) for k in ('wrapper','getter'))
        exports.update(nm['exports'])
    if system:
        functions.update(int(at,16) for at in system['cpu']['functions'].values())
        functions.add(int(system['windows']['function'],16))
        for part in system.values():exports.update(part['exports'])
    if combiners:
        functions.update(int(at,16) for at in combiners['functions'].values())
        exports.update(combiners['exports'])
    if platform:
        functions.update(int(platform[key],16) for key in ('selector','store','lookup'))
        exports.update(platform['exports'])
    h=load('update-native-harness').make_harness(context,exports,functions,root=root)
    native=load('build-native-entry-code');rows=load('update-bindings').rows
    calls={hex(r['address']):{'target':hex(r['direct_target']) if r['direct_target'] is not None else r['operands']}
           for a in (prepare,constructor) for r in rows(native,h.image,a) if r['call']}
    if calls!=context['call_sites']:
        raise ValueError('Version prepare call sites differ')
    offset=h.image.offset(wrapper_table-h.image.pe.base)
    data=h.raw[offset:offset+0x50]
    if hashlib.sha256(data).hexdigest()!=context['wrapper_table_sha256'] or (
            struct.unpack_from('<Q',data,0x38)[0],struct.unpack_from('<Q',data,0x48)[0])!=(send,prepare):
        raise ValueError('Version wrapper table links differ')
    if not any(r['mnemonic']=='lea' and r['rip_references']==[table] for r in rows(native,h.image,constructor)):
        raise ValueError('Version constructor table link differs')
    def map_data(address):
        page=address&~4095
        if any(lo<=page<=hi for lo,hi,_ in h.uc.mem_regions()):return
        off=h.image.offset(page-h.image.pe.base)
        h.uc.mem_map(page,4096)
        h.uc.mem_write(page,h.raw[off:off+4096])
    map_data(wrapper_table)
    fixture={k:int(v,16) for k,v in context['fixtures'].items()}
    if platform and (fixture['selector'],fixture['context_store'],fixture['context_value']) != (
            int(platform['selector'],16),int(platform['store'],16),int(platform['lookup'],16)):
        raise ValueError('Version platform helper links differ')
    if combiners and (fixture['combine_first'],fixture['combine_second']) != (
            int(combiners['functions']['first'],16),int(combiners['functions']['second'],16)):
        raise ValueError('Version combiner links differ')
    if system and (fixture['suffix']!=int(system['windows']['function'],16) or
                   fixture['first_text']!=int(system['cpu']['functions']['formatter'],16)):
        raise ValueError('Version system helper links differ')
    if nm and (int(nm['wrapper'],16)!=fixture['provider'] or
            [r['direct_target'] for r in rows(native,h.image,int(nm['wrapper'],16)) if r['call']]!=[int(nm['getter'],16)]):
        raise ValueError('Version native NM provider link differs')
    globals_={k:int(v,16) for k,v in context['globals'].items()}
    owner,input_descriptor,store=[h.scratch+n for n in (0x1000,0x2000,0x3000)]
    state={}

    def reg(name):
        return h.uc.reg_read(getattr(h.x,'UC_X86_REG_'+name))

    def allocate(size):
        if not 1<=size<=2048 or state['heap']+size+32>h.scratch+0x30000:
            raise ValueError('Version fixture allocation bound')
        pointer=state['heap']+16
        state['heap']+=(size+63)&~15
        h.uc.mem_write(pointer-16,b'\xa5'*16+b'\x5a'*size+b'\xa6'*16)
        state['allocations'][pointer]=size
        return pointer

    def release(pointer):
        if pointer not in state['allocations'] or pointer in state['freed']:
            raise ValueError('Version unowned or repeated free')
        size=state['allocations'][pointer]
        if bytes(h.uc.mem_read(pointer-16,16))!=b'\xa5'*16 or bytes(h.uc.mem_read(pointer+size,16))!=b'\xa6'*16:
            raise ValueError('Version allocation canary changed')
        state['freed'].add(pointer)

    def write_text(descriptor,text):
        raw=text.encode('utf-16le')+b'\0\0' if text else b''
        pointer=allocate(len(raw)) if raw else 0
        if raw:h.uc.mem_write(pointer,raw)
        h.uc.mem_write(descriptor,struct.pack('<QII',pointer,len(raw)//2,len(raw)//2))
        return descriptor

    def read_text(descriptor):
        pointer,count,capacity=struct.unpack('<QII',h.uc.mem_read(descriptor,16))
        if not 0<=count<=capacity<=1024 or (count and not pointer):
            raise ValueError('Version string descriptor bound')
        if not count:return ''
        raw=bytes(h.uc.mem_read(pointer,count*2))
        if not raw.endswith(b'\0\0'):
            raise ValueError('Version string terminator differs')
        return raw[:-2].decode('utf-16le')

    def literal(pointer,wide=False):
        data=bytearray();width=2 if wide else 1
        for i in range(256):
            value=bytes(h.uc.mem_read(pointer+i*width,width))
            if value==bytes(width):return data.decode('utf-16le' if wide else 'ascii')
            data.extend(value)
        raise ValueError('Version literal bound')

    def handler(name):
        def execute(machine):
            a,b,c=reg('RCX'),reg('RDX'),reg('R8');result=0
            if name=='log':state['logs']+=1
            elif name=='selector':result=state['selector']
            elif name=='context_store':result=store if state['present'] else 0
            elif name=='context_value':
                if a!=store or c!=state['selector']:
                    raise ValueError('Version context lookup arguments differ')
                write_text(b,state['context_text']);state['context_calls']+=1
            elif name in ('suffix','first_text','provider'):
                result=write_text(a,state[name])
            elif name=='ascii_string':result=write_text(a,literal(b))
            elif name=='wide_string':result=write_text(a,literal(b,True))
            elif name=='combine_first':
                if (read_text(b),read_text(c))!=(state['context_text'] if state['present'] else '', '_'):
                    raise ValueError('Version first combine inputs differ')
                result=write_text(a,'intermediate-fixture')
            elif name=='combine_second':
                if (read_text(b),read_text(c))!=('intermediate-fixture',state['suffix']):
                    raise ValueError('Version second combine inputs differ')
                result=write_text(a,state['combined'])
            elif name=='copy_string':result=write_text(a,read_text(b))
            elif name=='resize':
                if b>1024:raise ValueError('Version resize bound')
                pointer,count,capacity=struct.unpack('<QII',h.uc.mem_read(a,16))
                previous=bytes(h.uc.mem_read(pointer,min(capacity,b)*2)) if pointer else b''
                if pointer:release(pointer)
                pointer=allocate(b*2) if b else 0
                if previous:h.uc.mem_write(pointer,previous)
                h.uc.mem_write(a,struct.pack('<QII',pointer,count,b))
            elif name=='free':release(a)
            elif name=='destructor':
                if a!=state['packet_pointer']:raise ValueError('Version destructor receiver differs')
                for field in STRING_OFFSETS:
                    pointer=int.from_bytes(h.uc.mem_read(a+field,8),'little')
                    if pointer:release(pointer)
                state['destroyed']=True
            else:raise ValueError('Unknown Version fixture')
            h.finish(result)
        return execute

    for name,address in fixture.items():
        if name=='provider' and nm:continue
        if system and name in ('suffix','first_text'):continue
        if combiners and name in ('combine_first','combine_second'):continue
        if platform and name in ('selector','context_store','context_value'):continue
        h.add_fixture(address,handler(name))
    if system:
        seed_system,check_system=load('version-system-fixtures').install(
            load,h,system,fixture,state,write_text,read_text,literal,reg)
    if combiners:
        load('version-combiner-fixtures').install(load,h,combiners,state,allocate,release,reg)
        import unicorn
        combiner_targets={int(at,16):key for key,at in combiners['functions'].items()}
        def count_combiner(machine,address,size,unused):
            if address in combiner_targets:
                key=combiner_targets[address];state['combiner_calls'][key]=state['combiner_calls'].get(key,0)+1
        h.uc.hook_add(unicorn.UC_HOOK_CODE,count_combiner)
    if platform:
        platform_module=load('version-platform-fixtures')
        seed_platform,check_platform=platform_module.install(load,h,platform,fixture,state,store,write_text,literal,reg)
    if nm:
        import unicorn
        h.uc.mem_write(int(nm['log_level'],16),b'\0')
        h.uc.mem_write(int(nm['log_enabled'],16),b'\0')
        targets={int(nm[k],16) for k in ('wrapper','getter')}
        def count_nm(machine,address,size,unused):
            if address in targets:state['nm_calls']+=1
        h.uc.hook_add(unicorn.UC_HOOK_CODE,count_nm)

    def capture_send(machine):
        a,b=reg('RCX'),reg('RDX')
        if a!=owner or state['sent'] or int.from_bytes(h.uc.mem_read(b,8),'little')!=table:
            raise ValueError('Version send receiver/packet differs')
        state['strings']=[read_text(b+field) for field in STRING_OFFSETS]
        state['integers']=[int.from_bytes(h.uc.mem_read(b+field,4),'little') for field in (0x20,0x98,0xc0)]
        state.update(sent=True,packet_pointer=b)
        h.finish(state['send_return'])

    h.add_fixture(send,capture_send)
    tag_pointer=int.from_bytes(h.uc.mem_read(globals_['tag_pointer'],8),'little')
    tag_source=context.get('compiled_tag_source')
    if tag_source is None:
        if context['source_sha256']!='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960':
            raise ValueError('New source requires explicit compiled tag metadata')
        tag_source=dict(literal='0x149960020',value='32283C4C6485307BCF524765A84409C3')
    if tag_pointer!=int(tag_source['literal'],16):raise ValueError('Version tag source pointer differs')
    map_data(tag_pointer)
    compiled_tag=literal(tag_pointer)
    if compiled_tag!=tag_source['value']:
        raise ValueError('Version compiled tag differs')
    cases=[]
    abi={name:0xfedcba9876543210+i for i,name in enumerate(('RBX','RSI','RDI','RBP','R12','R13','R14','R15'))}
    abi.update({'XMM'+str(i):0x123456789abcdef0fedcba9876543210+i for i in range(6,16)})
    platform_cases=platform_module.SCENARIOS if platform else (dict(present=False),dict(present=True))
    for poison in (0,0x55,0xaa,0xff):
        for platform_case in platform_cases:
            present=platform_case['present']
            for empty in (False,True):
                for raw_enum in (0,0xffffffff):
                    for send_return in (0,1):
                        state.update(heap=h.scratch+0x10000,allocations={},freed=set(),logs=0,
                            present=present,empty=empty,selector=0x87,context_text='контекст',suffix='' if empty else 'suffix-fixture',
                            first_text='' if empty else 'CPU-Ж🙂',provider='' if empty else 'provider-界',
                            combined='' if empty else 'combined-fixture',context_calls=0,sent=False,
                            destroyed=False,send_return=send_return,nm_calls=0,combiner_events=[],combiner_calls={})
                        h.uc.mem_write(h.scratch+0x30000,b'\0'*0x8000)
                        if system:seed_system()
                        if platform:seed_platform(platform_case)
                        if combiners:state['combined']=(state['context_text'] if present else '')+'_'+state['suffix']
                        owner_bytes=bytearray([poison]*0x180);struct.pack_into('<Q',owner_bytes,0,wrapper_table)
                        h.uc.mem_write(owner-16,b'\xa5'*16+bytes(owner_bytes)+b'\xa6'*16)
                        global_text='' if empty else 'global-fixture';input_text='' if empty else 'input-🙂'
                        write_text(globals_['text'],global_text);write_text(input_descriptor,input_text)
                        if nm:
                            # Identity remains populated even when the other fields are empty.
                            state['provider']='nm-cache-Ж🙂'
                            write_text(int(nm['cache'],16),state['provider'])
                        input_pointers=set(state['allocations'])
                        input_guard=bytes(h.uc.mem_read(input_descriptor,16))
                        h.uc.mem_write(globals_['enum'],struct.pack('<I',raw_enum))
                        for name,value in abi.items():h.uc.reg_write(getattr(h.x,'UC_X86_REG_'+name),value)
                        h.uc.reg_write(h.x.UC_X86_REG_RDX,input_descriptor)
                        h.call(prepare,owner,budget=100000)
                        if system:check_system()
                        if platform:check_platform()
                        if combiners and (state['combiner_calls'].get('first')!=1 or state['combiner_calls'].get('second')!=1
                                or state['combiner_calls'].get('append')!=1+int(present and bool(state['context_text']))):
                            raise ValueError('Version native combiner calls differ')
                        expected=[global_text,state['combined'],state['first_text'],state['provider'],input_text,'','','','',compiled_tag]
                        if not state['sent'] or state['strings']!=expected or state['integers']!=[0,207,raw_enum]:
                            raise ValueError('Version prepared fields differ')
                        if state['context_calls']!=int(present) or not state['destroyed'] or state['logs']!=2:
                            raise ValueError('Version context/destruction/log lifecycle differs')
                        if state['nm_calls']!=(2 if nm else 0):
                            raise ValueError('Version native NM call count differs')
                        if set(state['allocations'])-input_pointers!=state['freed']:
                            raise ValueError('Version preparation temporary leaked or input freed')
                        struct.pack_into('<Q',owner_bytes,0x160,0)
                        if bytes(h.uc.mem_read(owner-16,0x1a0))!=b'\xa5'*16+bytes(owner_bytes)+b'\xa6'*16:
                            raise ValueError('Version owner reset or canaries differ')
                        if bytes(h.uc.mem_read(input_descriptor,16))!=input_guard or read_text(input_descriptor)!=input_text:
                            raise ValueError('Version input changed')
                        if any(reg(name)!=value for name,value in abi.items()) or reg('RSP')!=h.scratch+0x38008:
                            raise ValueError('Version prepare ABI differs')
                        cases.append(dict(poison=poison,context_present=present,empty=empty,raw_enum=raw_enum,
                            send_return=send_return,strings=state['strings'],integers=state['integers'],
                            native_nm_calls=state['nm_calls'],native_system_calls=dict(state.get('system_calls',{})),
                            native_combiner_calls=dict(state['combiner_calls']),guards=True))
                        if platform:cases[-1].update(platform_scenario=platform_case['name'],
                            native_platform_calls=dict(state['platform_calls']),platform_index=state['platform_index'])
    return dict(schema=1,source_sha256=context['source_sha256'],method='bounded_native',cases=cases,
        evidence=h.evidence,network_used=False,profile_activated=False,
        runtime=load('update-native-harness').runtime_inputs(),
        native_nm_used=bool(nm),
        native_system_used=bool(system),
        native_combiners_used=bool(combiners),
        native_platform_used=bool(platform),
        platform_fixture_sha256=hashlib.sha256((HERE/'version-platform-fixtures.py').read_bytes()).hexdigest() if platform else None,
        combiner_fixture_sha256=hashlib.sha256((HERE/'version-combiner-fixtures.py').read_bytes()).hexdigest() if combiners else None,
        system_fixture_sha256=hashlib.sha256((HERE/'version-system-fixtures.py').read_bytes()).hexdigest() if system else None,
        limits=['Whole prepare/constructor; optional native NM provider/getter uses initialized synthetic cache only.',
                'Windows/CPU helpers are native only when native_system_used; OS/CRT/cache boundaries and context/string/allocator/free/destructor/log/send remain fixtures.',
                'Combiners are native only when native_combiners_used; allocation/copy boundaries stay fixtures. No real hardware/SDK getter values proved.',
                'Platform selector/store/lookup are native only when native_platform_used; FName/type/resolver/value-at remain fixtures.',
                'No Login preparation, result readers, framing, auth, socket or runtime activation.'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context',type=Path,required=True)
    parser.add_argument('--root',type=Path,default=Path('F:/PhoneExit Resources/Vampir'))
    args=parser.parse_args()
    report=verify(json.loads(args.context.read_text('utf-8')),args.root)
    report['context_sha256']=hashlib.sha256(args.context.read_bytes()).hexdigest()
    report['tool_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    target=load('research-workflow').snapshot(args.root,'native-version-prepare-checks',report)
    print(json.dumps(dict(report=str(target),cases=len(report['cases']))))
