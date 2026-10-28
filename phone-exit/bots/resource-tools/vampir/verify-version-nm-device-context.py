"""Current native Version provider -> NM getter; synthetic storage/GUID fixtures only."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from importlib.util import spec_from_file_location,module_from_spec

HERE=Path(__file__).resolve().parent


def load(name):
    spec=spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=module_from_spec(spec);spec.loader.exec_module(module)
    return module


def verify(context,root):
    wrapper,getter,cache=[int(context[k],16) for k in ('wrapper','getter','cache')]
    h=load('update-native-harness').make_harness(context,context['exports'],{wrapper,getter},root=root)
    native=load('build-native-entry-code');rows=load('update-bindings').rows
    calls={hex(r['address']):hex(r['direct_target']) if r['direct_target'] is not None else r['operands']
           for at in (wrapper,getter) for r in rows(native,h.image,at) if r['call']}
    if calls!=context['call_sites'] or [r['direct_target'] for r in rows(native,h.image,wrapper) if r['call']]!=[getter]:
        raise ValueError('NM provider/getter call sites differ')
    # Cold-path storage descriptors are explicit initialized-state fixtures, not inferred registry paths.
    arguments=[int(v,16) for v in context['storage_arguments']]
    fixture={k:int(v,16) for k,v in context['fixtures'].items()}
    output,guid=[h.scratch+n for n in (0x1000,0x2000)]
    state={}

    def reg(name):return h.uc.reg_read(getattr(h.x,'UC_X86_REG_'+name))

    def alloc(size):
        if not 1<=size<=2048 or state['heap']+size+32>h.scratch+0x30000:
            raise ValueError('NM allocation budget')
        pointer=state['heap']+16;state['heap']+=(size+63)&~15
        h.uc.mem_write(pointer-16,b'\xa5'*16+b'\x5a'*size+b'\xa6'*16)
        state['allocations'][pointer]=size
        return pointer

    def free(pointer):
        if pointer not in state['allocations'] or pointer in state['freed']:
            raise ValueError('NM unowned or repeated free')
        size=state['allocations'][pointer]
        if bytes(h.uc.mem_read(pointer-16,16))!=b'\xa5'*16 or bytes(h.uc.mem_read(pointer+size,16))!=b'\xa6'*16:
            raise ValueError('NM allocation canary changed')
        state['freed'].add(pointer)

    def write_text(descriptor,text):
        raw=(text+'\0').encode('utf-16le') if text else b''
        pointer=alloc(len(raw)) if raw else 0
        if raw:h.uc.mem_write(pointer,raw)
        h.uc.mem_write(descriptor,struct.pack('<QII',pointer,len(raw)//2,len(raw)//2))

    def read_text(descriptor):
        pointer,count,capacity=struct.unpack('<QII',h.uc.mem_read(descriptor,16))
        if not 0<=count<=capacity<=1024 or (count and not pointer):raise ValueError('NM descriptor bound')
        if not count:return ''
        raw=bytes(h.uc.mem_read(pointer,count*2))
        if not raw.endswith(b'\0\0'):raise ValueError('NM string terminator differs')
        return raw[:-2].decode('utf-16le')

    def handler(name):
        def execute(machine):
            a,b,c,d=[reg(k) for k in ('RCX','RDX','R8','R9')];result=0
            if name=='resize':
                if not 1<=b<=1024:raise ValueError('NM resize bound')
                old,count,capacity=struct.unpack('<QII',h.uc.mem_read(a,16))
                previous=bytes(h.uc.mem_read(old,min(b,capacity)*2)) if old else b''
                if old:free(old)
                pointer=alloc(b*2)
                if previous:h.uc.mem_write(pointer,previous)
                h.uc.mem_write(a,struct.pack('<QII',pointer,count,b))
            elif name=='free':free(a)
            elif name=='assign_span':
                if not 0<=c<=1023:raise ValueError('NM span bound')
                if a!=cache:raise ValueError('NM cache assignment differs')
                write_text(a,bytes(h.uc.mem_read(b,c*2)).decode('utf-16le'));result=a
            elif name=='stored_read':
                if [a,b,c]!=arguments:raise ValueError('NM storage read arguments differ')
                write_text(d,state['profile'].get('stored',''))
                result=int(state['profile'].get('read_ok',True));state['events'].append('read')
            elif name=='parse':
                state['parsed_text']=read_text(a)
                h.uc.mem_write(b,struct.pack('<IIII',*state['profile'].get('words',(1,2,3,4))))
                result=int(state['profile'].get('parse_ok',True));state['events'].append('parse')
            elif name=='new_guid':
                h.uc.mem_write(a,struct.pack('<IIII',0x12345678,0x90abcdef,0x87654321,0xfedcba09))
                result=a;state['events'].append('generate')
            elif name=='format_guid':
                if c!=0:raise ValueError('NM GUID format mode differs')
                if bytes(h.uc.mem_read(a,16))!=struct.pack('<IIII',0x12345678,0x90abcdef,0x87654321,0xfedcba09):
                    raise ValueError('NM GUID formatter input differs')
                write_text(b,'generated-fixture');result=b;state['events'].append('format')
            elif name=='stored_write':
                if [a,b,c]!=arguments or d!=cache:raise ValueError('NM storage write arguments differ')
                state['written']=read_text(d);result=int(state['profile'].get('write_ok',True))
                state['events'].append('write')
            else:raise ValueError('Unknown NM fixture')
            h.finish(result)
        return execute
    for name,address in fixture.items():h.add_fixture(address,handler(name))
    # The diagnostic branch is deliberately excluded; no logging sink or user data is touched.
    h.uc.mem_write(int(context['log_level'],16),b'\0')
    h.uc.mem_write(int(context['log_enabled'],16),b'\0')
    profiles=[dict(name='cached',cache='cache-Ж🙂'),dict(name='cached-one-char',cache='x'),
              dict(name='cached-space',cache=' '),dict(name='stored',stored='StoredCase-Fixture'),
              dict(name='parse-failure',stored='invalid-fixture',parse_ok=False),
              dict(name='zero-guid',stored='zero-fixture',words=(0,0,0,0)),
              dict(name='write-failure',parse_ok=False,write_ok=False),
              dict(name='read-failure-value',stored='retained-fixture',read_ok=False),
              dict(name='read-failure-empty',read_ok=False,parse_ok=False)]
    cases=[];abi={name:0xfedcba9876543210+i for i,name in enumerate(('RBX','RSI','RDI','RBP','R12','R13','R14','R15'))}
    abi.update({'XMM'+str(i):0x123456789abcdef0fedcba9876543210+i for i in range(6,16)})
    for poison in (0,0x55,0xaa,0xff):
        for profile in profiles:
            state.update(heap=h.scratch+0x10000,allocations={},freed=set(),profile=profile,events=[],written=None)
            h.uc.mem_write(h.scratch+0x30000,b'\0'*0x8000)
            write_text(cache,profile.get('cache',''))
            for index,address in enumerate(arguments):write_text(address,'storage-'+str(index)+'-fixture')
            inputs={p for p in state['allocations']}
            expected=(profile['cache'] if profile.get('cache') else
                profile.get('stored','') if profile.get('parse_ok',True) and any(profile.get('words',(1,2,3,4)))
                else 'generated-fixture')
            first_events=None
            for repeat in (False,True):
                h.uc.mem_write(output-16,b'\xa5'*16+bytes((poison,))*16+b'\xa6'*16)
                for name,value in abi.items():h.uc.reg_write(getattr(h.x,'UC_X86_REG_'+name),value)
                if h.call(wrapper,output,budget=100000)!=output or read_text(output)!=expected or read_text(cache)!=expected:
                    raise ValueError('NM provider result/cache differs')
                if bytes(h.uc.mem_read(output-16,16))!=b'\xa5'*16 or bytes(h.uc.mem_read(output+16,16))!=b'\xa6'*16:
                    raise ValueError('NM output canary changed')
                if any(reg(name)!=value for name,value in abi.items()) or reg('RSP')!=h.scratch+0x38008:
                    raise ValueError('NM getter ABI differs')
                pointer=int.from_bytes(h.uc.mem_read(output,8),'little')
                if pointer:free(pointer)
                if repeat and first_events!=state['events']:raise ValueError('NM repeat bypassed cache')
                if not repeat:first_events=state['events'].copy()
            expected_events=[] if profile.get('cache') else ['read','parse']+(
                ['generate','format','write'] if expected=='generated-fixture' else [])
            if state['events']!=expected_events:raise ValueError('NM getter lifecycle differs')
            cache_pointer=int.from_bytes(h.uc.mem_read(cache,8),'little')
            live=set(state['allocations'])-state['freed']
            if live!=(inputs|{cache_pointer})-state['freed']:
                raise ValueError('NM temporary allocation leaked')
            if state['written']!=('generated-fixture' if 'write' in expected_events else None):
                raise ValueError('NM stored write differs')
            cases.append(dict(poison=poison,profile=profile['name'],value=expected,events=state['events'],
                              repeated_cache_only=True,guards=True))
    return dict(schema=1,source_sha256=context['source_sha256'],method='bounded_native',cases=cases,
        evidence=h.evidence,network_used=False,user_identity_read=False,profile_activated=False,
        runtime=load('update-native-harness').runtime_inputs(),
        limits=['Whole provider wrapper and NM getter; diagnostics disabled in synthetic memory.',
                'Storage, GUID parser/generator/formatter and FString allocator/assignment/free are explicit fixtures.',
                'Storage descriptor values are initialized-state fixtures, not proof of registry paths or actual identity.',
                'No whole Version/Login preparation, OS getters, real registry writes, auth or sockets.'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context',type=Path,required=True)
    parser.add_argument('--root',type=Path,default=Path('F:/PhoneExit Resources/Vampir'))
    args=parser.parse_args();report=verify(json.loads(args.context.read_text('utf-8')),args.root)
    report['context_sha256']=hashlib.sha256(args.context.read_bytes()).hexdigest()
    report['tool_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    target=load('research-workflow').snapshot(args.root,'native-version-nm-checks',report)
    print(json.dumps(dict(report=str(target),cases=len(report['cases']))))
