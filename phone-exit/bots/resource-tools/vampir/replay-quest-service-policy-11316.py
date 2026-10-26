"""Native nonzero service-group policy with explicit synthetic manager/TLS state."""
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def run():
    audit=load('audit-client-release'); path=HERE/'knowledge/native-contexts/quest-service-policy-11316.json'
    context=json.loads(path.read_text('utf-8'))
    h=load('native-request-harness-11316').make_harness(context['exports'],{0x145a4d2f0,0x145bfe3d0,0x145c022b0},
        leaves={int(a,16):b for a,b in context['leaves'].items()})
    if any(not f.get('block_coverage_complete') for f in h.fragments): raise ValueError('Policy coverage incomplete')
    uc,x,base=h.uc,h.x,h.scratch
    manager=0x14b1c7890
    row,cells,gate,nodes,slots,record,version=[base+n for n in (0x1000,0x2000,0x3000,0x4000,0x5000,0x6000,0x7000)]
    blocks={}; cursor=[base+0x10000]; current={}; calls={}
    def reg(name): return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def put(at,value,size=8): uc.mem_write(at,(int(value)%(1 << (size*8))).to_bytes(size,'little'))
    def get(at,size=8): return int.from_bytes(uc.mem_read(at,size),'little')
    def count(name): calls[name]=calls.get(name,0)+1
    # Model the already-initialized TLS epoch only; init/runtime registration must remain unreachable.
    tls=0x29000000; uc.mem_map(tls,0x110000); uc.reg_write(x.UC_X86_REG_GS_BASE,tls)
    put(tls+0x58,tls+0x1000); put(tls+0x1000,tls+0x2000); put(tls+0x2000+0x101184,0,4)
    put(0x14b6a4c20,0,4); put(0x14b5f0930,0,4)
    def allocate(data):
        at=cursor[0]+16; size=len(data); cursor[0]=at+((size+15)&~15)+16
        if cursor[0]>=base+0x30000: raise ValueError('Policy allocation budget')
        uc.mem_write(at-16,b'L'*16+data+b'R'*16); blocks[at]=size
        return at
    def release(at):
        size=blocks.pop(at,None)
        if size is None or bytes(uc.mem_read(at-16,16))!=b'L'*16 or bytes(uc.mem_read(at+size,16))!=b'R'*16:
            raise ValueError('Policy allocation guards differ')
    def wide(ptr):
        data=bytearray()
        for i in range(64):
            b=bytes(uc.mem_read(ptr+i*2,2))
            if b==b'\0\0': return data.decode('utf-16le')
            data+=b
        raise ValueError('Policy string budget')
    def assign(at,text):
        data=text.encode('utf-16le')+b'\0\0'; ptr=allocate(data)
        put(at,ptr); put(at+8,len(data)//2,4); put(at+12,len(data)//2,4)
    def id_string(machine):
        if reg('RDX')!=current['server']: raise ValueError('Current numeric identifier differs')
        assign(reg('RCX'),str(current['server'])); count('id_string'); h.finish(reg('RCX'))
    def split(machine):
        source,destination=reg('RCX'),reg('RDX')
        if source not in (record+0x18,record+0x28) or reg('R9')!=1: raise ValueError('Policy list split scope')
        values=current['deny'] if source==record+0x18 else current['allow']
        uc.mem_write(destination,bytes(16))
        if values:
            ptr=allocate(bytes(16*len(values)))
            for i,text in enumerate(values): assign(ptr+i*16,text)
            put(destination,ptr); put(destination+8,len(values),4); put(destination+12,len(values),4)
        count('deny_split' if source==record+0x18 else 'allow_split'); h.finish(destination)
    def string_resize(machine):
        at,n=reg('RCX'),reg('RDX')
        if not 0<n<=64: raise ValueError('String copy budget')
        put(at,allocate(bytes(n*2))); put(at+12,n,4); h.finish()
    def compare(machine):
        count('compare'); h.finish(0 if wide(reg('RCX'))==wide(reg('RDX')) else 1)
    def destroy_array(machine):
        at,n=reg('RCX'),reg('RDX')
        if n>4: raise ValueError('List cleanup budget')
        for i in range(n): release(get(at+i*16))
        count('destroy_array'); h.finish()
    def free(machine): release(reg('RCX')); h.finish()
    def version_manager(machine): count('version_manager'); h.finish(base+0x7800)
    def version_lookup(machine):
        if reg('RCX')!=base+0x7800 or reg('RDX')!=current['server']: raise ValueError('Version lookup scope')
        count('version_lookup'); h.finish(version if current['version'] is not None else 0)
    for at,callback in ((0x141429f30,id_string),(0x141432310,split),(0x141436ed0,string_resize),
            (0x14145f1e0,compare),(0x141404ac0,destroy_array),(0x141483080,free),
            (0x145bfe250,version_manager),(0x145bfdcc0,version_lookup)):
        h.add_fixture(at,callback)
    def numeric_input():
        if reg('RCX')!=cells: raise ValueError('Service numeric cell pointer differs')
        return bytes(uc.mem_read(cells,16)).split(b'\0',1)[0]
    runtime=load('replay-quest-scalars-11316').install_runtime(h,numeric_input,base+0x8000)
    scenarios=[dict(name='empty',layout='empty',expected=1),dict(name='missing',layout='missing',expected=1),
        dict(name='empty-array',layout='empty-array',expected=1),dict(name='zero-server',server=0,expected=0),
        dict(name='type-mismatch',type_match=False,expected=1),dict(name='deny',deny=['42'],expected=1),
        dict(name='deny-before-allow',deny=['42'],allow=['42'],expected=1),dict(name='allow',allow=['42'],version=None,expected=0),
        dict(name='version-missing',version=None,expected=1),dict(name='below-min',version=9,expected=1),
        dict(name='at-min',version=10,expected=0),dict(name='middle',version=15,expected=0),
        dict(name='at-max',version=20,expected=0),dict(name='above-max',version=21,expected=1),
        dict(name='nonmatching-lists',deny=['7','8'],allow=['9'],version=15,expected=0)]
    cases=[]
    for external in (False,True):
      for scenario in scenarios:
        current.clear(); current.update(layout='normal',server=42,type_match=True,deny=[],allow=[],version=15)
        current.update(scenario); calls.clear(); blocks.clear(); cursor[0]=base+0x10000; runtime['calls'].clear()
        uc.mem_write(manager,bytes(0x88)); uc.mem_write(nodes,bytes(64)); uc.mem_write(record,bytes(64))
        uc.mem_write(row,bytes(64)); uc.mem_write(cells,bytes(32)); uc.mem_write(gate,bytes(32))
        put(row+0x20,1,4); put(row+0x28,cells); uc.mem_write(cells,b'10000\0'); put(cells+16,5); put(cells+24,15)
        put(gate+8,0,2); put(manager+0x78,7,4); put(manager+0x7c,current['server'],4)
        put(manager+0x28,nodes); put(manager+0x30,0 if current['layout']=='empty' else 1,4)
        put(manager+0x70,2,4); put(manager+0x60,0,4); put(manager+0x64,-1,4)
        if external:
            put(manager+0x68,base+0x9000); put(base+0x9000,0,4); put(base+0x9004,-1,4)
        put(nodes,10001 if current['layout']=='missing' else 10000,4); put(nodes+8,slots)
        put(nodes+16,0 if current['layout']=='empty-array' else 1,4); put(nodes+24,-1,4)
        put(slots,record); put(record+0xc,7 if current['type_match'] else 8,4)
        put(record+0x10,10,4); put(record+0x14,20,4); put(version+0x28,current['version'] or 0,4)
        immutable=[(at,bytes(uc.mem_read(at,n))) for at,n in ((manager,0x88),(nodes,64),(record,64),(row,64),(cells,32))]
        uc.reg_write(x.UC_X86_REG_RDX,row)
        result=h.call(0x145a4d2f0,gate)&255
        if result!=scenario['expected']: raise ValueError('Service policy differs '+str((scenario,result)))
        if runtime['calls']!=['atoi']: raise ValueError('Service gate did not use exact atoi path')
        if blocks or any(bytes(uc.mem_read(at,len(b)))!=b for at,b in immutable): raise ValueError('Policy state changed/leaked')
        cases.append(dict(name=scenario['name'],external_buckets=external,skip=result,callbacks=calls.copy()))
    runtime['verify']()
    report=dict(source_sha256=h.sha,tool_sha256=audit.sha256(Path(__file__)),context_sha256=audit.sha256(path),exports=h.evidence,
        system_runtime=runtime['system_runtime'],imported=runtime['imported'],cases=cases,native_execution=True,
        network_used=False,order_admitted=False,limits=context['limits'])
    target=audit.save_snapshot(h.root/'code-clues/quest-service-policy-11316',report)
    return target,report


if __name__=='__main__':
    target,result=run(); print(json.dumps(dict(artifact=str(target),cases=len(result['cases'])),ensure_ascii=False))
