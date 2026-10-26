"""Native service environment setter: lookup/fallback and change flags."""
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def run():
    audit=load('audit-client-release'); path=HERE/'knowledge/native-contexts/quest-service-setup-11316.json'
    context=json.loads(path.read_text('utf-8'))
    h=load('native-request-harness-11316').make_harness(context['exports'],{0x145c21f20})
    if not all(f.get('block_coverage_complete') and f.get('direct_flow_coverage_complete') for f in h.fragments):
        raise ValueError('Service setter coverage incomplete')
    caller_path=h.root/'ghidra/request-exports'/h.sha/context['caller_run']/'details.json'
    if audit.sha256(caller_path)!=context['caller_sha256']: raise ValueError('Caller export changed')
    caller=next(f for f in json.loads(caller_path.read_text('utf-8'))['functions'] if f['address']=='0x14679aec0')
    instructions={r['address']:r['bytes'] for r in caller['instructions']}
    for address,expected in {'0x14679b2ca':'e8013146ff','0x14679b2cf':'8b970c030000','0x14679b2e2':'e8396c48ff'}.items():
        off=h.image.offset(int(address,16)-h.image.pe.base)
        if instructions.get(address)!=expected or h.raw[off:off+len(bytes.fromhex(expected))].hex()!=expected:
            raise ValueError('Selected server setter call changed')
    uc,x,base=h.uc,h.x,h.scratch
    manager,provider=base+0x1000,base+0x2000
    current={}; calls=[]
    def reg(name): return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def put(at,value,size=4): uc.mem_write(at,(int(value)%(1 << (size*8))).to_bytes(size,'little'))
    def get(at,size=4): return int.from_bytes(uc.mem_read(at,size),'little')
    def getter(machine): calls.append('provider'); h.finish(provider)
    def lookup(machine):
        if reg('RCX')!=provider or reg('RDX')!=base+0x38010:
            raise ValueError('Region lookup contract differs')
        calls.append('lookup')
        if current['found']: put(reg('RDX'),current['region'])
        h.finish(int(current['found']))
    h.add_fixture(0x14556ae90,getter); h.add_fixture(0x14556b8b0,lookup)
    cases=[]
    for region in (0,4,7):
     for server in (0,256,0xffffffff):
      for found in (False,True):
       for dirty in (0,1):
        for same_region in (False,True):
         for same_server in (False,True):
            current.update(region=region,found=found); calls.clear()
            uc.mem_write(manager-16,b'A'*16+bytes(0x90)+b'B'*16)
            uc.mem_write(provider,b'P'*0xb0); put(provider+0xa8,region)
            put(manager+0x78,region if same_region else region+100)
            put(manager+0x7c,server if same_server else server^0x55)
            put(manager+0x80,dirty,1); put(manager+0x81,0,1)
            immutable=bytes(uc.mem_read(provider,0xb0)); before=bytearray(uc.mem_read(manager-16,0xb0))
            uc.reg_write(x.UC_X86_REG_RDX,server); h.call(0x145c21f20,manager)
            expected_dirty=int(bool(dirty or not same_region or not same_server))
            if (get(manager+0x78),get(manager+0x7c),get(manager+0x80,1),get(manager+0x81,1))!=(region,server,expected_dirty,1):
                raise ValueError('Service setter fields/flags differ')
            if calls!=(['provider','lookup'] if found else ['provider','lookup','provider']):
                raise ValueError('Service lookup/fallback path differs')
            for offset,size in ((0x78,4),(0x7c,4),(0x80,2)):
                before[16+offset:16+offset+size]=uc.mem_read(manager+offset,size)
            if bytes(before)!=bytes(uc.mem_read(manager-16,0xb0)) or bytes(uc.mem_read(provider,0xb0))!=immutable:
                raise ValueError('Service setter changed other fields/guards/provider')
            cases.append(dict(region=region,server=server,lookup_found=found,initial_dirty=dirty,
                same_region=same_region,same_server=same_server,dirty=expected_dirty,calls=calls.copy()))
    report=dict(source_sha256=h.sha,tool_sha256=audit.sha256(Path(__file__)),context_sha256=audit.sha256(path),exports=h.evidence,
        caller=dict(path=str(caller_path),sha256=context['caller_sha256']),cases=cases,native_execution=True,
        network_used=False,active_region_verified=False,order_admitted=False,limits=context['limits'])
    target=audit.save_snapshot(h.root/'code-clues/quest-service-setup-11316',report)
    return target,report


if __name__=='__main__':
    target,result=run(); print(json.dumps(dict(artifact=str(target),cases=len(result['cases'])),ensure_ascii=False))
