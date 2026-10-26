"""Native service environment setter: lookup/fallback and change flags."""
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def run(context_path=None):
    audit=load('audit-client-release')
    path=Path(context_path) if context_path else HERE/'knowledge/native-contexts/quest-service-setup-11316.json'
    context=json.loads(path.read_text('utf-8'))
    native_lookup=context.get('native_lookup') is True
    native_key=context.get('native_key') is True
    native_identity=context.get('native_identity') is True
    functions={0x145c21f20,0x14556b8b0} if native_lookup else {0x145c21f20}
    if native_key: functions.add(0x14556b740)
    if native_identity: functions.add(0x14560b900)
    h=load('native-request-harness-11316').make_harness(context['exports'],
        functions,
        leaves={int(a,0):b for a,b in context.get('leaves',{}).items()})
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
    blocks={}; cursor=[base+0x10000]
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
    if native_lookup:
        def wide(ptr):
            data=bytearray()
            for i in range(128):
                raw=bytes(uc.mem_read(ptr+i*2,2))
                if raw==b'\0\0': return data.decode('utf-16le')
                data+=raw
            raise ValueError('Config key string budget')
        def descriptor(at): return wide(get(at,8)) if get(at+8,4) else ''
        def assign(at,text):
            uc.mem_write(at,bytes(16))
            if text:
                raw=text.encode('utf-16le')+b'\0\0'; ptr=cursor[0]+16; cursor[0]=ptr+((len(raw)+15)&~15)+16
                if cursor[0]>=base+0x30000: raise ValueError('Config key allocation budget')
                uc.mem_write(ptr-16,b'L'*16+raw+b'R'*16); blocks[ptr]=len(raw)
                put(at,ptr,8); put(at+8,len(raw)//2); put(at+12,len(raw)//2)
        def wide_init(machine):
            assign(reg('RCX'),wide(reg('RDX'))); h.finish(reg('RCX'))
        def key(machine):
            if reg('RCX')!=provider: raise ValueError('Dynamic config key scope')
            calls.append('key'); assign(reg('RDX'),'SyntheticRegionKey'); h.finish(reg('RDX'))
        def read_config(machine):
            name=descriptor(reg('RCX'))
            expected=current.get('primary_key','SyntheticRegionKey') if not current['read_count'] else 'RegionSelect'
            if name!=expected or descriptor(reg('R8'))!='' or current['read_count']>=2:
                raise ValueError('Region config read contract differs')
            current['read_count']+=1; calls.append('read:'+name)
            success=current['lookup_path']=='primary' or name=='RegionSelect' and current['lookup_path']=='legacy'
            if success: put(reg('RDX'),current['region'])
            h.finish(int(success))
        def write_config(machine):
            name=descriptor(reg('RCX'))
            expected=current.get('primary_key','SyntheticRegionKey') if not current['write_count'] else 'RegionSelect_PreLogin'
            if name!=expected or reg('RDX')!=current['region'] or descriptor(reg('R8'))!='' or current['write_count']>=2:
                raise ValueError('Region config write contract differs')
            current['write_count']+=1; calls.append('write:'+name); h.finish()
        def free(machine):
            ptr=reg('RCX'); size=blocks.pop(ptr,None)
            if size is None or bytes(uc.mem_read(ptr-16,16))!=b'L'*16 or bytes(uc.mem_read(ptr+size,16))!=b'R'*16:
                raise ValueError('Config string free/guards differ')
            h.finish()
        put(0x14b5e4788,provider,8)
        callbacks=[(0x141426b30,wide_init),(0x1445ceaa0,read_config),(0x1445d7220,write_config),(0x141483080,free)]
        if native_key:
            def engine(machine): h.finish(base+0x4000 if current['profile']!='absent' else 0)
            def identity(machine): h.finish(base+0x5000)
            def resize(machine):
                at,n=reg('RCX'),reg('RDX')
                if not 0<n<=128: raise ValueError('Identity string resize budget')
                ptr=cursor[0]+16; size=n*2; cursor[0]=ptr+((size+15)&~15)+16
                uc.mem_write(ptr-16,b'L'*16+bytes(size)+b'R'*16); blocks[ptr]=size
                put(at,ptr,8); put(at+12,n); h.finish()
            def format_key(machine):
                if reg('RDX')!=0x1498fd618 or wide(reg('RDX'))!='RegionSelect_%s':
                    raise ValueError('Native region key format differs')
                value=wide(reg('R8'))
                if value!=current['identity']: raise ValueError('Native identity input differs')
                assign(reg('RCX'),'RegionSelect_'+value); h.finish(reg('RCX'))
            callbacks += [(0x14560ad80,engine),(0x141436ed0,resize),(0x141433340,format_key)]
            if native_identity:
                def platform(machine): h.finish(base+0x7000)
                def initialize(machine):
                    if reg('RCX')!=base+0x7000: raise ValueError('Identity initialization receiver differs')
                    calls.append('identity-init')
                    if current['profile']=='new-subsystem': put(base+0x7110,base+0x8000,8)
                    h.finish()
                def fetch_identity(machine):
                    if reg('RCX')!=base+0x8000: raise ValueError('Identity subsystem receiver differs')
                    calls.append('identity-fetch'); assign(reg('RDX'),current['identity']); h.finish(reg('RDX'))
                callbacks += [(0x1444b1550,platform),(0x1416b0660,initialize),(0x14452b620,fetch_identity)]
            else: callbacks.append((0x14560b900,identity))
        else: callbacks.append((0x14556b740,key))
        for at,callback in callbacks:
            h.add_fixture(at,callback)
    else:
        h.add_fixture(0x14556ae90,getter); h.add_fixture(0x14556b8b0,lookup)
    cases=[]
    for region in ((0,4,7,8,9,10) if native_identity else (0,4,7,8) if native_key else (0,4,7)):
     for server in (0,256,0xffffffff):
      for lookup_path in (('primary','legacy','missing') if native_lookup else ('missing','primary')):
       for dirty in (0,1):
        for same_region in (False,True):
         for same_server in (False,True):
            found=lookup_path!='missing'
            current.update(region=region,found=found,lookup_path=lookup_path,read_count=0,write_count=0); calls.clear()
            blocks.clear(); cursor[0]=base+0x10000
            if native_key:
                profile={0:'absent',4:'account-a',7:'account-b',8:'empty',9:'failed-subsystem',10:'new-subsystem'}[region]
                text={'absent':'','empty':'','failed-subsystem':'cached-c','new-subsystem':'account-d'}.get(profile,profile)
                current.update(profile=profile,identity=text,primary_key='RegionSelect_'+text if text else 'RegionSelect_PreLogin')
                uc.mem_write(base+0x4000,bytes(0x80)); put(base+0x4038,base+0x6000,8)
                uc.mem_write(base+0x5000,bytes(16))
                if text:
                    raw=text.encode('utf-16le')+b'\0\0'; uc.mem_write(base+0x5100,raw)
                    put(base+0x5000,base+0x5100,8); put(base+0x5008,len(raw)//2); put(base+0x500c,len(raw)//2)
                if native_identity:
                    uc.mem_write(base+0x5ff0,b'C'*16+bytes(0x80)+b'D'*16); uc.mem_write(base+0x7000,bytes(0x120))
                    put(base+0x7110,0 if profile in ('failed-subsystem','new-subsystem') else base+0x8000,8)
                    assign(base+0x6048,'cached-c' if profile=='failed-subsystem' else 'previous-cache')
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
            if native_lookup:
                primary_key=current.get('primary_key','SyntheticRegionKey')
                expected_calls=([] if native_key else ['key'])+['read:'+primary_key]
                if lookup_path!='primary': expected_calls+=['read:RegionSelect']
                if lookup_path=='legacy': expected_calls+=([] if native_key else ['key'])+['write:'+primary_key,'write:RegionSelect_PreLogin']
                actual_calls=[value for value in calls if not value.startswith('identity-')]
                if actual_calls!=expected_calls: raise ValueError('Native config path differs')
                if native_identity:
                    expected_cache='previous-cache' if current['profile']=='absent' else current['identity']
                    if descriptor(base+0x6048)!=expected_cache: raise ValueError('Identity cache result differs')
                    cached_object=bytearray(uc.mem_read(base+0x6000,0x80)); cached_object[0x48:0x58]=bytes(16)
                    if any(cached_object) or bytes(uc.mem_read(base+0x5ff0,16))!=b'C'*16 or bytes(uc.mem_read(base+0x6080,16))!=b'D'*16:
                        raise ValueError('Identity getter changed other fields/guards')
                    if get(base+0x6048,8):
                        ptr=get(base+0x6048,8); size=blocks.pop(ptr,None)
                        if size is None or bytes(uc.mem_read(ptr-16,16))!=b'L'*16 or bytes(uc.mem_read(ptr+size,16))!=b'R'*16:
                            raise ValueError('Owned identity cache guard differs')
                if blocks: raise ValueError('Native config path leaked temporary strings')
            elif calls!=(['provider','lookup'] if found else ['provider','lookup','provider']):
                raise ValueError('Service lookup/fallback path differs')
            for offset,size in ((0x78,4),(0x7c,4),(0x80,2)):
                before[16+offset:16+offset+size]=uc.mem_read(manager+offset,size)
            if bytes(before)!=bytes(uc.mem_read(manager-16,0xb0)) or bytes(uc.mem_read(provider,0xb0))!=immutable:
                raise ValueError('Service setter changed other fields/guards/provider')
            cases.append(dict(region=region,server=server,lookup_found=found,initial_dirty=dirty,
                same_region=same_region,same_server=same_server,dirty=expected_dirty,calls=calls.copy()))
            if native_lookup: cases[-1]['lookup_path']=lookup_path
            if native_key: cases[-1].update(profile=current['profile'],primary_key=current['primary_key'])
    report=dict(source_sha256=h.sha,tool_sha256=audit.sha256(Path(__file__)),context_sha256=audit.sha256(path),exports=h.evidence,
        caller=dict(path=str(caller_path),sha256=context['caller_sha256']),cases=cases,native_execution=True,
        network_used=False,active_region_verified=False,order_admitted=False,limits=context['limits'])
    if native_lookup: report['native_lookup']=True
    if native_key: report['native_key']=True
    if native_identity: report['native_identity']=True
    target=audit.save_snapshot(h.root/('code-clues/quest-service-identity-11316' if native_identity else
        'code-clues/quest-service-key-11316' if native_key else
        'code-clues/quest-service-region-11316' if native_lookup else 'code-clues/quest-service-setup-11316'),report)
    return target,report


if __name__=='__main__':
    target,result=run(); print(json.dumps(dict(artifact=str(target),cases=len(result['cases'])),ensure_ascii=False))
