"""Offline execution of the complete common launcher transport, with HTTP fixtures."""
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
SHA='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
KEYS=(
    ('Accept',0x1411b5090,0x148ae4c30,0x14b564718),
    ('accessToken',0x1411b50c0,0x14952cb68,0x14b564698),
    ('authToken',0x1411b50f0,0x14952cbb8,0x14b5646c8),
    ('buildCode',0x1411b5120,0x14952cbe8,0x14b5646e8),
    ('Content-Type',0x1411b51e0,0x148aebc00,0x14b5646f8),
    ('gameCode',0x1411b5390,0x14952cbd0,0x14b5646d8),
)


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def run():
    h=load('native-request-harness-11316').make_harness(
        {'run-cea84c0140a4':'dc9945d73e758aec186dbd2fe0c0cf42952e4b2451a437c29cf22d6dda9b08f6',
         'run-89bc7497bac0':'f9cc85c42ef46d269cd4095d5157617109803a919eb5d64c2b57be14a10f8588'},
        {0x1445231a0}|{key[1] for key in KEYS},source_sha256=SHA,copy_thunk=None)
    native=load('build-native-entry-code');shapes=load('audit-launcher-shape-11318')
    checked={int(f['address'],16):shapes.normalize_function(native,h.image,f) for f in h.fragments}
    uc,x,b=h.uc,h.x,h.scratch
    manager,output,route,body,headers,delegate,request,table,factory,ftable,context,cdata,holder=[b+n for n in
        (0x1000,0x2000,0x3000,0x4000,0x5000,0x6000,0x7000,0x8000,0x9000,0xa000,0xb000,0xc000,0xd000)]
    tls=0x30000000;uc.mem_map(tls,0x110000)
    current={};events=[]
    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def get(at,size=8):return int.from_bytes(uc.mem_read(at,size),'little')
    def put(at,value,size=8):uc.mem_write(at,int(value).to_bytes(size,'little'))
    def string(at,value):
        pointer=b+0x18000+current.get('strings',0)*0x200
        current['strings']=current.get('strings',0)+1
        if current['strings']>32:raise ValueError('Bounded string budget')
        encoded=(value+'\0').encode('utf-16le');uc.mem_write(pointer,encoded)
        put(at,pointer);put(at+8,len(value)+1,4);put(at+12,len(value)+1,4)
    def read_string(at):
        count=get(at+8,4)
        if count>255:raise ValueError('Bounded string length')
        return bytes(uc.mem_read(get(at),count*2)).decode('utf-16le').rstrip('\0') if count else ''
    def allocator(machine):
        if reg('RCX')!=0x60:raise ValueError('Callback holder allocation differs')
        put(reg('RDX'),holder);put(reg('RDX')+8,1,4);h.finish(holder)
    def make_request(machine):
        if reg('RCX')!=factory or reg('RDX')!=output:raise ValueError('Request factory arguments differ')
        put(output,request);put(output+8,0);events.append('create');h.finish(output)
    def service(machine):
        if reg('RCX')!=manager:raise ValueError('Service context differs')
        out=reg('RDX');put(out,context);put(out+8,0);h.finish(out)
    def readiness(machine):
        if reg('RDX')!=context:raise ValueError('Service readiness input differs')
        put(reg('RCX'),context);put(reg('RCX')+8,0);h.finish(reg('RCX'))
    def ascii_string(machine):
        value=bytearray()
        for i in range(128):
            c=get(reg('RDX')+i,1)
            if not c:break
            value.append(c)
        else:raise ValueError('Bounded literal exceeded')
        string(reg('RCX'),value.decode('ascii'));h.finish(reg('RCX'))
    def wide_string(machine):
        label,entry,literal,global_at=current['key']
        if reg('RCX')!=global_at or reg('RDX')!=literal:
            raise ValueError('Header initializer arguments differ')
        off=h.image.offset(literal-h.image.pe.base);encoded=(label+'\0').encode('utf-16le')
        if h.raw[off:off+len(encoded)]!=encoded:raise ValueError('Header literal differs')
        # Borrow the immutable literal; this fixture does not emulate FString allocation.
        put(global_at,literal);put(global_at+8,len(label)+1,4);put(global_at+12,len(label)+1,4)
        h.finish(global_at)
    def header(machine):
        if reg('RCX')!=request:raise ValueError('Header receiver differs')
        events.append(['header',read_string(reg('RDX')),read_string(reg('R8'))]);h.finish()
    def set_url(machine):
        if reg('RCX')!=request or reg('RDX')!=route:raise ValueError('URL forwarding differs')
        events.append('url');h.finish()
    def method(machine):
        if reg('RCX')!=request:raise ValueError('Method receiver differs')
        events.append(['method',read_string(reg('RDX'))]);h.finish()
    def set_body(machine):
        if reg('RCX')!=request or reg('RDX')!=body:raise ValueError('Body forwarding differs')
        events.append('body');h.finish()
    def bind(machine):
        if reg('RCX')!=b+0xe000 or reg('RDX')!=manager:
            raise ValueError('Completion binding context differs')
        if get(reg('R8'))!=0x144538a40:raise ValueError('Completion thunk differs')
        if get(reg('R9'))!=holder:raise ValueError('Completion holder differs')
        events.append('bind');h.finish()
    def send(machine):
        if reg('RCX')!=request:raise ValueError('Send receiver differs')
        events.append('send');h.finish(1)
    def destroy(machine):
        if reg('RCX')!=holder or reg('RDX')!=0:raise ValueError('Holder cleanup differs')
        events.append('holder-destroy');h.finish()
    def cleanup(machine):
        if reg('RDX')!=0 or reg('R8')!=0 or reg('R9')!=0x10:
            raise ValueError('Holder container cleanup differs')
        put(reg('RCX'),0);events.append('container-cleanup');h.finish()
    fixture_targets={0x14142d090:allocator,0x14142ef00:lambda machine:h.finish(),
        0x141c06cf0:lambda machine:h.finish(factory),0x14452ab90:service,
        0x1445268e0:readiness,0x141426950:ascii_string,0x141426b30:wide_string,
        0x1487e976c:lambda machine:h.finish(),
        0x1444b22e0:lambda machine:h.finish(context),0x1444b1730:lambda machine:h.finish(context),
        0x1445323c0:lambda machine:(string(reg('RCX'),'fixture-build-code'),h.finish(reg('RCX'))),
        0x144511700:bind,0x141483080:lambda machine:h.finish(),0x141436cc0:cleanup,
        0x1487e9300:lambda machine:h.finish(reg('RAX'))}
    for slot,fn in ((0x68,set_url),(0xb0,header),(0x60,method),(0x90,set_body),
                    (0xf0,lambda machine:h.finish(b+0xe000)),(0xe8,send)):
        target=b+0x10000+slot;put(table+slot,target);fixture_targets[target]=fn
    put(ftable+0x40,b+0x11000);fixture_targets[b+0x11000]=make_request
    holder_destructor=int.from_bytes(h.raw[h.image.offset(0x14947d8a0-h.image.pe.base):
        h.image.offset(0x14947d8a0-h.image.pe.base)+8],'little')
    fixture_targets[holder_destructor]=destroy
    for at,fn in fixture_targets.items():h.add_fixture(at,fn)
    for key in KEYS:
        current['key']=key;h.call(key[1])
        if read_string(key[3])!=key[0]:raise ValueError('Initialized header key differs')
    uc.reg_write(x.UC_X86_REG_GS_BASE,tls)
    put(tls+0x58,tls+0x100);put(tls+0x100,tls+0x200)
    # Explicit initialized TLS and disabled diagnostic/network-error CVars.
    for at,size in ((0x14b6a6c20,4),(0x14b5653a8,4),(0x14b5653a0,8),(0x14b5652e0,1)):
        put(at,0,size)
    cases=[]
    for has_body in (False,True):
     for has_auth in (False,True):
        events.clear();current.clear()
        uc.mem_write(b+0x35000,bytes(0x3000))
        for at in (manager,output,route,body,headers,delegate,request,factory,context,cdata,holder):
            uc.mem_write(at,bytes(0x180))
        put(request,table);put(factory,ftable);put(context+0x110,cdata)
        string(route,'https://offline.invalid/launcher/token')
        string(body,'{}' if has_body else '');string(cdata+0x38,'fixture-game-code')
        string(cdata+0x78,'fixture-auth' if has_auth else '')
        original={at:bytes(uc.mem_read(at,0x100)) for at in (manager,route,body,headers,delegate,cdata)}
        stack=b+0x38000;put(stack+0x28,body);put(stack+0x30,delegate)
        uc.reg_write(x.UC_X86_REG_RDX,output);uc.reg_write(x.UC_X86_REG_R8,route)
        uc.reg_write(x.UC_X86_REG_R9,headers)
        result=h.call(0x1445231a0,manager)
        if result!=output or get(output)!=request:raise ValueError('Returned request handle differs')
        if any(bytes(uc.mem_read(at,len(value)))!=value for at,value in original.items()):
            raise ValueError('Borrowed request inputs changed')
        if events.count('send')!=1 or events.count('body')!=int(has_body):raise ValueError('Send/body count differs')
        headers_seen=[e for e in events if isinstance(e,list) and e[0]=='header']
        if len(headers_seen)!=4+2*int(has_auth):raise ValueError('Default header count differs')
        if ['method','POST'] not in events:raise ValueError('HTTP method differs')
        cases.append(dict(body_present=has_body,auth_present=has_auth,events=events.copy()))
    audit=load('audit-client-release')
    report=dict(source_sha256=SHA,tool_sha256=audit.sha256(Path(__file__)),exports=h.evidence,
        instructions=len(checked[0x1445231a0]['shape']),header_keys=[dict(name=k[0],initializer=hex(k[1]),
            literal=hex(k[2]),global_address=hex(k[3])) for k in KEYS],
        cases=cases,fixture_targets=[hex(a) for a in sorted(fixture_targets)],
        native_execution=True,network_used=False,profile_activation=False,compatibility='not_established',
        limits=['Whole common transport with non-null service/request and empty input callback/custom headers only.',
            'HTTP methods, allocation, FString conversion, SDK context, binding and cleanup are fixtures; no actual JSON serialization, response or network.',
            'Send fixture always returns true; error/logging/CVar initialization and nonempty custom header iteration remain unexecuted.'])
    target=audit.save_snapshot(h.root/'code-clues/launcher-common-11318',report)
    return target,report


if __name__=='__main__':
    path,result=run();print(json.dumps(dict(artifact=str(path),cases=len(result['cases']))))
