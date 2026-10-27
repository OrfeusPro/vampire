"""Whole launcher caller handoff with synthetic identity/credential/JSON/HTTP boundaries."""
import copy
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
SHA='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
BUILDS=(('A',0x1411b3260,0x148a49f74,0x14b5648d8),
        ('B',0x1411b3290,0x1489f1014,0x14b5648e8),
        ('C',0x1411b32c0,0x1489ff7b8,0x14b5648f8))


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def run():
    keys=load('audit-launcher-references-11318').KEYS
    h=load('native-request-harness-11316').make_harness(
        {'run-5e88e50e265d':'8a81049376b63fbb7b476c3381aae08b0f9e325360c73ddf249f2108e3d799b4',
         'run-652644c53992':'fd7a0e84eb9246d0eaa4b57e864eb1e4c99d41609e705a3f4c1e1dd61a9f22ad',
         'run-934cf393e845':'66bf70420bebe7cf3530e7fee7cb01459629459bb78a0b309850954a696516d9',
         'run-1a7e48a82067':'f63ec39e371d6757c1fa8889657fc53368f71723bcc46217823baac17fa38fe9'},
        {0x1444eecd0,0x144503e10,0x1445323c0}|{k[1] for k in keys+BUILDS},
        source_sha256=SHA,copy_thunk=0x1487f60d9)
    native=load('build-native-entry-code');shapes=load('audit-launcher-shape-11318')
    coverage={f['address']:len(shapes.normalize_function(native,h.image,f)['shape']) for f in h.fragments}
    uc,x,b=h.uc,h.x,h.scratch
    owner,credential_pair,callback,credential,ctable,module,data,service,transport,capture=[b+n for n in
        (0x1000,0x2000,0x3000,0x5000,0x6000,0x7000,0x8000,0x9000,0xa000,0xb000)]
    current={};values={};maps={};sent=[]
    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def get(at,size=8):return int.from_bytes(uc.mem_read(at,size),'little')
    def put(at,value,size=8):uc.mem_write(at,int(value).to_bytes(size,'little'))
    def string(at,text):
        number=current.get('strings',0);current['strings']=number+1
        if number>=48:raise ValueError('Caller fixture string budget')
        encoded=(text+'\0').encode('utf-16le')
        if len(encoded)>0x200:raise ValueError('Caller fixture string size')
        pointer=b+0x18000+number*0x200;uc.mem_write(pointer,encoded)
        put(at,pointer);put(at+8,len(encoded)//2,4);put(at+12,len(encoded)//2,4)
    def text(at):
        count=get(at+8,4)
        if count>4096:raise ValueError('Caller fixture FString bound')
        return bytes(uc.mem_read(get(at),count*2)).decode('utf-16le').rstrip('\0') if count else ''
    def wide(machine):
        key=current['key'];label,entry,literal,global_at=key
        if reg('RCX')!=global_at or reg('RDX')!=literal:raise ValueError('Request key constructor differs')
        encoded=(label+'\0').encode('utf-16le');off=h.image.offset(literal-h.image.pe.base)
        if h.raw[off:off+len(encoded)]!=encoded:raise ValueError('Request key literal differs')
        pointer=literal
        if key in BUILDS:
            pointer=b+0x14000+0x200*BUILDS.index(key);uc.mem_write(pointer,encoded)
        put(global_at,pointer);put(global_at+8,len(label)+1,4);put(global_at+12,len(label)+1,4);h.finish(global_at)
    def ascii_string(machine):
        pointer=reg('RDX');result=bytearray()
        for i in range(128):
            byte=get(pointer+i,1)
            if not byte:break
            result.append(byte)
        else:raise ValueError('Caller ASCII literal bound')
        string(reg('RCX'),result.decode('ascii'));h.finish(reg('RCX'))
    def service_getter(machine):
        if reg('RCX')!=owner:raise ValueError('Caller service owner differs')
        out=reg('RDX');put(out,service);put(out+8,0);h.finish(out)
    def auth_getter(machine):
        if reg('RDX')!=service:raise ValueError('Caller auth service differs')
        out=reg('RCX');put(out,service);put(out+8,0);h.finish(out)
    def identity(machine,name,settings=False):
        if settings and reg('RCX')!=data:raise ValueError('Identity settings receiver differs')
        if name=='deviceKey' and reg('R8')&0xff!=1:raise ValueError('Device key flag differs')
        out=reg('RDX') if settings else reg('RCX');string(out,current['profile'][name]);h.finish(out)
    def value_wrapper(machine,object_value=False):
        value=copy.deepcopy(maps[reg('RDX')]) if object_value else text(reg('RDX'))
        pointer=b+0x24000+len(values)*0x40;values[pointer]=value
        out=reg('RCX');put(out,pointer);put(out+8,0);h.finish(out)
    def map_constructor(machine):
        out=reg('RCX');ranges=reg('RDX');start,end=get(ranges),get(ranges+8)
        if end-start!=4*16:raise ValueError('Caller initial field range differs')
        maps[out]={text(get(at)):copy.deepcopy(values[get(get(at+8))]) for at in range(start,end,16)}
        uc.mem_write(out,bytes(0x50));h.finish(out)
    def credential_object(machine):
        if reg('RCX')!=credential:raise ValueError('Credential object receiver differs')
        out=reg('RDX');uc.mem_write(out,bytes(0x38))
        maps[out]=copy.deepcopy(current['profile']['credentialObject']);h.finish(out)
    def string_setter(machine):
        maps[reg('RCX')][text(reg('RDX'))]=text(reg('R8'));h.finish()
    def field_setter(machine):
        pair=reg('R8');maps[reg('RCX')][text(get(pair))]=copy.deepcopy(values[get(get(pair+8))])
        put(reg('RDX'),0,4);h.finish()
    def lookup_url(machine):
        if reg('RCX')!=data or text(reg('RDX'))!='authUrl':raise ValueError('SDK authUrl lookup differs')
        string(reg('R8'),'https://offline.invalid/');h.finish(1)
    def reserve(machine):
        out=reg('RCX');capacity=reg('RDX')
        if capacity>128:raise ValueError('String allocation fixture differs')
        pointer=b+0x23000;uc.mem_write(pointer,bytes(0x200));put(out,pointer);put(out+12,capacity,4);h.finish()
    def append(machine):
        out=reg('RCX');suffix=bytes(uc.mem_read(reg('RDX'),reg('R8')*2)).decode('utf-16le')
        if suffix not in ('launcher/token','launcher/sign-in'):raise ValueError('Launcher suffix differs')
        string(out,text(out)+suffix);h.finish(out)
    def json_object(machine):
        out=reg('RCX');maps[out]=copy.deepcopy(maps[reg('RDX')]);uc.mem_write(out,bytes(0x38));h.finish(out)
    def serialize(machine):
        if reg('R8')!=1:raise ValueError('Launcher serializer mode differs')
        string(reg('RDX'),json.dumps(maps[reg('RCX')],ensure_ascii=False,separators=(',',':')));h.finish(reg('RDX'))
    def header_map(machine):
        out=reg('RCX');ranges=reg('RDX');start,end=get(ranges),get(ranges+8)
        if end-start!=16:raise ValueError('Launcher header range differs')
        maps[out]={text(get(start)):text(get(start+8))};uc.mem_write(out,bytes(0x50));h.finish(out)
    def callback_assignment(machine):
        expected=owner+(0x188 if current['kind']=='token' else 0x98)
        if reg('RCX')!=expected or reg('RDX')!=callback:raise ValueError('Caller delegate slot differs')
        h.finish()
    def transport_getter(machine):
        if reg('RCX')!=service:raise ValueError('Transport service source differs')
        h.finish(transport)
    def send(machine,kind):
        if reg('RCX')!=transport:raise ValueError('Caller transport pointer differs')
        stack=reg('RSP');is_token=kind=='token'
        body=reg('R9') if is_token else get(stack+0x28)
        delegate=get(stack+(0x28 if is_token else 0x30))
        if get(delegate)!=(0x1444df0b0 if is_token else 0x1444df1a0):raise ValueError('Caller completion pointer differs')
        sent.append(dict(kind=kind,url=text(reg('R8')),body=json.loads(text(body)),
            headers={} if is_token else copy.deepcopy(maps[reg('R9')]),serializer_mode=1))
        put(reg('RDX'),0);put(reg('RDX')+8,0)
        # The real wrappers move this delegate; the boundary fixture consumes it.
        put(delegate,0);put(delegate+0x10,0);h.finish(reg('RDX'))
    fixtures={0x141426b30:wide,0x1487e976c:lambda machine:h.finish(),0x141426950:ascii_string,
        0x1444c1090:callback_assignment,0x14452ab90:service_getter,0x14452c1d0:auth_getter,
        0x1444b1850:lambda machine:h.finish(module),0x1444b22e0:lambda machine:h.finish(module),
        0x1444ecb90:lambda machine:identity(machine,'nmDeviceKey'),
        0x1445293c0:lambda machine:identity(machine,'deviceKey',True),
        0x144528d00:lambda machine:identity(machine,'countryCode',True),
        0x1444ed250:lambda machine:identity(machine,'os'),
        0x144475a70:value_wrapper,0x144475620:lambda machine:value_wrapper(machine,True),
        0x1444c26d0:map_constructor,0x144488e90:string_setter,0x144470790:field_setter,
        0x14455a3a0:lookup_url,0x141436ed0:reserve,0x1414324d0:append,
        0x144474430:json_object,0x144489150:serialize,0x143bfd5f0:header_map,
        0x14452b580:transport_getter,0x144522f90:lambda machine:send(machine,'token'),
        0x144523110:lambda machine:send(machine,'signin'),
        0x14148fb60:lambda machine:h.finish(capture),
        0x144476600:lambda machine:h.finish(),0x141579060:lambda machine:h.finish(),
        0x141465560:lambda machine:h.finish(),0x141483080:lambda machine:h.finish(),
        0x1414720a0:lambda machine:h.finish(),0x1444c5b60:lambda machine:h.finish(),
        0x1487e9300:lambda machine:h.finish(reg('RAX')),b+0x12000:credential_object}
    for at,fn in fixtures.items():h.add_fixture(at,fn)
    for key in keys+BUILDS:current['key']=key;h.call(key[1])
    build_cases=[]
    for byte in range(256):
        out=b+0xc000;uc.mem_write(out,bytes(16));uc.reg_write(x.UC_X86_REG_RDX,byte)
        returned=h.call(0x1445323c0,out);actual=text(out)
        if returned!=out or actual!=('B' if byte==1 else 'C' if byte==2 else 'A'):
            raise ValueError('Native BuildCode byte mapping differs')
        build_cases.append(dict(byte=byte,value=actual))
    put(ctable+8,b+0x12000)
    profiles=[dict(nmDeviceKey='fixture-nm-A',deviceKey='fixture-device-A',countryCode='UA',os='fixture-Windows-A',
        gameCode='fixture-game-A',buildByte=1,buildCode='B',
        credentialObject={'channelCode':33,'channelAccessToken':'fixture-provider-A'}),
        dict(nmDeviceKey='тест-nm-B',deviceKey='device.+/=B',countryCode='KR',os='fixture-Windows-B',
        gameCode='fixture-game-B',buildByte=2,buildCode='C',credentialObject={'fixtureField':'строка "Б"'})]
    cases=[]
    for profile in profiles:
     for kind,present,token in (('token',False,''),('token',True,''),('signin',True,''),('signin',True,'fixture.+/=_token')):
        current.clear();current.update(profile=profile,kind=kind);values.clear();maps.clear();sent.clear()
        uc.mem_write(b+0x35000,bytes(0x3000))
        for at,size in ((owner,0x300),(credential_pair,0x100),(callback,0x100),(credential,0x100),
                        (module,0x180),(data,0x180),(capture,0x100)):
            uc.mem_write(at,bytes(size))
        put(module+0x110,data);put(credential_pair,credential if present else 0);put(credential,ctable)
        string(credential+0x58,token);string(data+0x38,profile['gameCode']);put(data+0x48,profile['buildByte'],1)
        uc.reg_write(x.UC_X86_REG_RDX,credential_pair);uc.reg_write(x.UC_X86_REG_R8,callback)
        h.call(0x1444eecd0 if kind=='token' else 0x144503e10,owner)
        if len(sent)!=1:raise ValueError('Caller handoff count differs')
        expected={k:profile[k] for k in ('nmDeviceKey','deviceKey','countryCode','os')}
        if kind=='token' and present:
            expected['credential']=dict(profile['credentialObject'],
                gameCode=profile['gameCode'],buildCode=profile['buildCode'])
        if sent[0]['body']!=expected:raise ValueError('Caller field projection differs')
        if sent[0]['headers']!=({} if kind=='token' else {'launcherToken':token}):
            raise ValueError('Caller header projection differs')
        if sent[0]['url']!='https://offline.invalid/launcher/'+('token' if kind=='token' else 'sign-in'):
            raise ValueError('Caller route differs')
        cases.append(dict(fixture=copy.deepcopy(profile),credential_present=present,launcher_token_empty=not token,**sent[0]))
    audit=load('audit-client-release')
    report=dict(source_sha256=SHA,tool_sha256=audit.sha256(Path(__file__)),exports=h.evidence,
        coverage=coverage,copy_import=h.copy_import,build_cases=build_cases,cases=cases,
        fixture_targets=[hex(a) for a in sorted(fixtures)],
        native_execution=True,network_used=False,profile_activation=False,compatibility='not_established',
        limits=['Whole callers, BuildCode formatter and eleven key/constant initializers execute with synthetic identities, service/settings, credential object, JSON/map/string and transport fixtures.',
            'JSON writer uses Python json.dumps as a boundary fixture; actual engine formatting/escaping and SDK identity/credential provenance remain unverified.',
            'Callbacks are empty; owner weak reference and shared control blocks are null. Error/expired-owner/active-callback/refcount destruction branches remain unexecuted.',
            'Only request preparation and one handoff are checked; no HTTP, response parsing, profile activation or live auth.'])
    target=audit.save_snapshot(h.root/'code-clues/launcher-caller-fields-11318',report)
    return target,report


if __name__=='__main__':
    path,result=run();print(json.dumps(dict(artifact=str(path),cases=len(result['cases']))))
