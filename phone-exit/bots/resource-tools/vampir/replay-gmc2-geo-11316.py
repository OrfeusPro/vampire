"""Current GMC2 geo bindings and native country update; synthetic JSON helpers."""
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
EXPORTS={
 'run-0cdca2f717ea':'e5667cf351382f2ae5d7454010f6526cb24d0a11b49e86e87eb652c64babaf34',
 'run-777fc0535ec7':'a0509eeaa329af68616c59bbb695a7440c1487aaa894f808615cebe0139bf2fa',
 'run-e780fb3fe6db':'0967705efbbe8b625a2176a36ee903b39020d9c6e6b714e4d5ab903ef4b1b2f4',
 'run-22a80de53437':'67dabcb549a4b24d5d89df01904966cda40ac129a0536804c2718c2c070afcdf',
 'run-c7fac48d96a1':'4a966a1a0f30e281fe55f90fb72b38362a5ec9d07232b5cc0e908856e470881a',
 'run-aa8c16b9c37f':'68a258e1f298e7e607337b366ef673deb7af1fece47a33bf24442fbc9647cd0e'}


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def replay(root=None):
    native=load('geo_source',HERE/'build-native-entry-code.py')
    root=Path(root) if root else native.ROOT
    source=root/'client-code-snapshots/d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960/ProjectRED-Win64-Shipping.exe'
    raw=source.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=source.parent.name: raise ValueError('GMC2 geo source changed')
    image=native.Image(raw); off=image.offset(0x14145f1e0-image.pe.base); compare=raw[off:off+71]
    if hashlib.sha256(compare).hexdigest()!='591d6b9ae17a1ebc090ce3e9b853202de35bfecd86a36324752503d4548097c0':
        raise ValueError('GMC2 country compare changed')
    harness=load('geo_harness',HERE/'native-request-harness-11316.py')
    functions={0x1444c4210,0x1444fa180,0x1444dee00,0x1444cf500,0x1444f8b10,
        0x1445515c0,0x14447cf10,0x14447d160,0x1411b05c0}
    h=harness.make_harness(EXPORTS,functions,leaves={0x14145f1e0:compare.hex()},root=root)
    links=[]
    for owner,target,kind in ((0x1444fa180,0x1444dee00,'LEA'),(0x1444dee00,0x1444cf500,'CALL'),
            (0x1444cf500,0x1444f8b10,'CALL'),(0x1444f8b10,0x1445515c0,'CALL')):
        f=next(f for f in h.fragments if int(f['address'],16)==owner)
        rows=[r for r in f['instructions'] if r['text'].startswith(kind+' ') and hex(target) in r['text']]
        if len(rows)!=1: raise ValueError('GMC2 geo source link missing/ambiguous')
        links.append(dict(owner=hex(owner),target=hex(target),instruction=rows[0]))
    rbp,manager,settings,cls,response=[h.scratch+n for n in (0x10000,0x14000,0x15000,0x16000,0x17000)]
    heap,options,events=[0],{},[]

    def put(destination,value):
        if not (h.scratch<=destination<=h.scratch+0x40000-16 or destination==0x14b561df0):
            raise ValueError('GMC2 geo FString destination bound')
        if value is None: h.uc.mem_write(destination,bytes(16)); return
        data=(value+'\0').encode('utf-16le')
        if len(data)>512 or heap[0]+len(data)>=h.scratch+0x2e000: raise ValueError('GMC2 geo string heap bound')
        pointer=heap[0];heap[0]+=(len(data)+15)&~15
        h.uc.mem_write(pointer,data);h.uc.mem_write(destination,struct.pack('<QII',pointer,len(data)//2,len(data)//2))

    def text(destination):
        if not (h.scratch<=destination<=h.scratch+0x40000-16 or destination==0x14b561df0):
            raise ValueError('GMC2 geo FString object bound')
        pointer,count,capacity=struct.unpack('<QII',bytes(h.uc.mem_read(destination,16)))
        if not 0<=count<=capacity<=256: raise ValueError('GMC2 geo FString counts')
        if not count:return ''
        if not h.scratch<=pointer<=h.scratch+0x40000-count*2:raise ValueError('GMC2 geo string data bound')
        data=bytes(h.uc.mem_read(pointer,count*2))
        if data[-2:]!=bytes(2):raise ValueError('GMC2 geo string terminator')
        return data[:-2].decode('utf-16le')

    def fixture(machine):
        at=machine.reg_read(h.x.UC_X86_REG_RIP)
        a,b,c=[machine.reg_read(r) for r in (h.x.UC_X86_REG_RCX,h.x.UC_X86_REG_RDX,h.x.UC_X86_REG_R8)]
        result=0
        if at in (0x141426950,0x141426b30):
            width=1 if at==0x141426950 else 2; off=h.image.offset(b-h.image.pe.base); data=h.raw[off:off+512]
            end=next((n for n in range(0,512,width) if data[n:n+width]==bytes(width)),None)
            if end is None: raise ValueError('GMC2 geo constructor literal bound')
            put(a,data[:end].decode('ascii' if width==1 else 'utf-16le'));result=a
        elif at==0x1444b1550: result=cls
        elif at==0x1416b0660:
            if a!=cls:raise ValueError('GMC2 geo CDO binding differs')
            machine.mem_write(cls+0x110,struct.pack('<Q',settings));events.append(['initialize'])
        elif at==0x14447cf10:
            key=text(c); expected='resultData' if not events else 'geoIp'
            # Class initialization occurs only after both nested lookups.
            if key!=expected or a!=(response if expected=='resultData' else rbp):
                raise ValueError('GMC2 nested field binding differs')
            if b!=(rbp if expected=='resultData' else rbp-0x38):raise ValueError('GMC2 nested destination differs')
            machine.mem_write(b,bytes(16));events.append(['nested',key]);result=b
        elif at==0x14447d160:
            key=text(c)
            if a!=rbp-0x38 or key not in ('clientIp','geoLocation'):raise ValueError('GMC2 string field binding differs')
            if b!=(rbp-0x58 if key=='clientIp' else rbp+0x38):raise ValueError('GMC2 string destination differs')
            put(b,options[key]);events.append(['string',key]);result=b
        elif at==0x141441d60:
            if a!=settings+0x3f0 or b!=rbp+0x38:raise ValueError('GMC2 country assignment binding differs')
            machine.mem_write(a,bytes(machine.mem_read(b,16)));events.append(['country-assignment']);result=a
        elif at==0x141483080:
            if not h.scratch+0x20000<=a<heap[0]:raise ValueError('GMC2 geo free bound')
        elif at!=0x1487e914c:raise ValueError('Unreviewed GMC2 geo fixture')
        h.finish(result)
    for at in (0x141426950,0x141426b30,0x1444b1550,0x1416b0660,0x14447cf10,
               0x14447d160,0x141441d60,0x141483080,0x1487e914c):h.add_fixture(at,fixture)
    h.uc.mem_write(0x14b5632e0,bytes(1))
    cases=[]; keys=None
    for poison,old,new,ip,lazy in itertools.product((0,0x55,0xaa,0xff),(None,'','JP','HK'),
            (None,'','A1','a1','JP','HK','A1x'),(None,'','1.1.1.1'),(False,True)):
        heap[0]=h.scratch+0x20000;events.clear();options.update(clientIp=ip,geoLocation=new)
        h.uc.mem_write(settings,bytes([poison])*0x500)
        h.uc.mem_write(rbp-0x180,bytes([poison])*0x300)
        h.call(0x1444c4210,receiver=manager,budget=4096)
        h.call(0x1411b05c0,budget=1024)
        keys={hex(offset):text(manager+offset) for offset in (0xc0,0xd0,0xe0,0xf0)}
        if list(keys.values())!=['geoIp','clientIp','geoLocation','isoCountry'] or text(0x14b561df0)!='resultData':
            raise ValueError('GMC2 geo constructor key bindings differ')
        put(settings+0x38,'old-ip-fixture');put(settings+0x3f0,old)
        h.uc.mem_write(cls+0x110,struct.pack('<Q',0 if lazy else settings))
        for name,value in dict(RSP=rbp-0x100,RBP=rbp,RCX=manager,RDX=response).items():
            h.uc.reg_write(getattr(h.x,'UC_X86_REG_'+name),value)
        h.uc.emu_start(0x1444f8b3c,0x1444f8c03,count=10000)
        if h.uc.reg_read(h.x.UC_X86_REG_RIP)!=0x1444f8c03:raise ValueError('GMC2 geo instruction budget')
        preserved=new is not None and new.lower()=='a1' and bool(old)
        wanted=old if preserved else new
        if text(settings+0x38)!=(ip or '') or text(settings+0x3f0)!=(wanted or ''):
            raise ValueError('GMC2 geo/country result differs')
        if sum(e[0]=='country-assignment' for e in events)!=int(not preserved):raise ValueError('GMC2 country gate differs')
        if bytes(h.uc.mem_read(settings+0x3e0,16))!=bytes([poison])*16 or bytes(h.uc.mem_read(settings+0x400,16))!=bytes([poison])*16:
            raise ValueError('GMC2 country canaries changed')
        cases.append(dict(poison=poison,old_country=old,incoming_country=new,incoming_ip=ip,lazy_cdo=lazy,
            country=text(settings+0x3f0),ip=text(settings+0x38),preserved=preserved,events=events.copy(),canaries_unchanged=True))
    return dict(schema=1,source=str(h.source),source_sha256=h.sha,evidence=h.evidence,keys=keys,links=links,
        cases=cases,native_execution=True,network_ready=False,
        dependencies={name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
            ('replay-gmc2-geo-11316.py','native-request-harness-11316.py','build-native-entry-code.py',
             'extract-native-enums.py','build-object-zero-init-code.py')},
        limits=['Actual constructor/resultData initializer, geo caller slice, SetCountryCode with notification/logging disabled and compare execute.',
            'JSON nested/string wrappers, FString storage/assignment/free, exit registration and CDO getters are fixtures.',
            'Callback chain is static only; full JSON conversion, constants/cache update, notification, actual route/IP, browser and authentication not executed.'])


if __name__=='__main__':
    report=replay();audit=load('geo_snapshot',HERE/'audit-client-release.py')
    path=audit.save_snapshot(Path('F:/PhoneExit Resources/Vampir/code-clues/gmc2-geo-11316'),report)
    print(json.dumps(dict(report=str(path),cases=len(report['cases']))))
