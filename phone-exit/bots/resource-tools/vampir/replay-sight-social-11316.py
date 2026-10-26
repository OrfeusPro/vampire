"""Whole GuildTinyInfo/PartyTag records with real native input and UTF-8 conversion."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def verify():
    context_path=HERE/'knowledge/native-contexts/sight-social-11316.json'
    context=json.loads(context_path.read_text('utf-8'));f={k:int(v,16) for k,v in context['functions'].items()}
    h=load('update-native-harness').make_harness(context,context['exports'],set(f.values()),
        leaves={int(k,16):v for k,v in context['leaves'].items()})
    uc,x=h.uc,h.x
    packet,archive,buffer=[h.scratch+n for n in (0x1000,0x2000,0x5000)]
    state={}
    def require(ok,message):
        if not ok:raise ValueError(message)
    def number(at,width):return int.from_bytes(uc.mem_read(at,width),'little')
    def text(at):
        ptr,count,capacity=struct.unpack('<QII',bytes(uc.mem_read(at,16)))
        require(0<=count==capacity<=2048,'Social FString descriptor differs')
        if not count:return ''
        require(ptr in state['allocations'] and state['allocations'][ptr]>=count*2,'Social FString ownership differs')
        data=bytes(uc.mem_read(ptr,count*2));require(data[-2:]==b'\0\0','Social FString terminator differs')
        return data[:-2].decode('utf-16le')
    sys.path.insert(0,str(HERE.parents[1]/'vampir-shared'))
    from vampir_core.sight_social_records import decode_guild_tiny_info,decode_party_tag
    for table,reader in [(0x149920598,f['guild_reader']),(0x149920550,f['emblem_reader']),
        (0x14991f3b8,f['time_reader']),(0x149921be0,f['party_reader']),(0x149921b98,f['option_reader'])]:
        require(struct.unpack_from('<Q',h.raw,h.image.offset(table+0x20-h.image.pe.base))[0]==reader,'Social vtable reader differs')
    cases=[]
    for kind,size,decoder,constructor,table in [('guild',0x60,decode_guild_tiny_info,f['guild_constructor'],0x149920598),
        ('party',0x50,decode_party_tag,0x1457a2350,0x149921be0)]:
        load('login-result-string-fixtures').install(load,h,context['string_storage'],state,packet,(0x10,) if kind=='guild' else (0x10,0x30))
        def attempt(body):
            state.clear();state.update(heap=h.scratch+0x10000,allocations={},body=body)
            uc.mem_write(packet-16,b'\xa1'*16+bytes(size)+b'\xa2'*16)
            uc.mem_write(archive-16,b'\xa3'*16+bytes(0x40)+b'\xa4'*16)
            uc.mem_write(buffer-16,b'\xa7'*16+body+b'\xa8'*16)
            h.call(constructor,packet);require(number(packet,8)==table,'Social constructor differs')
            if kind=='guild':require(number(packet+0x28,8)==0x149920550 and number(packet+0x48,8)==0x14991f3b8,'Guild nested constructors differ')
            else:require(number(packet+0x20,8)==0x149921b98,'Party option constructor differs')
            uc.reg_write(x.UC_X86_REG_RDX,buffer);uc.reg_write(x.UC_X86_REG_R8,len(body));uc.reg_write(x.UC_X86_REG_R9,1)
            uc.mem_write(h.scratch+0x38028,bytes(8));h.call(f['input_constructor'],archive)
            uc.reg_write(x.UC_X86_REG_RDX,archive)
            accepted=bool(h.call(f[kind+'_reader'],packet,budget=1000000)&255)
            consumed=number(archive+0x30,8)-buffer;require(0<=consumed<=len(body),'Social cursor exceeded input')
            for at,length,a,b in [(packet,size,b'\xa1',b'\xa2'),(archive,0x40,b'\xa3',b'\xa4')]:
                require(bytes(uc.mem_read(at-16,16))==a*16 and bytes(uc.mem_read(at+length,16))==b*16,'Social frame guard differs')
            require(bytes(uc.mem_read(buffer-16,len(body)+32))==b'\xa7'*16+body+b'\xa8'*16,'Social input changed')
            for at,length in state['allocations'].items():
                require(bytes(uc.mem_read(at-16,16))==b'\xa5'*16 and bytes(uc.mem_read(at+length,16))==b'\xa6'*16,'Social string storage guard differs')
            if accepted:
                value=decoder(body[:consumed],source_sha256=h.sha)
                require(number(packet+8,8)==value.at(8) and text(packet+0x10)==value.at(0x10),'Social key/name differs')
                if kind=='guild':
                    for offset,width in [(0x20,4),(0x38,8),(0x40,1),(0x50,8),(0x58,1)]:
                        require(number(packet+offset,width)==value.at(offset),'Guild scalar differs')
                    for offset,item in value.at(0x28).fields:require(number(packet+0x28+offset,2)==item,'Guild emblem differs')
                else:
                    options=value.at(0x20);require(text(packet+0x30)==options.at(0x10),'Party option text differs')
                    for offset,width in [(0x48,1),(0x49,1),(0x4c,4)]:require(number(packet+offset,width)==value.at(offset),'Party scalar differs')
                    for offset in (8,9,10,0x20,0x21):require(number(packet+0x20+offset,1)==options.at(offset),'Party option scalar differs')
            return accepted,consumed
        def encoded(text):
            data=text.encode('utf-8');return struct.pack('<H',len(data))+data
        def body_for(label,other,style,enum):
            key=(0,2**63,2**64-1)[style];flag=(0,1,255)[style]
            if kind=='guild':return struct.pack('<Q',key)+encoded(label)+struct.pack('<I4HQBQB',0xffffffff,0,32767,32768,65535,key,enum,key,flag)
            return struct.pack('<Q',key)+encoded(label)+bytes([enum,enum,enum])+encoded(other)+bytes([flag,flag,flag,enum])+struct.pack('<I',0xffffffff)
        names=['','ASCII','Гильдия 🦇','x'*15,'x'*16,'x'*31,'x'*255]
        for i,label in enumerate(names):
            for style in range(3):
                for enum in (0,1,3,6,8,102,255):
                    body=body_for(label,names[-i-1],style,enum)
                    sizes=range(len(body)+1) if enum in (0,255) else [len(body)]
                    for length in sizes:
                        accepted,consumed=attempt(body[:length]);require(accepted==(length==len(body)),'Social native prefix differs')
                        try:decoder(body[:length],source_sha256=h.sha);portable=True
                        except ValueError:portable=False
                        require(portable==accepted,'Social portable prefix differs')
                        cases.append(dict(kind=kind,name=i,style=style,enum=enum,size=length,accepted=accepted,consumed=consumed))
                    accepted,consumed=attempt(body+b'\xff');require(accepted and consumed==len(body),'Social trailing cursor differs')
        for enum in range(256):
            body=body_for('','',2,enum);require(attempt(body)[0],'Social byte clamp case failed')
            cases.append(dict(kind=kind,enum=enum,size=len(body),accepted=True))
    report=dict(source_sha256=h.sha,exports=h.evidence,context_sha256=hashlib.sha256(context_path.read_bytes()).hexdigest(),
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),cases=cases,network_used=False,
        limits=['Whole two constructors/readers including emblem/time/party options and actual input/UTF8 conversion.',
            'Bounded fresh empty string owners with storage allocation/free fixtures; no previous-storage reuse, engine or actor claim.',
            'Valid Unicode scalar strings only in native/portable comparisons; portable rejects malformed UTF8, NUL and U+FFFE/U+FFFF.',
            'Native permits trailing data; portable exact-size policy is stricter.'])
    path=load('audit-client-release').save_snapshot(h.root/'code-clues/sight-social-11316',report)
    return dict(report=str(path),cases=len(cases))


if __name__=='__main__':print(json.dumps(verify()))
