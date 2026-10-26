"""Whole native localization transform; UTF/string services and flags are fixtures."""
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def run():
    audit=load('audit-client-release')
    path=HERE/'knowledge/native-contexts/quest-localization-11316.json'
    context=json.loads(path.read_text('utf-8'))
    # Recheck named PAK bytes and native static bindings, rather than trusting an old report.
    _,data=load('inspect-quest-override-data-11316').run()
    ru=next(row for row in data['records'] if row['locale']=='ru')
    if ru['sha256']!=context['russian_csv_sha256']: raise ValueError('Russian CSV changed')
    h=load('native-request-harness-11316').make_harness(context['exports'],{0x14585e070})
    if not all(f.get('block_coverage_complete') and f.get('direct_flow_coverage_complete') for f in h.fragments):
        raise ValueError('Localization coverage incomplete')
    off=h.image.offset(0x14996c9c0-h.image.pe.base)
    if h.raw[off:off+8]!='###\0'.encode('utf-16le'): raise ValueError('Native prefix differs')
    uc,x,base=h.uc,h.x,h.scratch
    source,result,fallback,flags,utf_buffer,input_heap=[base+n for n in (0x1000,0x2000,0x3000,0x4000,0x5000,0x6000)]
    blocks={}; cursor=[base+0x10000]; calls={}
    def reg(name): return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def put(at,value,size=8): uc.mem_write(at,int(value).to_bytes(size,'little'))
    def get(at,size=8): return int.from_bytes(uc.mem_read(at,size),'little')
    def count(name): calls[name]=calls.get(name,0)+1
    def allocate(data):
        at=cursor[0]+16; size=len(data); cursor[0]=at+((size+15)&~15)+16
        if cursor[0]>=base+0x30000: raise ValueError('String arena budget')
        uc.mem_write(at-16,b'L'*16+data+b'R'*16); blocks[at]=size
        return at
    def wide(ptr):
        if ptr==0: return ''
        data=bytearray()
        for i in range(512):
            b=bytes(uc.mem_read(ptr+i*2,2))
            if b==b'\0\0': return data.decode('utf-16le')
            data+=b
        raise ValueError('Wide input budget')
    def assign(at,text):
        raw=text.encode('utf-16le')+b'\0\0'
        uc.mem_write(at,bytes(16))
        # Empty FString with count=0 is explicit fixture input/storage behavior.
        if text:
            put(at,allocate(raw)); put(at+8,len(raw)//2,4); put(at+12,len(raw)//2,4)
    def release(at):
        size=blocks.pop(at,None)
        if size is None or bytes(uc.mem_read(at-16,16))!=b'L'*16 or bytes(uc.mem_read(at+size,16))!=b'R'*16:
            raise ValueError('String free/guards differ')
    def utf_convert(machine):
        ptr=reg('RDX')
        if ptr not in (source,input_heap): raise ValueError('UTF8 pointer outside exact input')
        data=bytes(uc.mem_read(ptr,512)).split(b'\0',1)[0]
        if len(data)>255: raise ValueError('UTF8 input budget')
        text=data.decode('utf-8')
        uc.mem_write(utf_buffer,text.encode('utf-16le')+b'\0\0')
        # Result wrapper lives on caller stack; owned UTF temporary remains null.
        put(reg('RCX')+0x108,utf_buffer); put(reg('RCX')+0x100,0)
        count('utf8'); h.finish(reg('RCX'))
    def wide_init(machine):
        assign(reg('RCX'),wide(reg('RDX'))); count('wide_copy'); h.finish(reg('RCX'))
    def prefix(machine):
        if reg('R8')!=3: raise ValueError('Prefix length differs')
        assign(reg('RCX'),wide(reg('RDX'))[:3]); count('prefix'); h.finish(reg('RCX'))
    def compare(machine):
        if reg('RDX')!=0x14996c9c0: raise ValueError('Unexpected prefix comparison')
        count('compare'); h.finish(0 if wide(reg('RCX'))=='###' else 1)
    def fallback_copy(machine):
        if reg('RDX')&255!=1 or reg('R8')!=fallback: raise ValueError('Fallback contract differs')
        assign(reg('RCX'),wide(get(fallback))); count('fallback'); h.finish(reg('RCX'))
    def free(machine): release(reg('RCX')); count('free'); h.finish()
    def settings(machine): count('settings'); h.finish(flags)
    for at,callback in ((0x1415c0820,utf_convert),(0x141426b30,wide_init),(0x14142c4b0,prefix),
            (0x14145f1e0,compare),(0x1456aa4f0,fallback_copy),(0x141483080,free),
            (0x14563dd10,settings),(0x1487e8ce0,lambda machine:h.finish(reg('RAX')))):
        h.add_fixture(at,callback)
    samples=[dict(id=t['id'],text=t['task_name'],origin='current_ru') for t in ru['selected_tasks']]
    samples += [dict(id=name,text=text,origin='lexical') for name,text in (
        ('empty',''),('short','А'),('prefix-only','###'),('prefix-text','###Нет перевода'),
        ('ordinary','Текст'),('internal-prefix','Текст ###'),('ascii','NPC'),('astral','😀Текст'))]
    cases=[]
    for sample in samples:
      for flag4 in (0,1):
       for flag5 in (0,1):
        for untranslated in (0,1):
         for fallback_text in ('','Запасной текст'):
          for external in (False,True):
            raw=sample['text'].encode('utf-8')
            if not external and len(raw)>15: continue
            uc.mem_write(source,bytes(32)); uc.mem_write(result-16,b'A'*16+bytes(16)+b'B'*16)
            uc.mem_write(flags,bytes(512)); put(flags+0x1e4,flag4,1); put(flags+0x1e5,flag5,1)
            blocks.clear(); cursor[0]=base+0x10000; calls.clear()
            if external:
                uc.mem_write(input_heap,raw+b'\0'); put(source,input_heap); put(source+24,255)
            else:
                uc.mem_write(source,raw+b'\0'); put(source+24,15)
            put(source+16,len(raw)); assign(fallback,fallback_text)
            immutable=[(at,bytes(uc.mem_read(at,n))) for at,n in ((source,32),(flags,512),(fallback,16),(input_heap,len(raw)+1))]
            uc.reg_write(x.UC_X86_REG_RDX,result); uc.reg_write(x.UC_X86_REG_R8,source); uc.reg_write(x.UC_X86_REG_R9,fallback)
            put(base+0x38028,untranslated,1)
            if h.call(0x14585e070,base+0x8000)!=result: raise ValueError('Localization return pointer differs')
            actual=wide(get(result)); expected=sample['text']; reason='retained'
            if not flag4 and untranslated:
                expected=''; reason='untranslated_hidden'
            elif flag4 and untranslated and not sample['text'] and fallback_text:
                expected=fallback_text; reason='fallback'
            elif not flag5 and sample['text'].startswith('###'):
                expected=''; reason='prefix_hidden'
            if actual!=expected: raise ValueError('Localization differs '+str((sample,flag4,flag5,untranslated,fallback_text,actual,expected)))
            if any(bytes(uc.mem_read(at,len(b)))!=b for at,b in immutable): raise ValueError('Input changed')
            if bytes(uc.mem_read(result-16,16))!=b'A'*16 or bytes(uc.mem_read(result+16,16))!=b'B'*16:
                raise ValueError('Result guards differ')
            if get(result): release(get(result))
            if get(fallback): release(get(fallback))
            if blocks: raise ValueError('Temporary strings leaked')
            cases.append(dict(id=sample['id'],origin=sample['origin'],flag1e4=flag4,flag1e5=flag5,untranslated=untranslated,
                              fallback=bool(fallback_text),external=external,result=actual,reason=reason,callbacks=calls.copy()))
    report=dict(source_sha256=h.sha,tool_sha256=audit.sha256(Path(__file__)),context_sha256=audit.sha256(path),
                exports=h.evidence,russian_csv_sha256=ru['sha256'],data_inspector_sha256=audit.sha256(HERE/'inspect-quest-override-data-11316.py'),
                cases=cases,native_execution=True,network_used=False,order_admitted=False,limits=context['limits'])
    target=audit.save_snapshot(h.root/'code-clues/quest-localization-11316',report)
    return target,report


if __name__=='__main__':
    target,result=run(); print(json.dumps(dict(artifact=str(target),cases=len(result['cases'])),ensure_ascii=False))
