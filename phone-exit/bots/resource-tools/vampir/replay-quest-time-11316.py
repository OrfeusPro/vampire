"""Native Time parameter/start/tick/timer/completion with explicit engine/JSON fixtures."""
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent


def load(name,path=None):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),path or HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def run(context_path=None):
    audit=load('audit-client-release');path=Path(context_path) if context_path else HERE/'knowledge/native-contexts/quest-time-11316.json'
    context=json.loads(path.read_text('utf-8'))
    native_pending=context.get('native_pending') is True
    native_gates=context.get('native_gates') is True
    h=load('native-request-harness-11316').make_harness(context['exports'],{int(v,16) for v in context['functions']},
        leaves={int(a,16):b for a,b in context['leaves'].items()})
    if h.sha!=context['source_sha256'] or not all(f.get('block_coverage_complete') and f.get('direct_flow_coverage_complete') for f in h.fragments):
        raise ValueError('Time source/coverage changed')
    def source_qword(at):return struct.unpack_from('<Q',h.raw,h.image.offset(at-h.image.pe.base))[0]
    tail=h.image.offset(0x1455b5830-h.image.pe.base)
    if h.raw[tail:tail+5]!=bytes.fromhex('e91ba8ffff') or 0x1455b5830+5+struct.unpack_from('<i',h.raw,tail+1)[0]!=0x1455b0050:
        raise ValueError('Time callback tail changed')
    init_export=h.root/'ghidra/request-exports'/h.sha/'run-6ba3bac90477/details.json'
    init=next(f for f in json.loads(init_export.read_text('utf-8'))['functions'] if f['address']=='0x1455d2630')
    instructions={int(i['address'],16):i['bytes'] for i in init['instructions']}
    for address,expected in ((0x1455d2672,'488d05b731feff'),(0x1455d2691,'e85a1200ff')):
        offset=h.image.offset(address-h.image.pe.base)
        if instructions.get(address)!=expected or h.raw[offset:offset+len(bytes.fromhex(expected))].hex()!=expected:
            raise ValueError('Time init callback/parser binding changed')
    for slot,target in ((0x20,0x1455cd9e0),(0x28,0x1455c3eb0),(0x48,0x1455d2630)):
        if source_qword(0x149905340+slot)!=target:raise ValueError('Time lifecycle slot changed')
    index_path=h.root/context['record_index'];index=json.loads(index_path.read_text('utf-8'));archive=Path(index['source']['path'])
    if audit.sha256(index_path)!=index_path.parent.name or audit.sha256(archive)!=context['pak_sha256']:
        raise ValueError('Time source index/PAK changed')
    reader_path=HERE.parent/'rfnext/scan-pak.py';reader=load('time_csv_reader',reader_path)
    if audit.sha256(reader_path)!=index['dependencies']['reader_sha256'] or audit.sha256(reader.ROOT/'tools/oodle-data-shared.dll')!=index['dependencies']['oodle_sha256']:
        raise ValueError('Time resource decoder changed')
    entry=next(e for e in index['entries'] if e['entry']==context['csv_entry'])
    with archive.open('rb') as stream:
        header=reader.header(stream,entry['offset'],index['index_offset'])
        if header is None or header['end']!=entry['end']:raise ValueError('Time CSV header changed')
        raw=reader.decode(stream,header)
    if hashlib.sha256(raw).hexdigest()!=context['csv_sha256']:raise ValueError('Time CSV bytes changed')
    source=[]
    for row in csv.DictReader(io.StringIO(raw.decode('utf-8-sig'))):
        if row['Id'] in ('110120005','110120070'):
            # Explicit JSON decoding fixture; native text reader/unescaping is not executed.
            param=json.loads(row['Param'].replace('\\r','\r').replace('\\n','\n'))
            if row['QuestInfoId']!='110120' or row['Type']!='6' or row['ServerServiceGroupId'] or param['type']!='Time':
                raise ValueError('Time source fields changed')
            source.append(dict(id=row['Id'],index=0 if row['Id']=='110120005' else 5,param=row['Param'],seconds=param['seconds']))
    if [(r['id'],r['seconds']) for r in source]!=[('110120005',0.1),('110120070',1)]:raise ValueError('Time source rows changed')
    uc,x,base=h.uc,h.x,h.scratch
    task,closure,json_ref,json_object,record,control,data,model,environment=[base+n for n in (0x1000,0x2000,0x2100,0x2200,0x3000,0x4000,0x5000,0x6000,0x7000)]
    current={};blocks={};cursor=[base+0x10000];calls=[];properties={};variants={};bags={}
    pending=base+0x8000;variant_result=base+0x9000;scope=base+0xa000
    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def put(at,n,size=8):uc.mem_write(at,(int(n)%(1<<(size*8))).to_bytes(size,'little'))
    def get(at,size=8):return int.from_bytes(uc.mem_read(at,size),'little')
    def f32(n):return struct.unpack('<f',struct.pack('<f',n))[0]
    def wide(ptr):
        raw=bytearray()
        for i in range(128):
            value=bytes(uc.mem_read(ptr+i*2,2))
            if value==bytes(2):return raw.decode('utf-16le')
            raw+=value
        raise ValueError('Time string budget')
    def assign(at,value):
        raw=value.encode('utf-16le')+bytes(2);ptr=cursor[0]+16;cursor[0]=ptr+((len(raw)+15)&~15)+16
        if cursor[0]>=base+0x30000:raise ValueError('Time string allocation budget')
        uc.mem_write(ptr-16,b'L'*16+raw+b'R'*16);blocks[ptr]=len(raw)
        put(at,ptr);put(at+8,len(raw)//2,4);put(at+12,len(raw)//2,4)
    def string_init(machine):assign(reg('RCX'),wide(reg('RDX')));h.finish(reg('RCX'))
    def free(machine):
        ptr=reg('RCX');size=blocks.pop(ptr,None)
        if size is None or bytes(uc.mem_read(ptr-16,16))!=b'L'*16 or bytes(uc.mem_read(ptr+size,16))!=b'R'*16:
            raise ValueError('Time string ownership/guards changed')
        h.finish()
    def property_type(machine):
        if reg('RCX')!=json_ref or get(json_ref)!=json_object or wide(reg('RDX'))!='type':raise ValueError('Time type getter scope')
        calls.append('type');assign(reg('R8'),'Time');h.finish(1)
    def property_seconds(machine):
        if reg('RCX')!=json_ref or wide(reg('RDX'))!='seconds' or reg('R8')!=task+0x11c:raise ValueError('Time seconds getter scope')
        calls.append('seconds');uc.mem_write(reg('R8'),struct.pack('<f',current['seconds']));h.finish(1)
    def start_status(machine):
        if reg('RCX')!=task or reg('RDX')&255!=0x17:raise ValueError('Time start status')
        calls.append('start-status');h.finish()
    def broadcast(machine):
        if reg('RCX')!=model+8 or reg('R8')!=task+0x20:raise ValueError('Time start broadcast')
        calls.append('broadcast');h.finish()
    def task_key(machine):
        if reg('RCX')!=record:raise ValueError('Time owner task getter')
        h.finish(int(current['id']))
    def task_data(machine):
        if reg('RCX')!=int(current['id']):raise ValueError('Time data key')
        h.finish(data)
    def gate_one(machine):
        if reg('RCX')!=110120:raise ValueError('Time owner quest key')
        h.finish(int(current['mode']!='gate-one'))
    def gate_two(machine):
        if reg('RCX')!=110120:raise ValueError('Time active quest key')
        h.finish(int(current['mode']!='gate-two'))
    def other_timer(machine):
        if reg('RCX') not in (task+0x1f0,task+0x240,task+0xb0):raise ValueError('Other Time gate scope')
        h.finish(1)
    def weak_object(machine):h.finish(0)
    def lookup(machine):
        if reg('RCX')!=model or reg('RDX')!=110120:raise ValueError('Time completion lookup')
        calls.append('lookup');h.finish(0 if current['mode']=='missing-model' else record)
    def bag_init(machine):
        properties.clear();bags[reg('RCX')]={};uc.mem_write(reg('RCX'),bytes(0x48));h.finish(reg('RCX'))
    def scalar(machine):
        variants[reg('RCX')]=reg('RDX');uc.mem_write(reg('RCX'),bytes(32));h.finish(reg('RCX'))
    def set_property(machine):
        name=wide(reg('RDX'))
        if name not in ('QuestInfoId','QuestTaskIndex') or reg('R8') not in variants:raise ValueError('Time named request property')
        properties[name]=variants[reg('R8')];bags[reg('RCX')][name]=variants[reg('R8')];h.finish()
    def completion_request(machine):
        if reg('RCX')!=model or properties!={'QuestInfoId':110120,'QuestTaskIndex':current['index']}:raise ValueError('Time completion request differs')
        calls.append('request');h.finish()
    callbacks={0x141426950:string_init,0x141483080:free,0x1445cf070:property_type,0x1445cd160:property_seconds,
        0x1455d2ec0:start_status,0x144a6ac90:broadcast,0x1455e7530:task_key,0x14546da00:task_data,
        0x14560adc0:lambda machine:h.finish(environment),0x14568cad0:gate_one,0x14568ca20:gate_two,
        0x14549a870:other_timer,0x1417fa0f0:weak_object,0x1455bbcb0:lookup,
        0x141c827e0:bag_init,0x1445c5890:scalar,0x1445c5800:scalar,0x1445d6930:set_property,
        0x1455ca010:completion_request,0x141c4f630:lambda machine:h.finish(),
        0x1487e8ce0:lambda machine:h.finish(reg('RAX'))}
    if native_gates:
        callbacks.pop(0x14568cad0);callbacks.pop(0x14568ca20)
        callbacks.pop(0x14560adc0)
        if source_qword(0x149909370+0xb8)!=0x1418af880:raise ValueError('Environment kind getter slot changed')
        if source_qword(0x1499f67f8+0x20)!=0x1433ae360:raise ValueError('QuestTask RunInInstance slot changed')
        def environment_registration(machine):
            if reg('RCX')!=environment+0x28:raise ValueError('Environment registration base receiver')
            calls.append('environment-registration-fixture');h.finish(reg('RCX'))
        callbacks[0x144286f50]=environment_registration
        def blocked_instance(machine):
            if reg('RCX')!=model or reg('RDX')!=110120 or reg('R8')&255!=1:raise ValueError('Blocked instance fallback scope')
            calls.append('blocked-instance');h.finish()
        callbacks[base+0xe120]=blocked_instance
        import unicorn
        for address,label in ((0x14144ec00,'gate-resolve'),(0x1433ae360,'gate-data-flag'),(0x1418af880,'gate-environment-kind')):
            uc.hook_add(unicorn.UC_HOOK_CODE,lambda machine,at,size,user,label=label:calls.append(label),begin=address,end=address)
    if native_pending:
        callbacks.pop(0x1455ca010)
        def copy_bag(machine):
            target,source=reg('RCX'),reg('RDX')
            if source not in bags:raise ValueError('Native pending copy source unknown')
            bags[target]=bags[source].copy();uc.mem_write(target,bytes(0x48));h.finish(target)
        def get_property(machine):
            if wide(reg('RDX'))!='QuestInfoId' or reg('RCX') not in bags:raise ValueError('Native pending property lookup')
            variants[variant_result]=bags[reg('RCX')]['QuestInfoId'];h.finish(variant_result)
        def integer_value(machine):
            if reg('RCX') not in variants:raise ValueError('Native pending scalar scope')
            h.finish(variants[reg('RCX')])
        def guard(machine):
            if reg('RCX')!=scope or reg('RDX')&65535!=7 or reg('R8')!=110120:raise ValueError('Native pending guard scope')
            calls.append('pending-guard');h.finish(int(current['mode']=='pending-guard'))
        def resize(machine):
            old=reg('RDX')
            if reg('RCX')!=model+0x80 or get(model+0x88,4)!=old+1 or not 0<=old<8:raise ValueError('Native pending growth scope')
            put(model+0x80,pending);put(model+0x8c,8,4);calls.append('pending-grow');h.finish()
        callbacks.update({0x1445c65d0:copy_bag,0x1445cbc90:get_property,0x1445c7500:integer_value,
            0x144aae520:lambda machine:h.finish(scope),0x144aae5a0:guard,0x1415397a0:resize})
        # Observation only: execute the real wrapper, never replace it with a hook result.
        import unicorn
        uc.hook_add(unicorn.UC_HOOK_CODE,lambda machine,address,size,user:calls.append('request'),begin=0x1455ca010,end=0x1455ca010)
    # Data virtual +20 fallback is deliberately closed when the active gate is false.
    data_page=0x1499f6000
    if not any(start<=data_page and end>=data_page+4095 for start,end,_ in uc.mem_regions()):
        uc.mem_map(data_page,4096)
        offset=h.image.offset(data_page-h.image.pe.base);uc.mem_write(data_page,h.raw[offset:offset+4096])
    if not native_gates:callbacks[source_qword(0x1499f67f8+0x20)]=lambda machine:h.finish(0)
    for at,callback in callbacks.items():h.add_fixture(at,callback)
    modes=('open','start-noowner','start-nocontrol','start-dead','start-nodata','disabled','record-state','phase','gate-one','gate-two','missing-model','record-advances')
    if native_gates:modes+=('gate-mode3-match','gate-record-null','gate-data-null','gate-flag-match','gate-flag-mismatch')
    if native_pending:modes+=('pending-same','pending-other-index','pending-other-type','pending-other-key','pending-guard')
    cases=[]
    for row in source:
      for mode in modes:
        current.clear();current.update(row,mode=mode);calls.clear();blocks.clear();variants.clear();properties.clear();bags.clear();cursor[0]=base+0x10000
        uc.mem_write(task-16,b'A'*16+bytes(0x2b0)+b'B'*16)
        uc.mem_write(record,bytes(0x60));uc.mem_write(control,bytes(0x20));uc.mem_write(data,bytes(0xc0));uc.mem_write(environment,bytes(0x40))
        put(task,0x149905340);put(task+0x10,record);put(task+0x18,control);put(task+0x20,int(row['id']));put(task+0x28,6,1);put(task+0x29,row['index'],1);put(task+0x40,data)
        put(record+0x20,110120);put(record+0x28,2,1);put(record+0x30,task);put(control+8,1,4);put(control+12,1,4);put(data,0x1499f67f8)
        put(closure,task);put(json_ref,json_object);put(0x14b5e4d60,model);put(environment+0x30,6,1)
        if native_gates:
            uc.mem_write(environment,b'\xa5'*0x100)
            if h.call(0x1456001d0,environment)!=environment or get(0x14b5e5ea8)!=environment or get(environment)!=0x149909370:
                raise ValueError('Environment constructor/global/vtable binding differs')
            if get(environment+0x40,4)!=0xa5a5a5a5:raise ValueError('Environment constructor kind footprint differs')
            if h.call(0x14560adc0,0)!=environment:raise ValueError('Environment global getter differs')
            put(environment+0x40,4 if mode=='gate-one' else 3,4)
            put(environment+0x30,6,1);put(environment+0x50,110120 if mode=='gate-mode3-match' else 110121)
            put(environment+0x58,3 if mode in ('gate-two','gate-mode3-match') else 0,1)
            put(environment+0x5a,0 if mode=='gate-flag-match' else 1,1)
            put(model,base+0xe000);put(base+0xe030,base+0xe120)
            put(data+0x14,3,4)
            put(data+0x89,int(mode in ('gate-flag-match','gate-flag-mismatch')),1)
        if native_pending:
            uc.mem_write(model,bytes(0x100));put(model+0xe6,7,2)
            uc.mem_write(pending-16,b'P'*16+bytes(0x58*8)+b'Q'*16)
            seeded=mode in ('pending-same','pending-other-index','pending-other-type','pending-other-key')
            if seeded:
                put(model+0x80,pending);put(model+0x88,1,4);put(model+0x8c,1,4)
                put(pending,2 if mode=='pending-other-type' else 1,1)
                bags[pending+8]={'QuestInfoId':110121 if mode=='pending-other-key' else 110120,
                    'QuestTaskIndex':(row['index']+1)%6 if mode=='pending-other-index' else row['index']}
            pending_before=bytes(uc.mem_read(pending,0x58)) if seeded else None
            seed_values=bags[pending+8].copy() if seeded else None
            pending_counts=[]

        uc.reg_write(x.UC_X86_REG_RDX,json_ref);h.call(0x1455b0050,closure)
        if get(task+0x118,1)!=0 or bytes(uc.mem_read(task+0x11c,4))!=struct.pack('<f',row['seconds']) or blocks:
            raise ValueError('Time callback fields/cleanup differ')
        if mode=='start-noowner':put(task+0x10,0)
        if mode=='start-nocontrol':put(task+0x18,0)
        if mode=='start-dead':put(control+8,0,4)
        if mode=='start-nodata':put(task+0x40,0)
        h.call(0x1455c3eb0,task)
        started=not mode.startswith('start-')
        if get(task+0xa0,1)!=int(started) or get(task+0x1a8,4)!=int(started):raise ValueError('Time start guard/state differs')
        if started and (get(task+0x1a0,4)!=0 or bytes(uc.mem_read(task+0x1a4,4))!=struct.pack('<f',row['seconds'])):
            raise ValueError('Time start duration differs')
        if mode=='disabled':put(task+0xa0,0,1)
        if mode=='record-state':put(record+0x28,0,1)
        if mode=='phase':put(environment+0x30,5,1)
        if native_gates:
            if mode=='gate-record-null':put(record+0x30,0)
            if mode=='gate-data-null':put(task+0x40,0)
        expected_data=bytes(uc.mem_read(data,0xc0))
        expected_control=bytes(uc.mem_read(control,0x20))
        expected_record=bytearray(uc.mem_read(record,0x60))
        elapsed=[];states=[];requests=[]
        for delta in (f32(row['seconds']/2),f32(row['seconds']/2),0.,f32(row['seconds']),0.):
            uc.reg_write(x.UC_X86_REG_XMM1,int.from_bytes(struct.pack('<f',delta),'little'))
            try:h.call(0x1455cd9e0,task)
            except Exception as error:raise ValueError('Time replay '+repr((mode,delta,hex(reg('RIP')),hex(reg('RCX')),hex(reg('RDX'))))) from error
            elapsed.append(struct.unpack('<f',bytes(uc.mem_read(task+0x1a0,4)))[0]);states.append(get(task+0x1a8,4));requests.append(calls.count('request'))
            if mode=='record-advances' and calls.count('request'):put(record+0x28,0,1)
            if native_pending:pending_counts.append(get(model+0x88,4))
        allowed=(mode in ('open','record-advances','gate-mode3-match','gate-flag-match') if native_gates else mode in ('open','missing-model','record-advances')) or mode.startswith('pending-')
        expected_requests=([0,0,1,1,2] if mode=='open' or mode in ('gate-mode3-match','gate-flag-match') or mode.startswith('pending-') else [0,0,1,1,1] if mode=='record-advances' else [0]*5)
        if requests!=expected_requests:raise ValueError('Time completion count differs '+repr((mode,requests,states,elapsed)))
        if allowed and states[:3]!=[1,0xffffffff,1]:raise ValueError('Time threshold requires next tick')
        if not allowed and (states!=[int(started)]*5 or any(elapsed)):raise ValueError('Blocked Time tick changed timer')
        if mode=='record-advances':expected_record[0x28]=0
        if bytes(uc.mem_read(data,0xc0))!=expected_data or bytes(uc.mem_read(control,0x20))!=expected_control or bytes(uc.mem_read(record,0x60))!=expected_record:
            raise ValueError('Time changed owner/control/data outside explicit state update')
        if bytes(uc.mem_read(task-16,16))!=b'A'*16 or bytes(uc.mem_read(task+0x2b0,16))!=b'B'*16 or blocks:
            raise ValueError('Time final guards/allocations differ')
        cases.append(dict(task_id=row['id'],index=row['index'],seconds=row['seconds'],mode=mode,states=states,elapsed=elapsed,requests=requests,calls=calls.copy()))
        if native_pending:
            added=int(mode in ('open','record-advances','pending-other-type','pending-other-key'))
            expected_counts=[int(seeded)]*2+[int(seeded)+added]*3
            if pending_counts!=expected_counts:raise ValueError('Native pending count differs '+repr((mode,pending_counts,expected_counts)))
            if seeded and (bytes(uc.mem_read(pending,0x58))!=pending_before or bags[pending+8]!=seed_values):raise ValueError('Existing pending row changed')
            entries=[dict(kind=get(pending+i*0x58,1),properties=bags[pending+i*0x58+8].copy()) for i in range(pending_counts[-1])]
            if added and entries[-1]!={'kind':1,'properties':{'QuestInfoId':110120,'QuestTaskIndex':row['index']}}:raise ValueError('Native pending fields differ')
            if bytes(uc.mem_read(pending-16,16))!=b'P'*16 or bytes(uc.mem_read(pending+0x58*8,16))!=b'Q'*16:raise ValueError('Native pending guards changed')
            cases[-1].update(pending_counts=pending_counts,pending_entries=entries)

    if audit.sha256(archive)!=context['pak_sha256']:raise ValueError('Time PAK changed during run')
    report=dict(source_sha256=h.sha,tool_sha256=audit.sha256(Path(__file__)),context_sha256=audit.sha256(path),exports=h.evidence,
        source_rows=source,cases=cases,native_execution=True,network_used=False,action_admitted=False,limits=context['limits'])
    if native_gates:
        report['native_gates']=True
        report['environment_binding']=dict(constructor='0x1456001d0',global_pointer='0x14b5e5ea8',vtable='0x149909370',getter='0x1418af880',field_offset=0x40,kind_after_constructor_with_registration_fixture=0xa5a5a5a5)
    if native_pending:report['native_pending']=True
    target=audit.save_snapshot(h.root/('code-clues/quest-time-gates-11316' if native_gates else 'code-clues/quest-pending-time-11316' if native_pending else 'code-clues/quest-time-11316'),report);return target,report


if __name__=='__main__':
    target,result=run();print(json.dumps(dict(artifact=str(target),cases=len(result['cases'])),ensure_ascii=False))
