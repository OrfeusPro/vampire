"""Native model update/pending consumer/QuestUpdate producer; explicit local fixtures."""
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def run():
    audit=load('audit-client-release');path=HERE/'knowledge/native-contexts/quest-consumer-11316.json'
    context=json.loads(path.read_text('utf-8'))
    prior_path,prior=load('replay-quest-time-11316').run(HERE/'knowledge/native-contexts/quest-pending-time-11316.json')
    source=[c for c in prior['cases'] if c['mode']=='open']
    if len(source)!=2 or not prior.get('native_pending') or prior['source_sha256']!=context['source_sha256']:
        raise ValueError('Time pending handoff changed')
    h=load('native-request-harness-11316').make_harness(context['exports'],{int(a,16) for a in context['functions']},
        leaves={int(a,16):v for a,v in context['leaves'].items()})
    index=load('knowledge-index');legacy_checked=[]
    if h.sha!=context['source_sha256']:raise ValueError('Quest consumer source changed')
    for f in h.fragments:
        if not f.get('block_coverage_complete') or index.missing_conditional_fallthroughs(f['instructions']):
            raise ValueError('Quest consumer native fallthrough coverage changed')
        if f.get('direct_flow_coverage_complete') is not True:
            if f.get('direct_flow_coverage_complete') is not None or f['address'] not in context['legacy_direct_flow']:
                raise ValueError('Quest consumer direct flow coverage changed')
            legacy_checked.append(f['address'])
    def source_qword(at):return struct.unpack_from('<Q',h.raw,h.image.offset(at-h.image.pe.base))[0]
    for table,slot,target in ((0x149903e50,0,0x1455cd260),(0x149a3cf18,0,0x1455cd260),
            (0x149a3ceb0,0x40,0x145d853f0),(0x149903de8,0x40,0x141403b70),
            (0x149a3ceb0,0x48,0x1455b4d40),(0x149965670,0x28,0x145834490)):
        if source_qword(table+slot)!=target:raise ValueError('Quest consumer interface/packet binding changed')
    move_offset=h.image.offset(0x1487f5abf-h.image.pe.base)
    if h.raw[move_offset:move_offset+2]!=bytes.fromhex('ff25'):raise ValueError('Consumer memmove thunk changed')
    move_slot=0x1487f5abf+6+struct.unpack_from('<i',h.raw,move_offset+2)[0]
    move_import=load('build-object-zero-init-code').import_at(h.raw,h.image,move_slot)
    if (move_import['dll'].lower(),move_import['name'])!=('vcruntime140.dll','memmove'):raise ValueError('Consumer memmove import changed')
    uc,x,base=h.uc,h.x,h.scratch
    model,pending,environment,scope,actor_owner,actor,component,record=[base+n for n in (0x1000,0x3000,0x5000,0x6000,0x7000,0x8000,0x9000,0xa000)]
    variant=base+0xb000;bags={};tags={};boxed={};current={};packets=[];released=[];moves=[];visited=[];calls=[]
    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def get(at,size=8):return int.from_bytes(uc.mem_read(at,size),'little')
    def put(at,value,size=8):uc.mem_write(at,(int(value)%(1<<(size*8))).to_bytes(size,'little'))
    def wide(ptr):
        result=bytearray()
        for i in range(128):
            value=bytes(uc.mem_read(ptr+i*2,2))
            if value==bytes(2):return result.decode('utf-16le')
            result+=value
        raise ValueError('Consumer property string budget')
    def property_get(machine):
        bag,name=reg('RCX'),wide(reg('RDX'))
        if bag not in bags:raise ValueError('Consumer property bag outside pending storage')
        boxed[variant]=(name,bags[bag].get(name));h.finish(variant)
    def number(machine):
        if reg('RCX') not in boxed:raise ValueError('Consumer scalar outside boxed property')
        name,value=boxed[reg('RCX')]
        if name not in ('QuestInfoId','QuestTaskIndex','TargetId'):raise ValueError('Consumer numeric property name')
        h.finish(0 if value is None else value)
    def string(machine):
        if reg('RCX') not in boxed:raise ValueError('Consumer string outside boxed property')
        uc.mem_write(reg('RDX'),bytes(16));h.finish(reg('RDX'))
    def busy(machine):
        if reg('RCX')!=scope or reg('RDX')&65535!=0x713:raise ValueError('Consumer busy identifier changed')
        calls.append('busy');h.finish(int(current['busy']))
    def actor_owner_get(machine):h.finish(0 if current['mode']=='missing-owner' else actor_owner)
    def actor_get(machine):
        if reg('RCX')!=actor_owner+0x28:raise ValueError('Consumer actor reference scope')
        h.finish(0 if current['mode']=='missing-actor' else actor)
    def lookup(machine):
        if reg('RCX')!=model or reg('RDX')!=110120:raise ValueError('Consumer quest lookup scope')
        h.finish(0 if current['mode']=='missing-model' else record)
    def send(machine):
        packet=reg('RDX')
        if reg('RCX')!=scope or reg('R8')&65535!=0x713 or reg('R9')!=110120 or get(reg('RSP')+0x28,1)!=0:
            raise ValueError('Consumer send arguments changed')
        if get(packet)!=0x149965670 or get(packet+0xa,1)!=1:raise ValueError('Consumer packet constructor/header changed')
        fields=dict(vector=list(struct.unpack('<ddd',bytes(uc.mem_read(packet+0x10,24)))),raw28=get(packet+0x28),raw30=get(packet+0x30),raw38=get(packet+0x38,1))
        expected= current['position'] if current['mode']!='default-position' else current['default_position']
        props=bags[pending+visited[-1]*0x58+8]
        if fields!=dict(vector=expected,raw28=props.get('TargetId',0),raw30=props['QuestInfoId'],raw38=props['QuestTaskIndex']):
            raise ValueError('Consumer constructed packet fields changed')
        packets.append(dict(tag=visited[-1],packet=fields));current['packet']=packet
        if current['mode']=='one-inflight':current['busy']=True
        h.finish()
    def cleanup(machine):
        if reg('RCX')!=current.get('packet'):raise ValueError('Consumer packet cleanup order changed')
        current['packet']=None;calls.append('packet-cleanup');h.finish()
    def destroy(machine):
        at,count=reg('RCX'),reg('RDX')
        if at<pending or (at-pending)%0x58 or not 0<count<=current['initial_count'] or at+count*0x58>pending+current['initial_count']*0x58:
            raise ValueError('Consumer destroy range outside pending entries')
        for i in range(count):released.append(tags[at+i*0x58+8])
        h.finish()
    def move(machine):
        target,source,size=reg('RCX'),reg('RDX'),reg('R8')
        if size%0x58 or not size or any(p<pending or p+size>pending+current['initial_count']*0x58 or (p-pending)%0x58 for p in (target,source)):
            raise ValueError('Consumer memmove range outside pending entries')
        raw=bytes(uc.mem_read(source,size));values=[(bags[source+i+8].copy(),tags[source+i+8]) for i in range(0,size,0x58)]
        uc.mem_write(target,raw)
        for i,(value,tag) in enumerate(values):bags[target+i*0x58+8]=value;tags[target+i*0x58+8]=tag
        moves.append(dict(target=(target-pending)//0x58,source=(source-pending)//0x58,count=size//0x58));h.finish(target)
    def progress(machine):
        if reg('RCX')!=model+0x100:raise ValueError('Consumer update prelude receiver changed')
        calls.append('update-prelude');h.finish()
    def free(machine):raise ValueError('Unexpected nonempty string allocation in consumer fixture')
    callbacks={0x1455cc7b0:progress,0x14568c180:lambda machine:h.finish(int(current['mode']!='update-blocked')),
        0x14560adc0:lambda machine:h.finish(environment),0x1445cbc90:property_get,0x1445c7500:number,
        0x1445c7520:number,0x1414782f0:string,0x144aae520:lambda machine:h.finish(scope),0x144aae530:busy,
        0x145594e00:actor_owner_get,0x1417f8040:actor_get,0x1455bbcb0:lookup,0x144aae900:send,
        0x1456b66c0:cleanup,0x1455a75d0:destroy,0x1487f5abf:move,0x141483080:free}
    for table in (0x149903de8,0x149a3ceb0):
        page=table&~4095
        if not any(start<=page and end>=page+4095 for start,end,_ in uc.mem_regions()):
            uc.mem_map(page,4096);offset=h.image.offset(page-h.image.pe.base);uc.mem_write(page,h.raw[offset:offset+4096])
    for at,handler in callbacks.items():h.add_fixture(at,handler)
    import unicorn
    def observe(machine,address,size,user):
        entry=reg('RDX')
        if not pending<=entry<pending+current['initial_count']*0x58 or (entry-pending)%0x58:raise ValueError('Consumer producer entry outside pending array')
        visited.append(tags[entry+8])
    uc.hook_add(unicorn.UC_HOOK_CODE,observe,begin=0x145d6f9b0,end=0x145d6f9b0)
    modes=('ready','busy','missing-owner','missing-actor','missing-model','default-position','environment-blocked','update-blocked','base-vtable','empty','mixed-busy','one-inflight')
    cases=[]
    for origin in source:
      for mode in modes:
        bags.clear();tags.clear();boxed.clear();packets.clear();released.clear();moves.clear();visited.clear();calls.clear()
        rows=[dict(kind=e['kind'],properties=e['properties'].copy()) for e in origin['pending_entries']]
        if rows!=[dict(kind=1,properties={'QuestInfoId':110120,'QuestTaskIndex':origin['index']})]:raise ValueError('Native Time pending handoff fields changed')
        if mode=='empty':rows=[]
        if mode=='mixed-busy':rows=[dict(kind=kind,properties={'QuestInfoId':110120,'QuestTaskIndex':i}) for i,kind in enumerate((1,255,1))]
        if mode=='one-inflight':rows=[dict(kind=kind,properties={'QuestInfoId':110120,'QuestTaskIndex':i}) for i,kind in enumerate((1,1,255,1))]
        current.clear();current.update(mode=mode,busy=mode in ('busy','mixed-busy'),initial_count=len(rows),packet=None,
            position=[90100.25,151000.5,-44.0])
        offset=h.image.offset(0x14b0c0298-h.image.pe.base);current['default_position']=list(struct.unpack_from('<ddd',h.raw,offset))
        uc.mem_write(model-16,b'M'*16+bytes(0x1a0)+b'N'*16);uc.mem_write(pending-16,b'P'*16+bytes(8*0x58)+b'Q'*16)
        for at,size in ((environment,0x40),(actor_owner,0x40),(actor,0x200),(component,0x220),(record,0x60)):uc.mem_write(at,bytes(size))
        put(model,0x149903de8 if mode=='base-vtable' else 0x149a3ceb0);put(model+0x80,pending);put(model+0x88,len(rows),4);put(model+0x8c,8,4)
        put(environment+0x30,5 if mode=='environment-blocked' else 6,1);put(actor+0x1b8,0 if mode=='default-position' else component)
        uc.mem_write(component+0x1f0,struct.pack('<ddd',*current['position']));put(0x14b5e4d60,model)
        for i,row in enumerate(rows):
            at=pending+i*0x58;put(at,row['kind'],1);bags[at+8]=row['properties'].copy();tags[at+8]=i
        before=bytearray(uc.mem_read(model-16,0x1c0));immutable=[(at,bytes(uc.mem_read(at,size))) for at,size in ((environment,0x40),(actor_owner,0x40),(actor,0x200),(component,0x220),(record,0x60))]
        uc.reg_write(x.UC_X86_REG_XMM1,0);h.call(0x1455cd260,model+0x28,budget=100000)
        remaining=get(model+0x88,4);retained=[tags[pending+i*0x58+8] for i in range(remaining)]
        expected_retained=([0] if mode in ('busy','environment-blocked','update-blocked','base-vtable') else [0,2] if mode=='mixed-busy' else [1,3] if mode=='one-inflight' else [])
        expected_packets=1 if mode in ('ready','default-position','one-inflight') else 0
        if retained!=expected_retained or len(packets)!=expected_packets or calls.count('packet-cleanup')!=expected_packets:
            raise ValueError('Consumer retain/send/cleanup differs '+repr((mode,retained,packets,released,moves)))
        expected_released=[i for i in range(len(rows)) if i not in expected_retained]
        if released!=expected_released:raise ValueError('Consumer release grouping differs')
        if mode=='mixed-busy' and moves!=[dict(target=1,source=2,count=1)]:raise ValueError('Consumer mixed compaction differs')
        if mode=='one-inflight' and moves!=[dict(target=0,source=1,count=1),dict(target=1,source=3,count=1)]:raise ValueError('Consumer inflight compaction differs')
        before[16+0x88:16+0x8c]=uc.mem_read(model+0x88,4)
        if bytes(uc.mem_read(model-16,0x1c0))!=before or any(bytes(uc.mem_read(at,len(value)))!=value for at,value in immutable):raise ValueError('Consumer changed other model/actor data')
        if bytes(uc.mem_read(pending-16,16))!=b'P'*16 or bytes(uc.mem_read(pending+8*0x58,16))!=b'Q'*16:raise ValueError('Consumer pending guards changed')
        cases.append(dict(task_id=origin['task_id'],index=origin['index'],mode=mode,retained=retained,released=released.copy(),moves=moves.copy(),visited=visited.copy(),packets=packets.copy(),calls=calls.copy()))
    report=dict(source_sha256=h.sha,tool_sha256=audit.sha256(Path(__file__)),context_sha256=audit.sha256(path),exports=h.evidence,
        handoff=dict(path=str(prior_path),sha256=audit.sha256(prior_path),shared_memory=False),cases=cases,
        packet_id=1810,send_identifier=1811,legacy_direct_flow_checked=legacy_checked,move_import=move_import,native_execution=True,network_used=False,action_admitted=False,limits=context['limits'])
    target=audit.save_snapshot(h.root/'code-clues/quest-consumer-11316',report);return target,report


if __name__=='__main__':
    target,result=run();print(json.dumps(dict(artifact=str(target),cases=len(result['cases'])),ensure_ascii=False))
