"""Whole current model sender with native lookup/state/position; no socket IO."""
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def run():
    path=HERE/'knowledge/native-contexts/quest-sender-11316.json'
    context=json.loads(path.read_text('utf-8'))
    h=load('native-request-harness-11316').make_harness(context['exports'],
        {int(v,16) for v in context['functions'].values()},
        leaves={int(k,16):v for k,v in context['leaves'].items()})
    uc,x=h.uc,h.x
    base=h.scratch
    model,nodes,buckets,quest,state,manager,actor,component,network,table,send=[base+n for n in
        (0x1000,0x2000,0x3000,0x4000,0x5000,0x6000,0x7000,0x8000,0x9000,0xa000,0x3e000)]
    selected={}
    captured=[]
    freed=[]

    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def put(at,value,size=8):uc.mem_write(at,int(value).to_bytes(size,'little',signed=value<0))
    def integer(at,size=8):return int.from_bytes(uc.mem_read(at,size),'little')
    def model_get(machine):h.finish(model)
    def manager_get(machine):h.finish(0 if selected['position']=='no_manager' else manager)
    def actor_get(machine):
        if reg('RCX')!=manager+0x28:raise ValueError('Unexpected actor weak-reference argument')
        h.finish(0 if selected['position']=='no_actor' else actor)
    def network_get(machine):h.finish(network)
    def send_packet(machine):
        if reg('RCX')!=network:raise ValueError('Sender receiver changed')
        packet=reg('RDX')
        if not base+0x37000<=packet<=base+0x38000:raise ValueError('Packet is not a bounded stack temporary')
        if integer(packet)!=0x149965670:raise ValueError('QuestUpdate constructor table differs')
        captured.append(bytes(uc.mem_read(packet+0x10,41)))
        h.finish(1)
    def cleanup(machine):
        packet=reg('RCX')
        if len(captured)!=len(freed)+1 or integer(packet)!=0x149965670:
            raise ValueError('Unexpected packet cleanup')
        freed.append(packet);h.finish()
    for at,callback in ((0x1455be4b0,model_get),(0x145594e00,manager_get),
            (0x1417f8040,actor_get),(0x144ab0c40,network_get),(0x1456b66c0,cleanup),(send,send_packet)):
        h.add_fixture(at,callback)
    put(network,table);put(table+0x38,send)
    fallback_component=bytes(uc.mem_read(0x14b0c0298,24))
    fallback_actor=bytes(uc.mem_read(0x14b186100,24))
    vector=struct.pack('<ddd',90049.,151840.,-44.)
    cases=[]
    for key in (0,1,0x8000000000000000,0xffffffffffffffff):
        for storage in ('inline','external'):
            for lookup in ('empty','missing','null_value','found'):
                for task in (None,0,1,2,255):
                    for position in ('current','no_component','no_actor','no_manager'):
                        selected.update(position=position)
                        captured.clear();freed.clear()
                        # Hash buckets and collision chain are real inputs to
                        # the native leaf, not a Python map lookup fixture.
                        for at,size in ((model,128),(nodes,64),(buckets,8),(quest,128),
                                (state,128),(manager,128),(actor,512),(component,640)):
                            uc.mem_write(at-16,b'\xa1'*16+bytes(size)+b'\xa2'*16)
                        put(model+0x30,nodes);put(model+0x38,0 if lookup=='empty' else 2,4)
                        put(model+0x70,buckets if storage=='external' else 0);put(model+0x78,2,4)
                        bucket_base=buckets if storage=='external' else model+0x68
                        put(bucket_base,-1,4);put(bucket_base+4,-1,4)
                        # xor2 preserves this native hash's parity. First node
                        # deliberately collides; second node may match.
                        put(nodes,key^2);put(nodes+8,quest);put(nodes+0x18,1,4)
                        put(nodes+32,key if lookup!='missing' else key^4)
                        put(nodes+40,0 if lookup=='null_value' else quest);put(nodes+56,-1,4)
                        hash_value=((key>>32)*23+(key&0xffffffff))&0xffffffff
                        put(bucket_base+(hash_value&1)*4,0,4)
                        put(quest+0x30,state if task is not None else 0)
                        if task is not None:put(state+0x29,task,1)
                        put(actor+0x1b8,component if position=='current' else 0)
                        uc.mem_write(component+0x1f0,vector)
                        immutable=[(at,bytes(uc.mem_read(at-16,size+32))) for at,size in
                            ((model,128),(nodes,64),(buckets,8),(quest,128),(state,128),
                             (manager,128),(actor,512),(component,640))]
                        uc.reg_write(x.UC_X86_REG_RDX,key)
                        h.call(0x145d85360,base+0xb000)
                        expected_send=lookup=='found'
                        if (len(captured),len(freed))!=(int(expected_send),int(expected_send)):
                            raise ValueError('Native lookup/send/cleanup path differs')
                        if expected_send:
                            coordinates=vector if position=='current' else fallback_component if position=='no_component' else fallback_actor
                            expected=coordinates+struct.pack('<QQB',0,key,255 if task is None else task)
                            if captured[0]!=expected:raise ValueError('Whole native sender fields differ')
                        for at,expected in immutable:
                            if bytes(uc.mem_read(at-16,len(expected)))!=expected:
                                raise ValueError('Quest sender changed model/actor or guard')
                        cases.append(dict(key_case=key,storage=storage,lookup=lookup,task=task,
                            position=position,sent=expected_send))
    audit=load('audit-client-release')
    report=dict(source_sha256=h.sha,tool_sha256=audit.sha256(Path(__file__)),context_sha256=audit.sha256(path),
        native_execution=True,network_used=False,exports=h.evidence,cases=cases,
        limits=['Whole current sender, actual packet constructor, native hash lookup/state leaf and position wrapper execute.',
            'Model singleton/engine manager/weak-reference resolver/network getter/send/destruction are explicit bounded fixtures.',
            'Captured native object fields are not serialized wire or server acceptance; no UI callback, route or quest completion.',
            'FF is observed for absent task storage, not approved as a runtime command parameter.',
            'Immutable models/actors and collision chains are synthetic; real incoming Quest mapping remains open.'])
    return audit.save_snapshot(h.root/'code-clues/quest-sender-11316',report),report


if __name__=='__main__':
    path,report=run();print(json.dumps(dict(report=str(path),cases=len(report['cases']),sent=sum(c['sent'] for c in report['cases']))))
