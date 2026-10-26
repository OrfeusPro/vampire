"""Current server/local tutorial record update; gate/launch/insertion fixtures."""
import importlib.util
import json
from pathlib import Path
import struct
HERE=Path(__file__).resolve().parent

def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def run():
    context_path=HERE/'knowledge/native-contexts/tutorial-populated-11316.json'
    current=json.loads(context_path.read_text('utf-8'))
    h=load('native-request-harness-11316').make_harness(current['exports'],{int(v,16) for v in current['functions'].values()})
    if current['source_sha256']!=h.sha:raise ValueError('Tutorial apply context differs')
    uc,x,b=h.uc,h.x,h.scratch
    context,server_nodes,local_nodes,inserted,packet,buckets=[b+n for n in (0x1000,0x2000,0x3000,0x4000,0x5000,0x6000)]
    def u32(at):return int.from_bytes(uc.mem_read(at,4),'little')
    def map_setup(offset, nodes, present, external):
        header = context + offset
        uc.mem_write(header, bytes(0x50))
        uc.mem_write(nodes, b'\xa5' * 120)
        if not present:
            return None
        uc.mem_write(header, struct.pack('<QI', nodes, 3))
        uc.mem_write(header + 0x38, struct.pack('<i', 0))
        bucket = buckets + offset
        uc.mem_write(bucket, struct.pack('<i', 0))
        uc.mem_write(header + 0x40, struct.pack('<QI', bucket if external else 0, 1))
        for i, key in enumerate((7, 1001, 8)):
            node = nodes + 40 * i
            uc.mem_write(node, struct.pack('<I', key))
            uc.mem_write(node + 16, struct.pack('<IIIB', key, 99, 0xaabbccdd, 3))
            uc.mem_write(node + 32, struct.pack('<i', i + 1 if i < 2 else -1))
        return nodes + 48

    events=[]
    selector,incoming_state,keep,blocked=0,0,0,False
    def fixture(machine):
        at=machine.reg_read(x.UC_X86_REG_RIP)
        a,c,d,e=[machine.reg_read(reg) for reg in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
        value=0
        if at==0x1464a0950:
            if (a,c)!=(context+0xa8,1001):raise ValueError('Insertion fixture arguments differ')
            value=inserted;events.append('insert_fixture')
        elif at==0x1464c41a0:
            if (a,c,d,e)!=(context,1001,selector,incoming_state):raise ValueError('Gate arguments differ')
            value=int(blocked);events.append('gate_fixture')
        elif at==0x1464ce5b0:
            if (a,c,d)!=(context,local_nodes+48,(selector if keep or blocked else selector+1)&0xffffffff):
                raise ValueError('Launch arguments differ')
            events.append('launch_fixture')
        else:raise ValueError('Unknown apply fixture')
        h.finish(value)
    for at in (0x1464a0950,0x1464c41a0,0x1464ce5b0):h.add_fixture(at,fixture)
    def setup(server_present,local_present,external):
        for at,size in ((context,0x400),(server_nodes,120),(local_nodes,120),(inserted,24),(packet,24),(buckets,0x400)):
            uc.mem_write(at-16,b'\xa1'*16+bytes(size)+b'\xa2'*16)
        uc.mem_write(context,bytes(0x400));uc.mem_write(inserted,b'\xa5'*24)
        server=map_setup(0xa8,server_nodes,server_present,external)
        local=map_setup(0x1c8,local_nodes,local_present,external)
        uc.mem_write(packet,bytes(24));uc.mem_write(packet+8,struct.pack('<IIIB',1001,selector,0x12345678,incoming_state))
        events.clear();return server or inserted,local
    applied = []
    for server_present in (False, True):
        for local_present in (False, True):
            for external in (False, True):
                for selector in (0, 2, 0xffffffff):
                    for incoming_state in (0, 1, 2, 3):
                        for keep in (0, 1):
                            for blocked in (False, True):
                                server, local = setup(server_present, local_present, external)
                                untouched = [(nodes + i * 40, bytes(uc.mem_read(nodes + i * 40, 40)))
                                    for nodes in (server_nodes, local_nodes) for i in (0, 2)]
                                uc.reg_write(x.UC_X86_REG_RDX,packet);uc.reg_write(x.UC_X86_REG_R8,keep)
                                h.call(0x1464d01a0,context)
                                if any(bytes(uc.mem_read(address, 40)) != before for address, before in untouched):
                                    raise ValueError('Apply modified an unrelated map record')
                                expected = (1001, selector, 0x12345678, incoming_state)
                                if struct.unpack('<IIIB', uc.mem_read(server + 8, 13)) != expected:
                                    raise ValueError('Authoritative record differs')
                                expected_events = [] if server_present else ['insert_fixture']
                                if local is not None:
                                    target = selector if blocked or keep else (selector + 1) & 0xffffffff
                                    state = 1 if not blocked and incoming_state == 0 else incoming_state
                                    if struct.unpack('<IIIB', uc.mem_read(local + 8, 13)) != (1001, target, 0xaabbccdd, state):
                                        raise ValueError('Local record or retained raw10 differs')
                                    expected_events += ['gate_fixture'] + ([] if blocked else ['launch_fixture'])
                                if events != expected_events:
                                    raise ValueError('Apply ordering differs')
                                for at,size in ((context,0x400),(server_nodes,120),(local_nodes,120),(inserted,24),(packet,24),(buckets,0x400)):
                                    if bytes(uc.mem_read(at-16,16))!=b'\xa1'*16 or bytes(uc.mem_read(at+size,16))!=b'\xa2'*16:
                                        raise ValueError('Populated tutorial storage guard changed')
                                applied.append(dict(server_present=server_present, local_present=local_present,
                                    external=external, selector=selector, state=incoming_state, keep=keep, blocked=blocked))

    audit=load('audit-client-release')
    report=dict(source_sha256=h.sha,tool_sha256=audit.sha256(Path(__file__)),context_sha256=audit.sha256(context_path),exports=h.evidence,cases=applied,native_execution=True,network_used=False,
        limits=['Whole current lookup/collision walk and existing server/local record writes execute.',
            'Absent-server insertion, gate outcome and task launch are bounded fixtures.',
            'No rehash, native allocation, completion gate side effects, queue drain, live readiness or outgoing command proof.'])
    path=audit.save_snapshot(h.root/'code-clues/tutorial-populated-11316',report)
    return path,report

if __name__=='__main__':
    p,r=run();print(json.dumps(dict(report=str(p),cases=len(r['cases']))))
