"""Current local tutorial advance routine; readiness and step execution are fixtures."""
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent


def run():
    spec=importlib.util.spec_from_file_location('tutorial_advance_archive',HERE/'replay-release-archive-input.py')
    archive=importlib.util.module_from_spec(spec);spec.loader.exec_module(archive)
    fixtures={0x1464c5770:None,0x1464cfb80:None}
    h=archive.make_harness(extra_addresses=(0x1464cd6f0,),fixtures=fixtures)
    evidence='details/run-3a40930c8abf/details.json'
    if h.audit.sha256(h.comparison/evidence)!='aadbdfcd1efca904840d3fb9a9c0539a955c34cb030ca91d05f7a884b11967f8':
        raise ValueError('Advance evidence changed')
    uc,x=h.uc,h.x
    context,record=h.scratch+0x10000,h.scratch+0x11000
    calls=[];blocked=False
    def fixture(machine):
        address=machine.reg_read(x.UC_X86_REG_RIP)
        args=[machine.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
        if args[0]!=context:raise ValueError('Tutorial context differs')
        calls.append(dict(address=hex(address),args=args))
        sp=machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RAX,int(blocked) if address==0x1464c5770 else 0)
        machine.reg_write(x.UC_X86_REG_RIP,int.from_bytes(machine.mem_read(sp,8),'little'))
        machine.reg_write(x.UC_X86_REG_RSP,sp+8)
    for address in fixtures:fixtures[address]=fixture
    cases=[]
    for progress in (0,1,0x7fffffff,0xffffffff):
        for state in (0,1,2,3):
            for keep_step in (0,1):
                for blocked in (False,True):
                    before=bytearray(24)
                    struct.pack_into('<IIIB',before,8,1001,progress,77,state)
                    uc.mem_write(record,bytes(before));calls.clear()
                    h.call(0x1464cd6f0,context,record,keep_step)
                    after=bytes(uc.mem_read(record,24))
                    expected=bytearray(before)
                    target=progress if keep_step else (progress+1)&0xffffffff
                    if not blocked:
                        struct.pack_into('<I',expected,12,target)
                        if state==0:expected[20]=1
                    if after!=bytes(expected):raise ValueError('Tutorial mutation differs')
                    if calls[0]['args'][1:]!=[1001,progress,state]:raise ValueError('Gate arguments differ')
                    if len(calls)!=(1 if blocked else 2):raise ValueError('Blocked step executed')
                    if not blocked and calls[1]['args'][1:3]!=[record,target]:raise ValueError('Step arguments differ')
                    cases.append(dict(progress=progress,state=state,keep_step=keep_step,blocked=blocked,
                        progress_after=struct.unpack_from('<I',after,12)[0],state_after=after[20],step_called=not blocked))
    calls.clear();h.call(0x1464cd6f0,context,0,0)
    if calls:raise ValueError('Null record reached a fixture')
    report=dict(source_sha256=h.sha,tool_sha256=h.audit.sha256(Path(__file__)),
        evidence=dict(path=str(h.comparison/evidence),sha256=h.audit.sha256(h.comparison/evidence)),
        fragments=h.fragments,cases=cases,null_record_skipped=True,native_execution=True,network_used=False,
        limits=['Whole 1464cd6f0 executes, including local field mutations and uint32 wraparound.',
            '1464c5770 gate and 1464cfb80 step execution are explicit fixtures; their conditions and effects are not established.',
            'No state enum names, active UI, server request, tutorial completion or live action claim.'])
    path=h.audit.save_snapshot(h.native.ROOT/'code-clues/release-tutorial-advance-replay',report)
    return path,report


if __name__=='__main__':
    path,r=run();print(json.dumps(dict(report=str(path),cases=len(r['cases']))))
