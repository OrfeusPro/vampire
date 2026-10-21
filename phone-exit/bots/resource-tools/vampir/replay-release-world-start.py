"""Execute current ID203 constructor/getter/writer with bounded output fixture."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
CTOR, WRITER, GET202, GET203 = 0x14584dcb0, 0x1456bbdc0, 0x145759140, 0x145759180
TABLE202, TABLE203 = 0x14996d600, 0x14996d678
WRITE64 = 0x3000c000


def run():
    spec = importlib.util.spec_from_file_location('world_start_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec); spec.loader.exec_module(archive)
    hooks = {WRITE64: None}
    h = archive.make_harness(extra_addresses=(WRITER,), extra_leaves=(CTOR,GET202,GET203), fixtures=hooks)
    evidence = h.comparison / 'details/run-3daa86310054/details.json'
    expected = 'bb0875c2ad7ed84d7d33a72a7d34e5c6c1902cde22969feea95d8db60dad4582'
    if h.audit.sha256(evidence) != expected: raise ValueError('World packet evidence changed')
    uc,x = h.uc,h.x
    obj,writer,table = [h.scratch+n for n in (0x10000,0x11000,0x12000)]
    def pointer(address):
        off=h.image.offset(address-h.image.pe.base)
        return struct.unpack_from('<Q',h.raw,off)[0]
    if pointer(TABLE203+0x10)!=WRITER or pointer(TABLE203+0x28)!=GET203 or pointer(TABLE202+0x28)!=GET202:
        raise ValueError('World packet vtable slots differ')
    for getter,expected_id in ((GET202,202),(GET203,203)):
        h.call(getter,obj)
        if uc.reg_read(x.UC_X86_REG_RAX)!=expected_id: raise ValueError('Packet ID differs')
    uc.mem_write(writer,struct.pack('<Q',table));uc.mem_write(table,bytes(0xc0))
    uc.mem_write(table+0xb8,struct.pack('<Q',WRITE64))
    output=bytearray(); capacity=0; calls=[]
    def fixture(machine):
        if machine.reg_read(x.UC_X86_REG_RCX)!=writer: raise ValueError('Unexpected output archive')
        value=machine.reg_read(x.UC_X86_REG_RDX)
        calls.append(value)
        accepted=len(output)+8<=capacity
        if accepted: output.extend(struct.pack('<Q',value))
        sp=machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RAX,int(accepted))
        machine.reg_write(x.UC_X86_REG_RIP,int.from_bytes(machine.mem_read(sp,8),'little'))
        machine.reg_write(x.UC_X86_REG_RSP,sp+8)
    hooks[WRITE64]=fixture
    cases=[]
    for value in (0,1,0x0123456789abcdef,2**63,2**64-1):
        for capacity in (0,7,8,9):
            uc.mem_write(obj,b'\xa5'*32)
            h.call(CTOR,obj)
            if bytes(uc.mem_read(obj,8))!=struct.pack('<Q',TABLE203): raise ValueError('Constructor table differs')
            if bytes(uc.mem_read(obj+0x10,8))!=bytes(8): raise ValueError('Constructor value differs')
            uc.mem_write(obj+0x10,struct.pack('<Q',value))
            before=bytes(uc.mem_read(obj,32)); output.clear(); calls.clear()
            h.call(WRITER,obj,writer)
            accepted=capacity>=8
            if (uc.reg_read(x.UC_X86_REG_RAX)&255)!=int(accepted): raise ValueError('Writer result differs')
            if calls!=[value] or bytes(output)!=(struct.pack('<Q',value) if accepted else b''):
                raise ValueError('Writer output differs')
            if bytes(uc.mem_read(obj,32))!=before: raise ValueError('Writer changed packet')
            cases.append(dict(value=value,capacity=capacity,accepted=accepted,body_hex=bytes(output).hex()))
    report=dict(source_sha256=h.sha,tool_sha256=h.audit.sha256(Path(__file__)),evidence_sha256=expected,
        native_execution=True,network_used=False,constructor=hex(CTOR),writer=hex(WRITER),
        packet_ids=[202,203],leaves=h.leaves,fragments=h.fragments,cases=cases,
        limits=['Whole constructor, ID getters and writer executed from current SHA.',
            'Output archive virtual +0xb8 is a bounded uint64 fixture; no real native archive backend.',
            'ID202 reader, registration, request lifecycle, world readiness and position are not executed.',
            'Only synthetic values; no game, account or network IO.'])
    target=h.audit.save_snapshot(h.comparison/'world-start-writer-replay',report)
    return target,h.audit.sha256(target)


if __name__=='__main__':
    path,sha=run(); print(json.dumps(dict(report=str(path),sha256=sha,cases=20)))
