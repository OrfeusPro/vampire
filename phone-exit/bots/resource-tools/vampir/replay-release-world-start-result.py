"""Current whole ID204 reader with actual scalar/vector readers, synthetic IO."""
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
READER, VECTOR, READ64, FLOAT = 0x1458507c0, 0x144aae290, 0x144aad7c0, 0x144aad640
TABLE, GETTER = 0x14996d6c8, 0x145759190


def run():
    spec=importlib.util.spec_from_file_location('start_result_archive',HERE/'replay-release-archive-input.py')
    archive=importlib.util.module_from_spec(spec);spec.loader.exec_module(archive)
    h=archive.make_harness(extra_addresses=(READER,VECTOR,READ64,FLOAT),extra_leaves=(GETTER,))
    evidence={
        'details/run-8e61a9c886bd/details.json':'71c410e80ea08fad68b32548373d8d40965bb1d27f4180edae37e18535f9420a',
        'details/run-273103367ebd/details.json':'24b73bd8d6edf1ff427614d88d78a61852fd6b56fdc4404665048aebc27769b6',
        'details/run-814364d053aa/details.json':'6216fc5f3e83db08510d29129eaf0ba4fe4e42465d1a2f0f1d19cbb2feb58188'}
    for relative,expected in evidence.items():
        if h.audit.sha256(h.comparison/relative)!=expected:raise ValueError('Reader evidence changed')
    offset=h.image.offset(TABLE-h.image.pe.base)
    if struct.unpack_from('<QQ',h.raw,offset+0x20)!=(READER,GETTER):
        raise ValueError('ID204 reader/getter table differs')
    if h.call(GETTER,h.obj)!=204:raise ValueError('Packet ID differs')
    uc=h.uc;packet=h.scratch+0x10000
    def execute(payload):
        h.call(h.ctor,h.obj)
        uc.mem_write(h.buffer,bytes(64))
        if payload:uc.mem_write(h.buffer,payload)
        uc.mem_write(h.obj+0x20,struct.pack('<QI',h.buffer,len(payload)))
        uc.mem_write(h.obj+0x30,struct.pack('<Q',h.buffer))
        # Packet storage is explicit; packet constructor/registration are not executed.
        uc.mem_write(packet,bytes(0x40))
        accepted=h.call(READER,packet,h.obj)&255
        consumed=int.from_bytes(uc.mem_read(h.obj+0x30,8),'little')-h.buffer
        return accepted,consumed
    cases=[]
    vectors=((0,0x80000000,0x3f800000),(0xbf800000,0x7f7fffff,0x00800000),(1,2,3))
    for bits in vectors:
        for kind in (0,21,22,255):
            for flag in (0,1,255):
                for code in (0,16):
                    payload=struct.pack('<IIIIIBBQ',code,0x12345678,*bits,kind,flag,0xfedcba9876543210)
                    accepted,consumed=execute(payload)
                    expected_vector=struct.pack('<ddd',*(struct.unpack('<f',struct.pack('<I',b))[0] for b in bits))
                    fields=[int.from_bytes(uc.mem_read(packet+0x10,4),'little'),
                        int.from_bytes(uc.mem_read(packet+0x14,4),'little'),uc.mem_read(packet+0x30,1)[0],
                        bool(uc.mem_read(packet+0x31,1)[0]),int.from_bytes(uc.mem_read(packet+0x38,8),'little')]
                    if (accepted,consumed)!=(1,30) or fields!=[code,0x12345678,min(kind,22),bool(flag),0xfedcba9876543210]:
                        raise ValueError('Start result fields differ')
                    vector=bytes(uc.mem_read(packet+0x18,24))
                    if vector!=expected_vector:raise ValueError('Native vector differs')
                    cases.append(dict(body_hex=payload.hex(),fields=fields,vector_hex=vector.hex()))
    short=[]
    for size in range(30):
        accepted,consumed=execute(payload[:size])
        if accepted or consumed!=size:raise ValueError('Short result was accepted or consumption differs')
        short.append(dict(size=size,consumed=consumed))
    report=dict(source_sha256=h.sha,tool_sha256=h.audit.sha256(Path(__file__)),evidence=evidence,
        native_execution=True,network_used=False,packet_id=204,table=hex(TABLE),reader=hex(READER),
        fragments=h.fragments,leaves=h.leaves,cases=cases,short=short,
        limits=['Whole current reader, vector helper and scalar readers execute; little-endian input only.',
            'Actual input archive default constructor with explicit buffer fixture and bounded memcpy fixture.',
            'Packet storage is synthetic; packet constructor, registration, handler and world loader do not execute.',
            'Portable decoder additionally rejects trailing bytes; vector world-position semantics remain unproved.',
            'No account, game or network IO.'])
    target=h.audit.save_snapshot(h.comparison/'world-start-result-replay',report)
    return target,h.audit.sha256(target)


if __name__=='__main__':
    path,sha=run();print(json.dumps(dict(report=str(path),sha256=sha,cases=72,short=30)))
