"""Execute current incoming movement readers on bounded synthetic bodies. No IO."""
import importlib.util
import json
import math
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent


def run():
    spec = importlib.util.spec_from_file_location('move_archive', HERE/'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec); spec.loader.exec_module(archive)
    h = archive.make_harness(extra_addresses=(0x1456c5190, 0x1456c5b60, 0x144aae220, 0x144aad640),
        extra_leaves=(0x1456c0040, 0x1456c0060, 0x1456d01a0, 0x1456d01b0))
    evidence = {'details/run-3cc1c3aeb25b/details.json':
        '42cad9c107821d91e1783be10a6b1b19ccddd9ae2ba5da38bf343d523d62eeda',
        'details/run-e94b2afaa516/details.json':
        'ced9ba6f512331429cf3cf0e6644d4d3d27ce2708cd2b87e52d40f917a2658c4'}
    for path, sha in evidence.items():
        if h.audit.sha256(h.comparison/path) != sha: raise ValueError('Movement evidence changed')
    sys.path.insert(0, str(HERE.parents[1]/'vampir-shared'))
    from vampir_core.character_move_event import decode_move_notify, decode_move_result
    uc = h.uc; packet = h.scratch+0x10000
    bindings = {306:(0x1499229e0,0x1456c0060,0x1456c5190,0x1456d01b0),
                307:(0x149922870,0x1456c0040,0x1456c5b60,0x1456d01a0)}
    for table, ctor, reader, getter in bindings.values():
        off = h.image.offset(table-h.image.pe.base)
        if struct.unpack_from('<QQ', h.raw, off+0x20) != (reader,getter):
            raise ValueError('Movement packet table changed')
    def read(packet_id, body):
        table, ctor, reader, getter = bindings[packet_id]
        uc.mem_write(packet, bytes(64)); h.call(ctor,packet)
        if int.from_bytes(uc.mem_read(packet,8),'little') != table or h.call(getter,packet) != packet_id:
            raise ValueError('Movement constructor/getter differs')
        uc.mem_write(h.buffer, bytes(64))
        if body: uc.mem_write(h.buffer, body)
        h.call(h.ctor,h.obj)
        uc.mem_write(h.obj+0x20,struct.pack('<QI',h.buffer,len(body)))
        uc.mem_write(h.obj+0x30,struct.pack('<Q',h.buffer))
        accepted = h.call(reader,packet,h.obj)&255
        consumed = int.from_bytes(uc.mem_read(h.obj+0x30,8),'little')-h.buffer
        return accepted,consumed
    cases = []
    values = (0,0x80000000,0x3f800000,0xc2f68000,0x7f800000,0x7fc12345)
    for key in (0,1,2**63,2**64-1):
        for bits in values:
            body = struct.pack('<QII',key,bits,0x43800000)
            if read(307,body) != (1,16): raise ValueError('Notify reader differs')
            got_key = int.from_bytes(uc.mem_read(packet+0x10,8),'little')
            xy = struct.unpack('<dd',uc.mem_read(packet+0x18,16))
            decoded = decode_move_notify(body,source_sha256=h.sha)
            expected = struct.unpack('<ff',body[8:])
            if got_key != decoded.entity_key: raise ValueError('Notify key differs')
            for native, portable in zip(xy,expected):
                if math.isnan(portable):
                    if not math.isnan(native): raise ValueError('Notify NaN differs')
                elif struct.pack('<d',native) != struct.pack('<d',portable):
                    raise ValueError('Notify coordinate differs')
            if all(math.isfinite(v) for v in expected):
                if decoded.finite_xy() != expected: raise ValueError('Finite XY differs')
            else:
                try: decoded.finite_xy()
                except ValueError: pass
                else: raise ValueError('Nonfinite XY admitted to consumer')
            cases.append(dict(packet_id=307,key=key,x_bits=bits))
    for value in (0,1,16,2**32-1):
        body = struct.pack('<I',value)
        if read(306,body) != (1,4): raise ValueError('Result reader differs')
        if int.from_bytes(uc.mem_read(packet+0x10,4),'little') != decode_move_result(body,source_sha256=h.sha):
            raise ValueError('Result field differs')
        cases.append(dict(packet_id=306,value=value))
    short = []
    for packet_id,size in ((306,4),(307,16)):
        for length in range(size):
            accepted,consumed = read(packet_id,bytes(length))
            if accepted or consumed>length: raise ValueError('Short movement body accepted')
            short.append(dict(packet_id=packet_id,length=length,consumed=consumed))
    report = dict(source_sha256=h.sha,tool_sha256=h.audit.sha256(Path(__file__)),
        evidence=evidence,fragments=h.fragments,leaves=h.leaves,cases=cases,short=short,
        native_execution=True,network_used=False,
        limits=['Whole current constructors, ID getters and readers including nested XY execute.',
            'Archive memcpy is a bounded fixture; samples are synthetic, not captured gameplay.',
            'No Z or world is present in ID307. Entity ownership, movement semantics, handlers and live updates remain unproven.',
            'ID306 raw uint32 is not interpreted as acknowledgement or an error enum.'])
    path = h.audit.save_snapshot(h.native.ROOT/'code-clues/release-character-move-replay',report)
    return path,report


if __name__=='__main__':
    path,report = run()
    print(json.dumps(dict(report=str(path),cases=len(report['cases']),short=len(report['short']))))
