"""Execute ID202 reader only through nested18, stopping before opaque nested30."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
READER, NESTED, THUNK = 0x1458506a0, 0x145823280, 0x144aae4e0
BOUNDARY = 0x3000d000


def run():
    spec = importlib.util.spec_from_file_location('reserve_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(archive)
    hooks = {BOUNDARY: None}
    h = archive.make_harness(extra_addresses=(READER, NESTED), extra_leaves=(THUNK,), fixtures=hooks)
    evidence = {
        'details/run-3daa86310054/details.json': 'bb0875c2ad7ed84d7d33a72a7d34e5c6c1902cde22969feea95d8db60dad4582',
        'details/run-8ca8ce322478/details.json': 'd6e0b648574b934150cdf23a82a74043101a667f36d71e8fb85a2ac7a6d758ed',
    }
    for relative, expected in evidence.items():
        if h.audit.sha256(h.comparison / relative) != expected:
            raise ValueError('Reserve reader evidence changed')
    uc, x = h.uc, h.x
    packet, nested_table, opaque_table = [h.scratch+n for n in (0x10000, 0x11000, 0x12000)]
    uc.mem_write(nested_table+0x20, struct.pack('<Q', NESTED))
    uc.mem_write(opaque_table+0x20, struct.pack('<Q', BOUNDARY))
    reached = False

    def boundary(machine):
        nonlocal reached
        if (machine.reg_read(x.UC_X86_REG_RCX), machine.reg_read(x.UC_X86_REG_RDX)) != (packet+0x30, h.obj):
            raise ValueError('Unexpected opaque boundary arguments')
        reached = True
        # Stop, do not simulate success of an unparsed world collection.
        machine.reg_write(x.UC_X86_REG_RIP, h.stop)
    hooks[BOUNDARY] = boundary
    cases = []
    values = [(0, 0, 0, 0, 0, 0), (16, 31, 1, 1, 1, 21),
              (0, 32, 2**63, 2**31, 2, 22), (0, 255, 2**64-1, 2**32-1, 255, 255)]
    for code, kind, raw20, raw28, flag, reason in values:
        payload = struct.pack('<IBQIBB', code, kind, raw20, raw28, flag, reason)
        for available in range(20):
            reached = False
            h.call(h.ctor, h.obj)
            uc.mem_write(h.buffer, payload)
            uc.mem_write(h.obj+0x20, struct.pack('<QI', h.buffer, available))
            uc.mem_write(h.obj+0x30, struct.pack('<Q', h.buffer))
            uc.mem_write(packet, b'\xcc'*0x240)
            uc.mem_write(packet+0x18, struct.pack('<Q', nested_table))
            uc.mem_write(packet+0x30, struct.pack('<Q', opaque_table))
            returned = h.call(READER, packet, h.obj) & 255
            consumed = int.from_bytes(uc.mem_read(h.obj+0x30,8),'little')-h.buffer
            if reached != (available == 19) or consumed != available or (not reached and returned):
                raise ValueError('Reserve prefix boundary / truncation differs')
            fields = None
            if reached:
                fields = [int.from_bytes(uc.mem_read(packet+0x10,4),'little'),
                    uc.mem_read(packet+0x14,1)[0],
                    int.from_bytes(uc.mem_read(packet+0x20,8),'little'),
                    int.from_bytes(uc.mem_read(packet+0x28,4),'little'),
                    bool(uc.mem_read(packet+0x2c,1)[0]), uc.mem_read(packet+0x2d,1)[0]]
                if fields != [code,min(kind,32),raw20,raw28,bool(flag),min(reason,22)]:
                    raise ValueError('Reserve prefix fields differ')
            cases.append(dict(body_hex=payload[:available].hex(), consumed=consumed,
                reached_opaque_boundary=reached, fields=fields))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        evidence=evidence, native_execution=True, network_used=False,
        outer_reader=hex(READER), nested_reader=hex(NESTED), fragments=h.fragments,
        leaves=h.leaves, cases=cases,
        limits=['Actual outer reader executes only through nested18; nested18 and scalar readers execute fully.',
            'Nested object vtables and input buffer are explicit fixtures; memcpy is the bounded archive fixture.',
            'Execution stops at nested30 entry; no success or validation of the complete ID202 body is claimed.',
            'No registration dispatch, handler, world readiness, position, account or network IO.'])
    target = h.audit.save_snapshot(h.comparison/'world-reserve-prefix-replay',report)
    return target,h.audit.sha256(target)


if __name__ == '__main__':
    path,sha=run()
    print(json.dumps(dict(report=str(path),sha256=sha,cases=80)))
