"""Current pending-key removal, ID 9904 deferral and record application; no game IO."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def run():
    spec = importlib.util.spec_from_file_location('tutorial_apply_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(archive)
    fixtures = {a: None for a in (0x1464a1f20, 0x1464c5770, 0x1464cfb80, 0x14560c570, 0x14690a090)}
    h = archive.make_harness(extra_addresses=(0x141682d60, 0x14163c5f0, 0x14163c480,
        0x1464c06d0, 0x1464d1770, 0x1464c4ea0, 0x14584d0a0),
        extra_leaves=(0x1457fee50, 0x1458571a0), fixtures=fixtures)
    evidence = {
        'details/run-0d509e824f91/details.json': '116e67e3daec8c5756fcb162c278265576e3f818f6d47adb585b11798ea314e4',
        'details/run-0de2f414b053/details.json': '277cf568f4fa8f1c0dd73d19005e0515b7f1c028706c63f5db4827224ed8537c',
        'details/run-4ec0da51a9f0/details.json': '1032df87507c1f596263b595c5af677a3312a275d7d619e58db5447e5949e7dd',
        'details/run-8a2129c0aba9/details.json': 'b74b3ffe9aeb054caa8a7e5cbde10ec001ff46e2615b63cbdd3c525ea35d6869',
        'details/run-96ebf1b2b695/details.json': '226982393df75a181050ee2d2e86d30756e527b8fe86a843c8951bf380cb8d72'}
    for relative, sha in evidence.items():
        if h.audit.sha256(h.comparison / relative) != sha:
            raise ValueError('Tutorial apply evidence changed')
    uc, x, b = h.uc, h.x, h.scratch
    context, pending_nodes, flag_heap, buckets = b + 0x10000, b + 0x11000, b + 0x12000, b + 0x13000
    server_nodes, local_nodes, inserted = b + 0x14000, b + 0x15000, b + 0x16000
    packet, clone, state_object, queue = b + 0x17000, b + 0x18000, b + 0x19000, b + 0x1a000
    for table in (0x14996ba48, 0x14992afc0):
        page = table & ~4095
        if not any(lo <= page <= hi for lo, hi, _ in uc.mem_regions()):
            uc.mem_map(page, 4096)
            offset = h.image.offset(page - h.image.pe.base)
            uc.mem_write(page, h.raw[offset:offset + 4096])
    pending = context + 0x268

    def u32(address):
        return int.from_bytes(uc.mem_read(address, 4), 'little')

    def pending_setup(external=False, external_flags=False):
        uc.mem_write(pending, bytes(0x50))
        uc.mem_write(pending, struct.pack('<QII', pending_nodes, 3, 3))
        uc.mem_write(pending + 0x10, struct.pack('<I', 7))
        uc.mem_write(flag_heap, struct.pack('<I', 7))
        uc.mem_write(pending + 0x20, struct.pack('<Q', flag_heap if external_flags else 0))
        uc.mem_write(pending + 0x30, struct.pack('<i', -1))
        uc.mem_write(pending + 0x38, struct.pack('<i', 0))
        uc.mem_write(pending + 0x40, struct.pack('<QI', buckets if external else 0, 1))
        uc.mem_write(buckets, struct.pack('<i', 0))
        for i, key in enumerate((0, 1001, 0xffffffff)):
            uc.mem_write(pending_nodes + 12 * i, struct.pack('<IiI', key, i + 1 if i < 2 else -1, 0))

    def pending_keys(external):
        index = struct.unpack('<i', uc.mem_read(buckets if external else pending + 0x38, 4))[0]
        keys = []
        while index != -1:
            if not 0 <= index < 3 or len(keys) >= 3:
                raise ValueError('Pending chain became cyclic or invalid')
            keys.append(u32(pending_nodes + 12 * index))
            index = struct.unpack('<i', uc.mem_read(pending_nodes + 12 * index + 4, 4))[0]
        return keys

    removals = []
    for external in (False, True):
        for external_flags in (False, True):
            for index, key in enumerate((0, 1001, 0xffffffff)):
                pending_setup(external, external_flags)
                if h.call(0x141682d60, pending, key) != 1:
                    raise ValueError('Native pending removal failed')
                expected = [k for k in (0, 1001, 0xffffffff) if k != key]
                flags = u32(flag_heap if external_flags else pending + 0x10)
                if pending_keys(external) != expected or flags != 7 & ~(1 << index):
                    raise ValueError('Pending hash chain or allocation flags differ')
                if (u32(pending + 0x30), u32(pending + 0x34)) != (index, 1):
                    raise ValueError('Pending free list differs')
                before = bytes(uc.mem_read(pending, 0x50)) + bytes(uc.mem_read(pending_nodes, 36))
                if h.call(0x141682d60, pending, key) or h.call(0x141682d60, pending, 77):
                    raise ValueError('Missing pending key was removed')
                if before != bytes(uc.mem_read(pending, 0x50)) + bytes(uc.mem_read(pending_nodes, 36)):
                    raise ValueError('Missing-key removal mutated storage')
                removals.append(dict(key=key, external=external, external_flags=external_flags,
                                     remaining=expected, flags=flags))

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

    events, blocked, selector, incoming_state = [], False, 0, 0

    def fixture(machine):
        address = machine.reg_read(x.UC_X86_REG_RIP)
        a, c, d, e = [machine.reg_read(reg) for reg in
            (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        result = 0
        if address == 0x1464a1f20:
            if a != context + 0xa8 or c != 1001:
                raise ValueError('Authoritative insertion fixture arguments differ')
            result = inserted
            events.append('insert_fixture')
        elif address == 0x1464c5770:
            if (a, c, d, e) != (context, 1001, selector, incoming_state):
                raise ValueError('Tutorial gate arguments differ')
            events.append('gate_fixture')
            result = int(blocked)
        elif address == 0x1464cfb80:
            if (a, c, d) != (context, local_nodes + 48, (selector if keep or blocked else selector + 1) & 0xffffffff):
                raise ValueError('Task launch arguments differ')
            events.append('launch_fixture')
        elif address == 0x14560c570:
            result = state_object
        elif address == 0x14690a090:
            if a != 0x38:
                raise ValueError('Deferred clone allocation bound')
            uc.mem_write(clone, bytes(0x38))
            result = clone
            events.append('clone_fixture')
        else:
            raise ValueError('Unexpected apply fixture')
        sp = machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RAX, result)
        machine.reg_write(x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(x.UC_X86_REG_RSP, sp + 8)

    for address in fixtures:
        fixtures[address] = fixture

    def setup(server_present, local_present, external):
        uc.mem_write(context, bytes(0x400))
        uc.mem_write(inserted, b'\xa5' * 24)
        server = map_setup(0xa8, server_nodes, server_present, external)
        local = map_setup(0x1c8, local_nodes, local_present, external)
        h.call(0x14584d0a0, packet)
        uc.mem_write(packet + 0x20, struct.pack('<IIIB', 1001, selector, 0x12345678, incoming_state))
        uc.mem_write(packet + 0x30, bytes((1, keep)))
        events.clear()
        return server or inserted, local

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
                                h.call(0x1464d1770, context, packet + 0x18, keep)
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
                                applied.append(dict(server_present=server_present, local_present=local_present,
                                    external=external, selector=selector, state=incoming_state, keep=keep, blocked=blocked))

    phases = []
    selector, incoming_state = 2, 1
    for phase in (0, 5, 6, 7):
        for bypass in (0, 1):
            for keep in (0, 1):
                for blocked in (False, True):
                    server, local = setup(True, True, False)
                    pending_setup()
                    uc.mem_write(context + 0x198, struct.pack('<QII', queue, 0, 4))
                    uc.mem_write(state_object + 0x30, bytes([phase]))
                    before = bytes(uc.mem_read(server, 24)) + bytes(uc.mem_read(local, 24))
                    h.call(0x1464c06d0, context, packet, bypass)
                    deferred = not bypass and phase < 6
                    if deferred:
                        if events != ['clone_fixture'] or u32(context + 0x1a0) != 1:
                            raise ValueError('Early result was not queued')
                        if int.from_bytes(uc.mem_read(queue, 8), 'little') != clone:
                            raise ValueError('Deferred queue pointer differs')
                        for offset, size in ((0x10, 4), (0x20, 13), (0x30, 2)):
                            if bytes(uc.mem_read(clone + offset, size)) != bytes(uc.mem_read(packet + offset, size)):
                                raise ValueError('Deferred clone fields differ')
                        uc.mem_write(packet + 0x20, bytes(13))
                        if u32(clone + 0x20) != 1001 or pending_keys(False) != [0, 1001, 0xffffffff]:
                            raise ValueError('Deferred copy aliased input or removed pending key')
                        if before != bytes(uc.mem_read(server, 24)) + bytes(uc.mem_read(local, 24)):
                            raise ValueError('Early result changed applied records')
                    else:
                        if pending_keys(False) != [0, 0xffffffff] or u32(pending + 0x34) != 1:
                            raise ValueError('Ready result did not remove pending key')
                        if u32(server + 12) != 2 or u32(local + 12) != (2 if keep or blocked else 3):
                            raise ValueError('Ready result did not apply correct selector')
                        if u32(context + 0x1a0):
                            raise ValueError('Ready result entered deferred queue')
                    phases.append(dict(phase=phase, bypass=bypass, keep=keep, blocked=blocked, deferred=deferred))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        evidence=evidence, fragments=h.fragments, leaves=h.leaves, removals=removals, applied=applied,
        phases=phases, native_execution=True, network_used=False,
        limits=['Whole pending lookup/unlink/sparse free, receiver, ID 9904 clone and record application execute.',
                'Existing maps use bounded prepared storage; fresh authoritative insertion, clone allocation and client phase are fixtures.',
                'The actual task gate and task execution remain fixtures; no active UI or live tutorial completion claim.',
                'Deferred queue uses preallocated capacity; growth and automatic queue drain do not execute.'])
    path = h.audit.save_snapshot(h.native.ROOT / 'code-clues/release-tutorial-apply-replay', report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), removals=len(report['removals']),
                          applied=len(report['applied']), phases=len(report['phases']))))
