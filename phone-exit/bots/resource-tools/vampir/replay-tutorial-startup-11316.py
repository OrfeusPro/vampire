"""Current fresh tutorial application/bootstrap; bounded table/storage fixtures."""
import importlib.util
import json
from pathlib import Path
import struct
HERE=Path(__file__).resolve().parent
KEYS=(1001,3001,3002,3007,3008,3009,3011,3012,3014,3015,3024,4017,4018,4019,4020,4021)

def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def run():
    context_path=HERE/'knowledge/native-contexts/tutorial-startup-11316.json'
    current=json.loads(context_path.read_text('utf-8'))
    functions={k:int(v,16) for k,v in current['functions'].items()}
    h=load('native-request-harness-11316').make_harness(current['exports'],set(functions.values()),
        leaves={int(k,16):v for k,v in current['leaves'].items()})
    if current['source_sha256']!=h.sha:raise ValueError('Startup context source differs')
    fixtures={a:None for a in (0x145c24be0,0x145c24d40,0x141444d40,0x141437480,
        0x141427140,0x141440ec0,0x1487e8ce0,0x1464ce5b0)}
    uc, x, b = h.uc, h.x, h.scratch
    context, server_nodes, local_nodes = b + 0x10000, b + 0x11000, b + 0x12000
    server_buckets, local_buckets = b + 0x13000, b + 0x14000
    data, records, row, group, status_nodes = [b + n for n in (0x15000, 0x16000, 0x17000, 0x18000, 0x19000)]
    guarded=((context,0x400),(server_nodes,32*40),(local_nodes,32*40),
        (server_buckets,128),(local_buckets,128),(data,0x30),(records,16*24),
        (row,0x80),(group,16),(status_nodes,32*16))
    launches, lookups = [], []
    row_found, selector, source_state = True, 0, 1

    def u32(address):
        return int.from_bytes(uc.mem_read(address, 4), 'little')

    def return_from_fixture(machine, value):
        sp = machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RAX, value)
        machine.reg_write(x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(x.UC_X86_REG_RSP, sp + 8)

    def fixture(machine):
        address = machine.reg_read(x.UC_X86_REG_RIP)
        a, c, d = [machine.reg_read(reg) for reg in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        value = 0
        if address in (0x145c24be0, 0x145c24d40):
            key = c & 0xffffffff if address == 0x145c24be0 else u32(c)
            if key not in KEYS:
                raise ValueError('Unexpected table lookup key')
            lookups.append((address, key))
            pointer = (row if address == 0x145c24be0 else group) if row_found else 0
            if address == 0x145c24be0:
                machine.mem_write(a, struct.pack('<IIQ', key, 0, pointer))
            else:
                machine.mem_write(a, struct.pack('<Q', pointer))
            value = a
        elif address == 0x141444d40:
            if a not in (context + 0xa8, context + 0x1c8):
                raise ValueError('Map slot allocator context differs')
            index = u32(a + 8)
            if index >= 32 or u32(a + 0x34):
                raise ValueError('Fresh bounded map storage required')
            nodes = server_nodes if a == context + 0xa8 else local_nodes
            node = nodes + index * 40
            machine.mem_write(node, bytes(40))
            machine.mem_write(a + 8, struct.pack('<I', index + 1))
            machine.mem_write(a + 0x28, struct.pack('<I', index + 1))
            machine.mem_write(a + 0x10, struct.pack('<I', (1 << (index + 1)) - 1))
            machine.mem_write(c, struct.pack('<IIQ', index, 0, node))
        elif address == 0x141437480:
            if c or u32(a + 8) != 1 or int.from_bytes(machine.mem_read(a, 8), 'little'):
                raise ValueError('Fresh bounded status storage required')
            machine.mem_write(status_nodes, bytes(32 * 16))
            machine.mem_write(a, struct.pack('<Q', status_nodes))
            machine.mem_write(a + 12, struct.pack('<I', 32))
        elif address in (0x141427140, 0x141440ec0):
            pointer = int.from_bytes(machine.mem_read(a, 8), 'little')
            if address == 0x141427140 and (pointer or u32(a + 8) or u32(a + 0x34)):
                raise ValueError('Prune cleanup requires an empty temporary set')
            if address == 0x141440ec0 and pointer not in (0, status_nodes):
                raise ValueError('Status cleanup escaped prepared storage')
        elif address == 0x1487e8ce0:
            value = machine.reg_read(x.UC_X86_REG_RAX)
        elif address == 0x1464ce5b0:
            if a != context or c != local_nodes + 8 or d != selector + 1:
                raise ValueError('Initial task launch differs')
            launches.append(d)
        else:
            raise ValueError('Unexpected startup fixture')
        return_from_fixture(machine, value)

    for address in fixtures:
        h.add_fixture(address, fixture)

    def map_setup(offset, nodes, buckets):
        header = context + offset
        uc.mem_write(header, bytes(0x50))
        uc.mem_write(header, struct.pack('<QII', nodes, 0, 32))
        uc.mem_write(header + 0x28, struct.pack('<IIiI', 0, 128, -1, 0))
        uc.mem_write(header + 0x40, struct.pack('<QI', buckets, 32))
        uc.mem_write(buckets, b'\xff' * 128)

    cases = []
    for count in (0, 1, 16):
        for row_found in (False, True):
            for policy_raw50 in (0, 1):
                for source_state in (0, 1, 2, 3):
                    for selector in (0, 1):
                        for flag in (0, 1):
                            for at,size in guarded:
                                uc.mem_write(at-16,b'\xa1'*16+bytes(size)+b'\xa2'*16)
                            uc.mem_write(context, bytes(0x400))
                            map_setup(0xa8, server_nodes, server_buckets)
                            map_setup(0x1c8, local_nodes, local_buckets)
                            uc.mem_write(data, bytes(0x30))
                            uc.mem_write(data + 8, bytes([flag]))
                            uc.mem_write(data + 0x10, struct.pack('<QII', records, count, count))
                            uc.mem_write(row, bytes(0x80))
                            uc.mem_write(row + 0x50, struct.pack('<I', policy_raw50))
                            uc.mem_write(group, struct.pack('<QI', 0, 2))
                            for i, key in enumerate(KEYS[:count]):
                                uc.mem_write(records + 24 * i, bytes(24))
                                uc.mem_write(records + 24 * i + 8, struct.pack('<IIIB', key,
                                    selector if i == 0 else 0, 0x12340000 + i, source_state if i == 0 else 0))
                            launches.clear()
                            lookups.clear()
                            uc.reg_write(x.UC_X86_REG_RDX,data)
                            h.call(0x1464c35d0,context,budget=1000000)
                            expected_count = count if row_found else 0
                            if u32(context + 0xb0) != expected_count:
                                raise ValueError(f'Notify row filtering differs: count={count}, found={row_found}, '
                                    f'policy={policy_raw50}, state={source_state}, selector={selector}, '
                                    f'flag={flag}, actual={u32(context + 0xb0)}, lookups={lookups}')
                            for i in range(expected_count):
                                native = struct.unpack('<IIIB', uc.mem_read(server_nodes + i * 40 + 16, 13))
                                expected = struct.unpack('<IIIB', uc.mem_read(records + i * 24 + 8, 13))
                                if native != expected:
                                    raise ValueError('Native server record copy differs')
                            active = bool(count and row_found and source_state == 1)
                            if u32(context + 0x1d0) != int(active) or launches != ([selector + 1] if active else []):
                                raise ValueError('Initial bootstrap eligibility differs')
                            if active and struct.unpack('<IIIB', uc.mem_read(local_nodes + 16, 13)) != (
                                    1001, selector + 1, 0x12340000, 1):
                                raise ValueError('Initial local record differs')
                            for at,size in guarded:
                                if bytes(uc.mem_read(at-16,16))!=b'\xa1'*16 or bytes(uc.mem_read(at+size,16))!=b'\xa2'*16:
                                    raise ValueError('Tutorial startup storage guard changed')
                            cases.append(dict(count=count, row_found=row_found, policy_raw50=policy_raw50,
                                state=source_state, selector=selector, flag=flag, launched=launches[:]))
    audit=load('audit-client-release')
    report=dict(source_sha256=h.sha,tool_sha256=audit.sha256(Path(__file__)),
        context_sha256=audit.sha256(context_path),exports=h.evidence,cases=cases,
        native_execution=True,network_used=False,
        limits=['Whole current apply, map record copy/hash link, no-removal prune, bootstrap, builder, advance and early gate execute.',
            'Table lookup/group descriptor, map/status slot allocation, temporary cleanup, cookie check and task launch are bounded fixtures.',
            'Fresh unique snapshots only; duplicate replacement, map growth, missing-key removal, existing local tasks and completion gate branches not covered.',
            'Synthetic row+0x50 and descriptor+8 are not renamed CSV fields; no live tutorial/UI/readiness or outgoing-command proof.'])
    path=audit.save_snapshot(h.root/'code-clues/tutorial-startup-11316',report)
    return path,report

if __name__=='__main__':
    p,r=run();print(json.dumps(dict(report=str(p),cases=len(r['cases']))))
