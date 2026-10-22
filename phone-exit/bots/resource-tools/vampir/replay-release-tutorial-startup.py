"""Fresh ID 9905 snapshot through native maps/bootstrap/advance and early native gate."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
KEYS = (1001, 3001, 3002, 3007, 3008, 3009, 3011, 3012, 3014, 3015, 3024, 4017, 4018, 4019, 4020, 4021)


def run():
    spec = importlib.util.spec_from_file_location('tutorial_startup_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(archive)
    fixtures = {address: None for address in (0x145c25f20, 0x145c26080, 0x141444e20,
        0x141437560, 0x141427220, 0x141440fa0, 0x1487eac40, 0x1464cfb80)}
    h = archive.make_harness(extra_addresses=(0x1464c4ba0, 0x1464a1460, 0x1464c67e0,
        0x1464cfeb0, 0x1464d0510, 0x1464cd6f0, 0x1464c5770, 0x14142e7d0),
        extra_leaves=(0x141488570, 0x1415004f0), fixtures=fixtures)
    evidence = {
        'details/run-766fdcdd1675/details.json': '83949d36af5bd2d984fa466377d0ca3345eac8c5bf92e340dbd1695bca89d394',
        'details/run-7a2165c27774/details.json': '7615373c76fb428868e4cd3159f009c0b6705a0c305152f4980d9afb38e919d1',
        'details/run-fdcbbd469256/details.json': '059c0634783da459057b5d782a7a31561c8d5a2a2dea10802c5762feee95fa7a',
        'details/run-9857fba8074e/details.json': '78ad55694af3927aa51093ca012a7a6f0b18810f5cfb417c78396e0329f8b4b2',
        'details/run-3a40930c8abf/details.json': 'aadbdfcd1efca904840d3fb9a9c0539a955c34cb030ca91d05f7a884b11967f8',
        'details/run-8786dbdc4bc0/details.json': '227163658055fb21668f6dedd1af0b5678fd3cdcfcf1658ff831dbc4f4f64f82',
        'details/run-c66fc08ad15f/details.json': '6a4f43f01b79aeaf4116f2c33528b137ba6a23fce4b4fedd3b6ba7639fb65cbf'}
    for relative, sha in evidence.items():
        if h.audit.sha256(h.comparison / relative) != sha:
            raise ValueError('Startup evidence changed')
    uc, x, b = h.uc, h.x, h.scratch
    context, server_nodes, local_nodes = b + 0x10000, b + 0x11000, b + 0x12000
    server_buckets, local_buckets = b + 0x13000, b + 0x14000
    data, records, row, group, status_nodes = [b + n for n in (0x15000, 0x16000, 0x17000, 0x18000, 0x19000)]
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
        if address in (0x145c25f20, 0x145c26080):
            key = c & 0xffffffff if address == 0x145c25f20 else u32(c)
            if key not in KEYS:
                raise ValueError('Unexpected table lookup key')
            lookups.append((address, key))
            pointer = (row if address == 0x145c25f20 else group) if row_found else 0
            if address == 0x145c25f20:
                machine.mem_write(a, struct.pack('<IIQ', key, 0, pointer))
            else:
                machine.mem_write(a, struct.pack('<Q', pointer))
            value = a
        elif address == 0x141444e20:
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
        elif address == 0x141437560:
            if c or u32(a + 8) != 1 or int.from_bytes(machine.mem_read(a, 8), 'little'):
                raise ValueError('Fresh bounded status storage required')
            machine.mem_write(status_nodes, bytes(32 * 16))
            machine.mem_write(a, struct.pack('<Q', status_nodes))
            machine.mem_write(a + 12, struct.pack('<I', 32))
        elif address in (0x141427220, 0x141440fa0):
            pointer = int.from_bytes(machine.mem_read(a, 8), 'little')
            if address == 0x141427220 and (pointer or u32(a + 8) or u32(a + 0x34)):
                raise ValueError('Prune cleanup requires an empty temporary set')
            if address == 0x141440fa0 and pointer not in (0, status_nodes):
                raise ValueError('Status cleanup escaped prepared storage')
        elif address == 0x1487eac40:
            value = machine.reg_read(x.UC_X86_REG_RAX)
        elif address == 0x1464cfb80:
            if a != context or c != local_nodes + 8 or d != selector + 1:
                raise ValueError('Initial task launch differs')
            launches.append(d)
        else:
            raise ValueError('Unexpected startup fixture')
        return_from_fixture(machine, value)

    for address in fixtures:
        fixtures[address] = fixture

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
                            h.call(0x1464c4ba0, context, data, budget=200000)
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
                            cases.append(dict(count=count, row_found=row_found, policy_raw50=policy_raw50,
                                state=source_state, selector=selector, flag=flag, launched=launches[:]))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)), evidence=evidence,
        fragments=h.fragments, leaves=h.leaves, cases=cases, native_execution=True, network_used=False,
        limits=['Whole notify apply, native map copy/hash link, no-removal pruning, bootstrap, builder, advance and early gate execute.',
                'Table lookup and group descriptor are fixtures: policy row+0x50 is 0/1, group+8 is 2, selector is 0/1.',
                'Map/status slot allocation, temporary cleanup, security-cookie helper and task launch are explicit bounded fixtures.',
                'Fresh unique snapshots only: no duplicate map replacement, hash growth, missing-key prune, existing local tasks or completion gate branch.',
                'This does not bind native row fields to CSV columns or establish live active UI / readiness.'])
    path = h.audit.save_snapshot(h.native.ROOT / 'code-clues/release-tutorial-startup-replay', report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), cases=len(report['cases']))))
