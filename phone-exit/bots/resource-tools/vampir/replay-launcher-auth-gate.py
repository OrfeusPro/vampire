"""Source-bound launcher auth gate; synthetic context, no real launch arguments."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('launcher_ping', HERE / 'build-headless-ping-codec.py')
ping = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ping)
ROOT = ping.native.ROOT
BASE = 0x140000000
GATE = 0x1444eb1c0
ROOTS = (0x1444fd270, 0x1444e8130, 0x1444dd8a0, GATE)
GHIDRA_EXPORT = 'export-c7552efd2125/run-2af5fa68a59a'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_bytes(raw, item):
    content = bytes.fromhex(item['bytes'])
    offset = item['file_offset']
    if raw[offset:offset + len(content)] != content:
        raise ValueError('Launcher evidence source bytes changed')


def run_gate(rows, compare, fixture):
    uc, x = ping.unicorn.Uc(ping.unicorn.UC_ARCH_X86, ping.unicorn.UC_MODE_64), ping.x
    scratch, stack, stop = 0x20000000, 0x20020000, 0x2003f000
    uc.mem_map(scratch, 0x40000)
    leaf = compare['compare_leaf']
    cs = ping.native.capstone.Cs(ping.native.capstone.CS_ARCH_X86, ping.native.capstone.CS_MODE_64)
    allowed = {r['address'] for r in rows}
    allowed.update(i.address for i in cs.disasm(bytes.fromhex(leaf['bytes']), leaf['address']))
    pages = {a & ~4095 for a in allowed | {0x144520a60, 0x14147d580, 0x14b4f1020, 0x14b4f13fd}}
    pages.update(a & ~4095 for r in rows for a in r['rip_references'])
    for item in compare.values():
        pages.update(range(item['address'] & ~4095,
                           (item['address'] + len(bytes.fromhex(item['bytes'])) + 4095) & ~4095, 4096))
    for page in sorted(pages):
        uc.mem_map(page, 4096)
    for r in rows:
        uc.mem_write(r['address'], bytes.fromhex(r['bytes']))
    for item in compare.values():
        uc.mem_write(item['address'], bytes.fromhex(item['bytes']))
    cursor = scratch + 0x1000

    def string(address, value):
        nonlocal cursor
        payload = (value + '\0').encode('utf-16le')
        uc.mem_write(cursor, payload)
        uc.mem_write(address, struct.pack('<QII', cursor, len(payload) // 2, len(payload) // 2))
        cursor += (len(payload) + 15) & ~15

    # The comparison global is explicit: its initializer is not executed here.
    string(0x14b4f1020, 'nmlauncher')
    uc.mem_write(0x14b4f13fd, bytes([fixture['prior_flag']]))
    events = []

    def hook(machine, address, size, user):
        if address in allowed:
            return
        if address == 0x144520a60:
            string(machine.reg_read(x.UC_X86_REG_RCX), fixture['auth_type'])
            string(machine.reg_read(x.UC_X86_REG_RDX), 'token-fixture' if fixture['context_ok'] else '')
            machine.reg_write(x.UC_X86_REG_RAX, int(fixture['context_ok']))
            events.append('auth_context_fixture')
        elif address == 0x14147d580:
            events.append('free_fixture')
        else:
            raise ValueError('Unreviewed launcher gate target ' + hex(address))
        rsp = machine.reg_read(x.UC_X86_REG_RSP)
        target = struct.unpack('<Q', bytes(machine.mem_read(rsp, 8)))[0]
        machine.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        machine.reg_write(x.UC_X86_REG_RIP, target)

    uc.hook_add(ping.unicorn.UC_HOOK_CODE, hook)
    uc.mem_write(stack, struct.pack('<Q', stop))
    uc.reg_write(x.UC_X86_REG_RSP, stack)
    uc.emu_start(GATE, stop, count=2048)
    if uc.reg_read(x.UC_X86_REG_RIP) != stop:
        raise ValueError('Launcher gate instruction budget exceeded')
    return dict(fixture=fixture, accepted=bool(uc.reg_read(x.UC_X86_REG_RAX) & 255),
                flag_after=uc.mem_read(0x14b4f13fd, 1)[0], events=events)


def build():
    auth_path = ROOT / 'code-clues/headless-auth-index.json'
    prior = json.loads(auth_path.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('Launcher client source changed')
    fragments = [f for f in prior['fragments'] if f['root_begin_rva'] + BASE in ROOTS]
    if {f['root_begin_rva'] + BASE for f in fragments} != set(ROOTS):
        raise ValueError('Incomplete launcher source roots')
    for fragment in fragments:
        for row in fragment['instructions']:
            validate_bytes(raw, row)
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    literals = [v for v in prior['referenced_constants'] if v['instruction']['address'] in rows]
    for literal in literals:
        validate_bytes(raw, literal)
    image = ping.native.Image(raw)
    vtable_address = 0x1494d61d8
    vtable_offset = image.offset(vtable_address - BASE)
    vtable_bytes = raw[vtable_offset:vtable_offset + 24]
    vtable = dict(address=vtable_address, file_offset=vtable_offset, bytes=vtable_bytes.hex(),
                  sha256=hashlib.sha256(vtable_bytes).hexdigest(),
                  slots=[hex(v) for v in struct.unpack('<QQQ', vtable_bytes)])
    if vtable['slots'][1] != '0x1444e6570':
        raise ValueError('Launcher credential GetObject target changed')
    compare_path = ROOT / 'code-clues/nid-result-primitives.json'
    primitives = json.loads(compare_path.read_text('utf-8'))
    compare = {k: primitives['evidence'][k] for k in ('compare_leaf', 'compare_table')}
    for item in compare.values():
        validate_bytes(raw, item)
    gate_rows = [r for f in fragments if f['root_begin_rva'] + BASE == GATE for r in f['instructions']]
    cases = [run_gate(gate_rows, compare, dict(auth_type=kind, context_ok=ok, prior_flag=flag))
             for kind, ok in (('nmlauncher', True), ('NMLAUNCHER', True), ('netmarble', True),
                              ('other-fixture', True), ('', False)) for flag in (0, 1)]
    output = ROOT / 'ghidra' / GHIDRA_EXPORT
    report_path = output / 'functions.json'
    provenance = json.loads((output / 'provenance.json').read_text('utf-8'))
    if digest(report_path) != provenance['files']['functions.json']:
        raise ValueError('Launcher Ghidra report hash changed')
    report = json.loads(report_path.read_text('utf-8'))
    if report['source_sha256'] != prior['sha256']:
        raise ValueError('Launcher Ghidra source mismatch')
    functions = [f for f in report['functions'] if int(f['address'], 16) in ROOTS]
    if len(functions) != 4 or not all(f['completed'] for f in functions):
        raise ValueError('Incomplete launcher Ghidra export')
    if any(digest(output / f['pseudocode_file']) != provenance['files'][f['pseudocode_file']] for f in functions):
        raise ValueError('Launcher Ghidra pseudocode hash changed')
    return dict(source=prior['source'], source_sha256=prior['sha256'], tool_sha256=digest(Path(__file__)),
                auth_report_sha256=digest(auth_path), compare_report_sha256=digest(compare_path),
                ghidra_output=str(output), ghidra_report_sha256=digest(report_path),
                pseudocode_sha256={f['name']: digest(output / f['pseudocode_file']) for f in functions},
                fragments=fragments, literals=literals, credential_vtable=vtable, compare=compare, cases=cases,
                native_execution='IsRunningOnLauncher only', network_used=False,
                limitations=['Auth-context getter, global comparison string and free are fixtures; logs disabled.',
                             'Actual ASCII compare executes; initializer of nmlauncher global is not executed.',
                             'Credential construction and HTTP callers are static evidence, not executed.',
                             'No real command line, token, account storage or live game session read.',
                             'No proof that launcher authorization is required for game Login.'])


if __name__ == '__main__':
    report = build()
    path = ROOT / 'code-clues/launcher-auth-gate-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=digest(path), cases=len(report['cases']))))
