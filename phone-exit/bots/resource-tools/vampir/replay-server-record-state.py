"""Execute the native saved-server state gate and reset for every byte value."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('state_base', HERE / 'build-headless-ping-codec.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
native, unicorn, x = base.native, base.unicorn, base.x
START, ACCEPT, RESET, END = 0x145d4bcd7, 0x145d4bce7, 0x145d4bd83, 0x145d4bd8e


def build():
    manifest = json.loads((native.ROOT / 'ghidra/entry-manifest.json').read_text('utf-8'))
    raw = Path(manifest['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest['source_sha256']:
        raise ValueError('Client changed')
    image = native.Image(raw)
    decoded = native.decode_ranges(image, {image.roots[image.containing(START)]})
    rows = [r for f in decoded for r in f['instructions']
            if START <= r['address'] < ACCEPT or RESET <= r['address'] < END]
    if {r['address'] for r in rows} != {START, START + 4, START + 7, START + 10, RESET}:
        raise ValueError('Native server state gate changed')
    cases = []
    for state in range(256):
        uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        uc.mem_map(START & ~4095, 4096)
        for row in rows: uc.mem_write(row['address'], bytes.fromhex(row['bytes']))
        uc.mem_map(0x20000000, 4096)
        record, master = 0x20000000, 0x20000400
        uc.mem_write(record + 0x35, bytes([state]))
        uc.mem_write(master + 0x308, struct.pack('<II', 251, 252))
        uc.reg_write(x.UC_X86_REG_RAX, record)
        uc.reg_write(x.UC_X86_REG_RDI, master)
        stops = []
        def hook(machine, address, size, user):
            if address in (ACCEPT, END):
                stops.append(address)
                machine.emu_stop()
            elif address not in {r['address'] for r in rows}:
                raise ValueError('Unexpected native state instruction')
        uc.hook_add(unicorn.UC_HOOK_CODE, hook)
        uc.emu_start(START, END + 1, count=16)
        selected = struct.unpack('<II', bytes(uc.mem_read(master + 0x308, 8)))
        excluded = state in (2, 3)
        if stops != [END if excluded else ACCEPT] or selected != ((0, 0) if excluded else (251, 252)):
            raise ValueError('Native state gate differs from independent model')
        cases.append(dict(state=state, excluded=excluded, selected_ids=selected))
    return dict(source=manifest['source'], source_sha256=manifest['source_sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                instructions=rows, cases=cases,
                limitations=['Actual byte arithmetic, branch and two-ID reset execute; record/master are fixtures.',
                             'Starts after successful record lookup; full Update and account policy excluded.',
                             'States 2/3 are excluded; other values do not prove entry or creation availability.',
                             'No game, network, credentials or process memory.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/server-record-state-replay.json'
    path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
