"""Source-bound GMC2 configuration loading graph; no requests or profile data."""
import hashlib
import importlib.util
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('config_native', HERE/'build-native-entry-code.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)

SELECTORS = [
    'Netmarble::Service::FGMC2ManagerImpl::FGMC2ManagerImpl(',
    'Netmarble::Service::FGMC2ManagerImpl::Start(',
    'Netmarble::Service::FGMC2ManagerImpl::RefreshSDKConstants(',
    'Netmarble::Service::FGMC2ManagerImpl::RequestGMC2(',
    'Netmarble::Service::FGMC2ManagerImpl::OnCompleteRequestGMC2(',
    'Netmarble::Service::FGMC2ManagerImpl::ParseConstantsTemplateGroups(',
    'Netmarble::Service::FGMC2ManagerImpl::DecryptXOR(',
]


def read_literal(raw, image, address):
    try:
        off = image.offset(address-image.pe.base)
    except ValueError:
        return None
    data = raw[off:off+2048]
    encoding = 'utf-16le' if data[1:2] == b'\0' else 'ascii'
    if encoding == 'utf-16le':
        end = next((i for i in range(0, len(data)-1, 2) if data[i:i+2] == b'\0\0'), -1)
    else:
        end = data.find(b'\0')
    if end < 2:
        return None
    try:
        text = data[:end].decode(encoding)
    except UnicodeDecodeError:
        return None
    if len(text) > 600 or not all(c.isprintable() for c in text):
        return None
    content = data[:end+(2 if encoding == 'utf-16le' else 1)]
    return dict(address=address, file_offset=off, encoding=encoding, text=text,
                bytes=content.hex(), sha256=hashlib.sha256(content).hexdigest())


def replay_mode_selection(raw, image, fragments):
    """Execute the actual Start mode branch; runtime settings are explicit inputs."""
    spec = importlib.util.spec_from_file_location('config_ping', HERE/'build-headless-ping-codec.py')
    ping = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ping)
    emulator = ping.PingEmulator()
    from unicorn import x86_const as x
    start, end = 0x144501a11, 0x144501a46
    emulator.ranges.append((start, end))
    page = start & ~4095
    if not any(lo <= page <= hi for lo, hi, _ in emulator.uc.mem_regions()):
        emulator.uc.mem_map(page, 4096)
        off = image.offset(page-image.pe.base)
        emulator.uc.mem_write(page, raw[off:off+4096])
        emulator.uc.mem_protect(page, 4096, ping.unicorn.UC_PROT_READ|ping.unicorn.UC_PROT_EXEC)
    rows = {i['address']: i for f in fragments for i in f['instructions']}
    if rows[start]['operands'] != 'edx, byte ptr [rcx + 0x49]':
        raise ValueError('Mode selection anchor changed')
    uc = emulator.uc
    settings, manager = emulator.scratch+0x1000, emulator.scratch+0x2000
    cases = []
    for mode in range(256):
        uc.mem_write(settings+0x49, bytes([mode]))
        uc.reg_write(x.UC_X86_REG_RCX, settings)
        uc.reg_write(x.UC_X86_REG_RDI, manager)
        uc.emu_start(start, end, count=100)
        if uc.reg_read(x.UC_X86_REG_RIP) != end:
            raise ValueError('Mode selection instruction budget exceeded')
        selected = uc.reg_read(x.UC_X86_REG_RDX)-manager
        expected = {0: 0x150, 1: 0x160, 2: 0x170, 3: 0x180}.get(mode, 0x160)
        if selected != expected:
            raise ValueError('Mode selection result changed')
        cases.append(dict(mode=mode, selected_field_offset=selected))
    return dict(start=start, end=end, cases=cases,
                limitations=['Explicit settings byte, synthetic manager base; no strings, network or runtime defaults executed.'])


def main():
    if native.capstone.__version__ != '5.0.6':
        raise ValueError('Use pinned Capstone')
    meta = json.loads((native.ROOT/'code-clues/headless-auth-index.json').read_text('utf-8'))
    raw = Path(meta['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != meta['sha256']:
        raise ValueError('Client changed')
    image = native.Image(raw)
    symbols = []
    for match in re.finditer(rb'[ -~]{8,}', raw):
        text = match.group().decode('ascii')
        selectors = [key for key in SELECTORS if key in text]
        if not selectors:
            continue
        address = image.pe.address(match.start())
        if address is None or raw[match.end()] != 0:
            raise ValueError('SDK diagnostic not file-backed/terminated')
        row = read_literal(raw, image, address)
        row['selectors'] = selectors
        symbols.append(row)
    targets = {row['address']: row for row in symbols}
    candidates = native.rip_candidates(image, targets)
    roots = {image.roots[f] for address, _ in candidates if (f := image.containing(address)) is not None}
    fragments = native.decode_ranges(image, roots)
    rows = {i['address']: i for f in fragments for i in f['instructions']}
    xrefs, rejected, constants = [], [], []
    for address, target in candidates:
        instruction = rows.get(address)
        if instruction is None or instruction['mnemonic'] != 'lea' or target not in instruction['rip_references']:
            rejected.append(dict(address=address, target=target))
            continue
        xrefs.append(dict(selector=targets[target]['selectors'][0], instruction=instruction,
                          root=image.pe.base+image.roots[image.containing(address)][0]))
    for instruction in rows.values():
        if instruction['mnemonic'] != 'lea':
            continue
        for address in instruction['rip_references']:
            row = read_literal(raw, image, address)
            if row and '__cdecl' not in row['text'] and not row['text'].startswith('.?AV'):
                constants.append(dict(**row, instruction=instruction))
    present = {key for row in symbols for key in row['selectors']}
    selection = replay_mode_selection(raw, image, fragments)
    report = dict(schema_version=1, source=meta['source'], sha256=meta['sha256'],
                  tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  selectors=SELECTORS, symbols=symbols, xrefs=xrefs, rejected_candidates=rejected,
                  fragments=fragments, referenced_constants=constants,
                  mode_selection=selection,
                  missing=[key for key in SELECTORS if key not in present],
                  statistics=dict(symbols=len(symbols), xrefs=len(xrefs), roots=len(roots), constants=len(constants), native_mode_cases=len(selection['cases'])),
                  network_ready=False, limitations=[
                      'Static diagnostic-to-root and literal references, not complete config execution.',
                      'URL candidates do not establish current production mode, region or live availability.',
                      'Encrypted constants response, active template/build values and final auth bases unresolved.',
                      'No network, Saved profiles, launcher/session memory or account data accessed.'])
    path = native.ROOT/'code-clues/headless-sdk-config.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', 'utf-8')
    print(json.dumps(dict(output=str(path), **report['statistics'], missing=report['missing'], rejected=len(rejected))))


if __name__ == '__main__':
    main()
