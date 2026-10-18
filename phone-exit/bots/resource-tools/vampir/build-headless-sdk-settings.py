"""Source-bound SDK settings registration/defaults; no active profile/config IO."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


config = load('settings_config', HERE / 'build-headless-sdk-config.py')
ping = load('settings_unicorn', HERE / 'build-headless-ping-codec.py')
START, STOP = 0x1444ac9f0, 0x1444aca99
BASE, STRING = 0x1417c5f20, 0x141421150
FIELDS = {'Market': (0x28, 0x1494c5178), 'GameCode': (0x38, 0x1494c51b0),
          'BuildCode': (0x48, 0x1494c5230), 'SDKZone': (0x49, 0x1494c52b0),
          'SDKType': (0x50, 0x1494c52f0), 'WindowsEmailClientId': (0x68, 0x1494c5370),
          'AndroidEmailClientId': (0x78, 0x1494c53a8), 'IosEmailClientId': (0x88, 0x1494c53e0),
          'NetmarbleClientId': (0x98, 0x1494c5418)}


def utf16(raw, image, address):
    offset = image.offset(address - image.pe.base)
    data = raw[offset:offset + 258]
    end = next((i for i in range(0, len(data) - 1, 2) if data[i:i + 2] == b'\0\0'), None)
    if end is None:
        raise ValueError('Unbounded constructor string')
    return data[:end].decode('utf-16le')


def replay(raw, image, poison):
    if ping.unicorn.__version__ != '2.1.4' or config.native.capstone.__version__ != '5.0.6':
        raise ValueError('Use pinned native analysis dependencies')
    uc = ping.unicorn.Uc(ping.unicorn.UC_ARCH_X86, ping.unicorn.UC_MODE_64)
    x = ping.x
    scratch, obj, stack = 0x20000000, 0x20001000, 0x20030000
    uc.mem_map(scratch, 0x40000)
    uc.mem_write(obj, bytes([poison]) * 0x228)
    for page in sorted({v & ~4095 for v in [START, STOP, BASE, STRING]}):
        uc.mem_map(page, 4096)
        off = image.offset(page - image.pe.base)
        uc.mem_write(page, raw[off:off + 4096])
        uc.mem_protect(page, 4096, ping.unicorn.UC_PROT_READ | ping.unicorn.UC_PROT_EXEC)
    strings, base_calls = {}, []
    permitted = {off for name, (off, _) in FIELDS.items() if name not in ('BuildCode', 'SDKZone')}

    def hook(machine, address, size, user):
        if START <= address < STOP:
            return
        if address not in (BASE, STRING):
            raise ValueError('Unreviewed constructor target')
        rcx = machine.reg_read(x.UC_X86_REG_RCX)
        if address == BASE:
            if rcx != obj:
                raise ValueError('Unexpected base object')
            base_calls.append(address)
        else:
            field = rcx - obj
            if field not in permitted or field in strings:
                raise ValueError('Unexpected string destination')
            text = utf16(raw, image, machine.reg_read(x.UC_X86_REG_RDX))
            strings[field] = text
            pointer = scratch + 0x10000 + field * 64
            data = text.encode('utf-16le') + b'\0\0'
            machine.mem_write(pointer, data)
            machine.mem_write(rcx, struct.pack('<QII', pointer, len(data) // 2, len(data) // 2))
            machine.reg_write(x.UC_X86_REG_RAX, rcx)
        rsp = machine.reg_read(x.UC_X86_REG_RSP)
        target = struct.unpack('<Q', bytes(machine.mem_read(rsp, 8)))[0]
        machine.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        machine.reg_write(x.UC_X86_REG_RIP, target)

    uc.hook_add(ping.unicorn.UC_HOOK_CODE, hook)
    uc.reg_write(x.UC_X86_REG_RCX, obj)
    uc.reg_write(x.UC_X86_REG_RSP, stack)
    uc.emu_start(START, STOP, count=512)
    if uc.reg_read(x.UC_X86_REG_RIP) != STOP or len(base_calls) != 1 or set(strings) != permitted:
        raise ValueError('Constructor slice incomplete')
    values = {name: (uc.mem_read(obj + offset, 1)[0] if name in ('BuildCode', 'SDKZone') else strings[offset])
              for name, (offset, _) in FIELDS.items()}
    return dict(poison=poison, values=values, base_calls=base_calls, string_calls=len(strings),
                slice_start=START, slice_stop=STOP, active_settings_proven=False)


def replay_game_override(raw, image, environment, globals_text):
    """Actual copy/compare/zone-write slice; environment conversion is a fixture."""
    uc = ping.unicorn.Uc(ping.unicorn.UC_ARCH_X86, ping.unicorn.UC_MODE_64)
    x = ping.x
    scratch, obj, stack = 0x20000000, 0x20001000, 0x20030000
    start, stop, compare = 0x14561a9cd, 0x14561ab3b, 0x141459730
    shims = {0x1414313d0, 0x1487a2e19, 0x14563d960, 0x141433970, 0x14147d580}
    uc.mem_map(scratch, 0x40000)
    table = 0x14145973a + 0x7543dc6
    pages = {a & ~4095 for a in [start, stop, compare, table, *shims, *globals_text]}
    for page in sorted(pages):
        uc.mem_map(page, 4096)
        try:
            offset = image.offset(page - image.pe.base)
        except ValueError:
            continue  # Only explicitly initialized synthetic .bss globals below.
        uc.mem_write(page, raw[offset:offset + 4096])
    for index, (address, text) in enumerate(globals_text.items()):
        pointer = scratch + 0x18000 + index * 256
        data = text.encode('utf-16le') + b'\0\0'
        uc.mem_write(pointer, data)
        uc.mem_write(address, struct.pack('<QII', pointer, len(data) // 2, len(data) // 2))
    for index, field in enumerate([0x28, 0x38, 0x98]):
        uc.mem_write(obj + field, struct.pack('<QII', scratch + 0x20000 + index * 256, 1, 128))
    uc.mem_write(obj + 0x49, b'\xff')
    real_address = 0x14561ab08 + 0x3ff01dc
    real_page = real_address & ~4095
    if real_page not in pages:
        uc.mem_map(real_page, 4096)
        off = image.offset(real_page - image.pe.base)
        uc.mem_write(real_page, raw[off:off + 4096])
    calls = []

    def hook(machine, address, size, user):
        if start <= address < stop or compare <= address < 0x14145977b:
            return
        if address not in shims:
            raise ValueError('Unreviewed game settings target')
        calls.append(address)
        rcx, rdx, r8 = [machine.reg_read(reg) for reg in
                        [x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8]]
        if address == 0x1414313d0:
            if rcx - obj not in (0x28, 0x38, 0x98) or not 0 < rdx <= 128:
                raise ValueError('Unbounded FString growth fixture')
            machine.mem_write(rcx + 12, struct.pack('<I', 128))
        elif address == 0x1487a2e19:
            if r8 > 256 or not all(scratch <= a <= scratch + 0x40000 - r8 for a in (rcx, rdx)):
                raise ValueError('Copy outside scratch')
            machine.mem_write(rcx, bytes(machine.mem_read(rdx, r8)))
            machine.reg_write(x.UC_X86_REG_RAX, rcx)
        elif address == 0x14563d960:
            machine.reg_write(x.UC_X86_REG_RAX, scratch + 0x5000)
        elif address == 0x141433970:
            if rcx != scratch + 0x5048 or not stack <= rdx < stack + 0x100:
                raise ValueError('Unexpected environment source')
            data = environment.encode('utf-16le') + b'\0\0'
            if len(data) > 256:
                raise ValueError('Environment fixture too large')
            machine.mem_write(scratch + 0x24000, data)
            machine.mem_write(rdx, struct.pack('<QII', scratch + 0x24000, len(data) // 2, len(data) // 2))
            machine.reg_write(x.UC_X86_REG_RAX, rdx)
        elif address == 0x14147d580 and not scratch <= rcx < scratch + 0x40000:
            raise ValueError('Free outside scratch fixture')
        rsp = machine.reg_read(x.UC_X86_REG_RSP)
        target = struct.unpack('<Q', bytes(machine.mem_read(rsp, 8)))[0]
        machine.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        machine.reg_write(x.UC_X86_REG_RIP, target)

    uc.hook_add(ping.unicorn.UC_HOOK_CODE, hook)
    for reg, value in [(x.UC_X86_REG_RDI, obj), (x.UC_X86_REG_RSI, 0), (x.UC_X86_REG_RSP, stack)]:
        uc.reg_write(reg, value)
    uc.emu_start(start, stop, count=2048)
    if uc.reg_read(x.UC_X86_REG_RIP) != stop:
        raise ValueError('Game initialization slice incomplete')
    values = {}
    for name in ['Market', 'GameCode', 'NetmarbleClientId']:
        offset = FIELDS[name][0]
        pointer, count, _ = struct.unpack('<QII', bytes(uc.mem_read(obj + offset, 16)))
        if not 1 <= count <= 128 or not scratch <= pointer < scratch + 0x40000 - count * 2:
            raise ValueError('Invalid copied FString')
        values[name] = bytes(uc.mem_read(pointer, (count - 1) * 2)).decode('utf-16le')
    values['SDKZone'] = uc.mem_read(obj + 0x49, 1)[0]
    return dict(environment_fixture=environment, values=values, shim_calls=calls,
                slice_start=start, slice_stop=stop, active_settings_proven=False)


def build():
    baseline_path = config.native.ROOT / 'code-clues/headless-sdk-config.json'
    baseline = json.loads(baseline_path.read_text('utf-8'))
    raw = Path(baseline['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != baseline['sha256']:
        raise ValueError('EXE changed')
    image = config.native.Image(raw)
    roots = {image.roots[image.containing(va)] for va in [START, 0x1444ab740, 0x1444ab7f0, 0x144529670,
             0x144536220, 0x14561a930, 0x141258ab0, 0x141258ae0, 0x141258b10, 0x145631210]}
    fragments = config.native.decode_ranges(image, roots)
    rows = {i['address']: i for f in fragments for i in f['instructions']}
    if rows[0x1444aca3d]['operands'] != 'word ptr [rbx + 0x48], 0x100':
        raise ValueError('Default byte-pair write changed')
    if rows[0x1444ab800]['rip_references'] != [0x1494c5e60]:
        raise ValueError('Settings registration anchor changed')
    descriptors = []
    for name, (offset, address) in FIELDS.items():
        off = image.offset(address - image.pe.base)
        data = raw[off:off + 56]
        literal = config.read_literal(raw, image, struct.unpack_from('<Q', data)[0])
        if not literal or literal['text'] != name or struct.unpack_from('<I', data, 0x30)[0] != (offset << 16) | 1:
            raise ValueError('Property descriptor anchor changed')
        pointers = [i for i in range(47) if struct.unpack_from('<Q', raw,
                    image.offset(0x1494c5cd0 + i * 8 - image.pe.base))[0] == address]
        if len(pointers) != 1:
            raise ValueError('Property array membership changed')
        descriptors.append(dict(name=name, offset=offset, address=address, file_offset=off,
                                bytes=data.hex(), sha256=hashlib.sha256(data).hexdigest(),
                                name_literal=literal, pointer_array_slot=pointers[0]))
    anchors = []
    for address, length in [(0x1444ac680, 20), (0x1494c5cd0, 47 * 8), (0x1494c5e60, 64),
                            (0x141459730, 75), (0x14899d500, 128), (0x14563d960, 8)]:
        offset = image.offset(address - image.pe.base)
        data = raw[offset:offset + length]
        anchors.append(dict(address=address, file_offset=offset, bytes=data.hex(), sha256=hashlib.sha256(data).hexdigest()))
    literals = []
    for row in rows.values():
        for address in row['rip_references']:
            literal = config.read_literal(raw, image, address)
            if literal:
                literals.append(dict(instruction=row['address'], **literal))
    cases = [replay(raw, image, poison) for poison in [0, 0x55, 0xaa, 0xff]]
    if any(case['values'] != cases[0]['values'] for case in cases):
        raise ValueError('Default initialization depends on fixture bytes')
    globals_text = {}
    for initializer, source_lea, destination_lea in [(0x141258ab0, 0x141258ab4, 0x141258abb),
            (0x141258ae0, 0x141258ae4, 0x141258aeb), (0x141258b10, 0x141258b14, 0x141258b1b)]:
        globals_text[rows[destination_lea]['rip_references'][0]] = utf16(raw, image, rows[source_lea]['rip_references'][0])
    environments = ['real', 'REAL', 'Real', 'rEaL', '', 'dev', 'alpha', 'dr', 'production', 'real ', ' real', 'reals', 'réal']
    game_cases = [replay_game_override(raw, image, value, globals_text) for value in environments]
    if any(case['values']['SDKZone'] != (2 if case['environment_fixture'].lower() == 'real' else 1) for case in game_cases):
        raise ValueError('Native game environment selection differs')
    return dict(schema_version=1, source=baseline['source'], sha256=baseline['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                baseline_sha256=hashlib.sha256(baseline_path.read_bytes()).hexdigest(),
                fragments=fragments, descriptors=descriptors, anchors=anchors, literals=literals, cases=cases,
                game_globals=globals_text, game_cases=game_cases,
                network_ready=False, active_settings_proven=False,
                limitations=['Native constructor prefix only; base UObject and FString constructor are shims.',
                    'Stops before remaining UI/default initialization; no CDO lifecycle or config loading executed.',
                    'Descriptor packed words corroborate offsets; property flags are preserved, not interpreted.',
                    'Class registration/config name and service logging are static evidence, not active overrides.',
                    'Game copy and actual mixed UTF16/ASCII comparison executed; environment conversion/singleton/growth/copy/free are shims.',
                    'Compiled game initializers bind globals, but later mutations and active environment source remain unproven.',
                    'No account files, live process, credentials, configuration response or network used.'])


if __name__ == '__main__':
    report = build()
    target = config.native.ROOT / 'code-clues/headless-sdk-settings.json'
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                          native_cases=len(report['cases']), descriptors=len(report['descriptors']),
                          defaults=report['cases'][0]['values']), indent=2))
