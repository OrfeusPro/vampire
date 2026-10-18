"""Track CDN JSON -> NetmarbleS/Zone -> SDK environment without network IO."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('cdn_settings', HERE / 'build-headless-sdk-settings.py')
settings = importlib.util.module_from_spec(spec)
spec.loader.exec_module(settings)

ROOTS = [0x145631210, 0x145647da0, 0x14563f080, 0x145642a30, 0x14565a5d0,
         0x14563da10, 0x144aa6f20, 0x1411dca50, 0x145618910, 0x14561a930, 0x1445bc080]


def replay_zone_load(raw, image, zone):
    """Execute lookup argument preparation, branch and field assignment callsite.

    JSON lookup, JSON-to-FString conversion and FString copy are explicitly
    capture shims. This is not native JSON parser or full ReadJson execution.
    """
    ping, x = settings.ping, settings.ping.x
    uc = ping.unicorn.Uc(ping.unicorn.UC_ARCH_X86, ping.unicorn.UC_MODE_64)
    scratch, obj, rbp = 0x20000000, 0x20001000, 0x20010000
    start, stop, missing = 0x14565a753, 0x14565a7c2, 0x14565f540
    string_ctor, lookup, convert, copy, free = 0x141421150, 0x14563da10, 0x1415e48f0, 0x141421d80, 0x14147d580
    uc.mem_map(scratch, 0x40000)
    for page in sorted({a & ~4095 for a in [start, stop, missing, string_ctor, lookup, convert, copy, free]}):
        uc.mem_map(page, 4096)
        off = image.offset(page - image.pe.base)
        uc.mem_write(page, raw[off:off + 4096])
    # LEAs refer to public literals; constructor shim reads them from pinned EXE.
    allocations, lookups, assignments = [], [], []
    sentinel = 'unchanged'
    current = [sentinel]

    def store_text(destination, value):
        pointer = scratch + 0x20000 + len(allocations) * 1024
        data = value.encode('utf-16le') + b'\0\0'
        if len(data) > 512 or len(allocations) > 16 or not scratch <= destination <= scratch + 0x3fff0:
            raise ValueError('FString fixture budget exceeded')
        uc.mem_write(pointer, data)
        uc.mem_write(destination, struct.pack('<QII', pointer, len(data) // 2, len(data) // 2))
        allocations.append(pointer)

    def read_text(address):
        if not scratch <= address <= scratch + 0x3fff0:
            raise ValueError('FString fixture outside scratch')
        pointer, count, _ = struct.unpack('<QII', bytes(uc.mem_read(address, 16)))
        if pointer not in allocations or not 1 <= count <= 256:
            raise ValueError('Invalid FString fixture')
        return bytes(uc.mem_read(pointer, (count - 1) * 2)).decode('utf-16le')

    def hook(machine, address, size, user):
        if address == missing:
            machine.emu_stop()
            return
        if start <= address < stop:
            return
        rcx, rdx, r8, r9 = [machine.reg_read(reg) for reg in
                           [x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9]]
        if address == string_ctor:
            store_text(rcx, settings.utf16(raw, image, rdx))
            machine.reg_write(x.UC_X86_REG_RAX, rcx)
        elif address == lookup:
            if (rcx, rdx) != (obj, scratch + 0x5000):
                raise ValueError('Unexpected lookup context')
            lookups.append(dict(section=read_text(r8), key=read_text(r9)))
            machine.reg_write(x.UC_X86_REG_RAX, scratch + 0x6000 if zone is not None else 0)
        elif address == convert:
            if rcx != scratch + 0x6000:
                raise ValueError('Unexpected JSON fixture')
            store_text(rdx, zone)
            machine.reg_write(x.UC_X86_REG_RAX, rdx)
        elif address == copy:
            if rcx != obj + 0x48:
                raise ValueError('Wrong environment destination')
            current[0] = read_text(rdx)
            store_text(rcx, current[0])
            assignments.append(dict(offset=0x48, value=current[0]))
            machine.reg_write(x.UC_X86_REG_RAX, rcx)
        elif address == free:
            if rcx not in allocations:
                raise ValueError('Free outside fixture allocations')
        else:
            raise ValueError('Unreviewed zone-load target ' + hex(address))
        rsp = machine.reg_read(x.UC_X86_REG_RSP)
        ret = struct.unpack('<Q', bytes(machine.mem_read(rsp, 8)))[0]
        machine.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        machine.reg_write(x.UC_X86_REG_RIP, ret)

    uc.hook_add(ping.unicorn.UC_HOOK_CODE, hook)
    for reg, value in [(x.UC_X86_REG_RBX, obj), (x.UC_X86_REG_R14, scratch + 0x5000),
                       (x.UC_X86_REG_RBP, rbp), (x.UC_X86_REG_RSP, scratch + 0x30000)]:
        uc.reg_write(reg, value)
    uc.emu_start(start, stop, count=512)
    actual_stop = uc.reg_read(x.UC_X86_REG_RIP)
    if actual_stop not in (stop, missing) or lookups != [dict(section='NetmarbleS', key='Zone')]:
        raise ValueError('Unexpected zone load path')
    return dict(zone_fixture=zone, lookups=lookups, assignments=assignments,
                final_value=current[0], missing_branch=actual_stop == missing,
                start=start, stop=actual_stop, parser_executed=False)


def build():
    prior_path = settings.config.native.ROOT / 'code-clues/headless-sdk-settings.json'
    prior = json.loads(prior_path.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('EXE changed')
    image = settings.config.native.Image(raw)
    roots = {image.roots[image.containing(va)] for va in ROOTS}
    fragments = settings.config.native.decode_ranges(image, roots)
    rows = {i['address']: i for f in fragments for i in f['instructions']}
    checks = [(0x14565a788, 0x14563da10), (0x14565a7a0, 0x1415e48f0),
              (0x14565a7ac, 0x141421d80), (0x145643110, 0x14565a5d0),
              (0x14561898d, 0x14561a930)]
    for address, target in checks:
        if rows[address]['direct_target'] != target:
            raise ValueError('Reviewed call anchor changed')
    literals = []
    for row in rows.values():
        for address in row['rip_references']:
            literal = settings.config.read_literal(raw, image, address)
            if literal:
                literals.append(dict(instruction=row['address'], **literal))
    anchors = []
    for address, size in [(0x1498bacd0, 48), (0x14563d960, 8)]:
        offset = image.offset(address - image.pe.base)
        data = raw[offset:offset + size]
        anchors.append(dict(address=address, file_offset=offset, bytes=data.hex(), sha256=hashlib.sha256(data).hexdigest()))
    cases = [replay_zone_load(raw, image, value) for value in [None, '', 'real', 'REAL', 'dev', 'real ', 'réal']]
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                settings_report_sha256=hashlib.sha256(prior_path.read_bytes()).hexdigest(),
                fragments=fragments, literals=literals, anchors=anchors, cases=cases,
                active_environment_proven=False, network_ready=False,
                limitations=['ReadJson zone slice only; JSON lookup/conversion/FString assignment/free are bounded capture shims.',
                    'Missing branch stops before diagnostic/whole-function failure handling.',
                    'Compiled dev default and NetworkSetting keys do not prove current public CDN URLs or loaded values.',
                    'Callback/InitSetting callers are static evidence; full startup ordering remains unproven.',
                    'No requests, account/config profile files or process memory accessed.'])


if __name__ == '__main__':
    report = build()
    target = settings.config.native.ROOT / 'code-clues/headless-cdn-config.json'
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                          native_cases=len(report['cases']), roots=len(ROOTS)), indent=2))
