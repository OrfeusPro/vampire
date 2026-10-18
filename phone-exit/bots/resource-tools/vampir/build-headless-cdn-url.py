"""Execute the CDN URL assembly tail using explicit ASCII fragments, no HTTP."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('cdn_url_settings', HERE / 'build-headless-sdk-settings.py')
settings = importlib.util.module_from_spec(spec)
spec.loader.exec_module(settings)
START, STOP = 0x14563f758, 0x14563f9d8
CONCAT, APPEND = 0x145630d40, 0x1445d8310
MALLOC, FREE, COPY, MOVE = 0x1468e4100, 0x14142c480, 0x1487a2e19, 0x1487a2e1f


def replay(raw, image, fragments, base, platform, prefix, version_fragment, filename='config.json', spare=False):
    ping, x = settings.ping, settings.ping.x
    uc = ping.unicorn.Uc(ping.unicorn.UC_ARCH_X86, ping.unicorn.UC_MODE_64)
    scratch, rbp, stack = 0x20000000, 0x20010000, 0x20030000
    uc.mem_map(scratch, 0x80000)
    helper_roots = {image.roots[image.containing(a)][0] for a in (CONCAT, APPEND)}
    allowed = [(image.pe.base + f['begin_rva'], image.pe.base + f['end_rva'])
               for f in fragments if f['root_begin_rva'] in helper_roots] + [(START, STOP)]
    pages = {a & ~4095 for lo, hi in allowed for a in range(lo, hi + 4095, 4096)}
    pages.update(a & ~4095 for a in (MALLOC, FREE, COPY, MOVE))
    for f in fragments:
        for row in f['instructions']:
            if START <= row['address'] < STOP:
                pages.update(a & ~4095 for a in row['rip_references'])
    for page in sorted(pages):
        uc.mem_map(page, 4096)
        off = image.offset(page - image.pe.base)
        uc.mem_write(page, raw[off:off + 4096])
    cursor, allocations, calls = [scratch + 0x40000], {}, []

    def allocate(size):
        if not 0 < size <= 4096:
            raise ValueError('Native allocation exceeds fixture budget')
        pointer = cursor[0]
        cursor[0] += (size + 31) & ~31
        if cursor[0] >= scratch + 0x70000:
            raise ValueError('Native heap fixture exhausted')
        allocations[pointer] = size
        return pointer

    def put(address, value):
        data = value.encode('ascii')
        if len(data) > 512 or b'\0' in data:
            raise ValueError('ASCII fragment fixture exceeds budget')
        if len(data) <= 15 and not spare:
            uc.mem_write(address, (data + b'\0').ljust(16, b'\0') + struct.pack('<QQ', len(data), 15))
        else:
            capacity = max(1024 if spare else 16, len(data))
            pointer = allocate(capacity + 1)
            uc.mem_write(pointer, data + b'\0')
            uc.mem_write(address, struct.pack('<QQQQ', pointer, 0, len(data), capacity))

    def hook(machine, address, size, user):
        if any(lo <= address < hi for lo, hi in allowed):
            return
        rcx, rdx, r8 = [machine.reg_read(reg) for reg in [x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8]]
        if address == MALLOC:
            result = allocate(rcx)
            calls.append(dict(kind='allocate', size=rcx))
        elif address == FREE:
            if rcx not in allocations:
                raise ValueError('Free outside owned fixture allocation')
            del allocations[rcx]
            result = 0
            calls.append(dict(kind='free'))
        elif address in (COPY, MOVE):
            if r8 > 4096:
                raise ValueError('Copy exceeds fixture bound')
            for pointer in (rcx, rdx):
                if scratch <= pointer <= scratch + 0x80000 - r8:
                    continue
                if address != COPY or pointer != rdx or r8 > 2:
                    raise ValueError('Copy outside scratch/static separator')
                off = image.offset(pointer - image.pe.base)
                if raw[off:off + r8] not in (b'/', b'/\0'):
                    raise ValueError('Unexpected static copy')
            if r8:
                machine.mem_write(rcx, bytes(machine.mem_read(rdx, r8)))
            result = rcx
            calls.append(dict(kind='memmove' if address == MOVE else 'memcpy', size=r8))
        else:
            raise ValueError('Unreviewed URL execution ' + hex(address))
        rsp = machine.reg_read(x.UC_X86_REG_RSP)
        ret = struct.unpack('<Q', bytes(machine.mem_read(rsp, 8)))[0]
        machine.reg_write(x.UC_X86_REG_RAX, result)
        machine.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        machine.reg_write(x.UC_X86_REG_RIP, ret)

    uc.hook_add(ping.unicorn.UC_HOOK_CODE, hook)
    for offset, value in [(0xc0, base), (0xe0, platform), (0x100, prefix), (0x120, filename), (-8, version_fragment)]:
        put(rbp + offset, value)
    for register, value in [(x.UC_X86_REG_RBP, rbp), (x.UC_X86_REG_RSP, stack), (x.UC_X86_REG_R12, 0)]:
        uc.reg_write(register, value)
    uc.emu_start(START, STOP, count=16384)
    if uc.reg_read(x.UC_X86_REG_RIP) != STOP:
        raise ValueError('URL assembly instruction budget exceeded')
    output = rbp - 0x28
    length, capacity = struct.unpack('<QQ', bytes(uc.mem_read(output + 16, 16)))
    pointer = struct.unpack('<Q', bytes(uc.mem_read(output, 8)))[0] if capacity > 15 else output
    if length > 4096 or not scratch <= pointer <= scratch + 0x80000 - length - 1:
        raise ValueError('Invalid URL output fixture')
    data = bytes(uc.mem_read(pointer, length + 1))
    if data[-1:] != b'\0':
        raise ValueError('Missing std::string terminator')
    return dict(base=base, platform=platform, prefix=prefix, version_fragment=version_fragment,
                filename=filename, spare_capacity=spare, result=data[:-1].decode('ascii'), calls=calls,
                acquisition_proven=False)


def build():
    prior_path = settings.config.native.ROOT / 'code-clues/headless-cdn-selection.json'
    prior = json.loads(prior_path.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('EXE changed')
    image = settings.config.native.Image(raw)
    roots = {image.roots[image.containing(a)] for a in [0x14563f080, CONCAT, APPEND, 0x1445daf80]}
    fragments = settings.config.native.decode_ranges(image, roots)
    filename_pointer_address = 0x14b149ba0
    offset = image.offset(filename_pointer_address - image.pe.base)
    pointer = struct.unpack_from('<Q', raw, offset)[0]
    filename = settings.config.read_literal(raw, image, pointer)
    if not filename or filename['text'] != 'config.json':
        raise ValueError('Filename source changed')
    cases = []
    inputs = [('https://cdn.invalid/', 'window', 'real', '1_2_3'),
              ('https://cdn.invalid', 'window', 'dev', '1_2_3'),
              ('', '', '', ''), ('b/', '/p', '/real/', '/v/'),
              ('https://cdn.invalid/a?x=1', 'android', 'real', '5.2.11'),
              ('b', 'ios', 'REAL', 'v'), ('b/', 'window', 'unreal', 'a_b'),
              ('https://cdn.invalid/' + 'a' * 90, 'window', 'r' * 50, '1' * 32)]
    for values in inputs:
        for spare in (False, True):
            case = replay(raw, image, fragments, *values, spare=spare)
            expected = values[0] + values[1] + '/' + values[2] + '/' + values[3] + '/config.json'
            if case['result'] != expected:
                raise ValueError('Native URL tail differs')
            cases.append(case)
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                selection_report_sha256=hashlib.sha256(prior_path.read_bytes()).hexdigest(),
                fragments=fragments, filename=filename,
                filename_pointer=dict(address=filename_pointer_address, file_offset=offset,
                                      bytes=raw[offset:offset + 8].hex()), cases=cases, network_ready=False,
                limitations=['URL tail, native concat/growth/append executed; external allocator/free/memcpy/memmove bounded shims.',
                    'Explicit ASCII fragments; platform/prefix/base/version preprocessing and acquisition not executed.',
                    'String concatenation preserves separators and query text, not valid/normalized URL proof.',
                    'Whole Initialize, HTTP callback ordering and real service addresses remain unproven.'])


if __name__ == '__main__':
    report = build()
    target = settings.config.native.ROOT / 'code-clues/headless-cdn-url.json'
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                          native_cases=len(report['cases'])), indent=2))
