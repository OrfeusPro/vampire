"""Execute the compiled default GUID formatting branch on synthetic uint32 words."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('device_guid_source', HERE / 'build-headless-device-identity.py')
source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source)
import unicorn
from unicorn import x86_const as x


def capture(raw, image, report, words):
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    allowed = set()
    pages = set()
    for fragment in report['fragments']:
        if fragment['root_begin_rva'] != 0x15ad580:
            continue
        for row in fragment['instructions']:
            allowed.add(row['address'])
            pages.add(row['address'] & ~4095)
    for span in report['spans'][1:]:
        allowed.update(i['address'] for i in span['instructions'])
        pages.update(i['address'] & ~4095 for i in span['instructions'])
    # Stack cookie is fixture data; security-check call is a no-op capture.
    pages.update((0x14b2004c0 & ~4095, 0x148796040 & ~4095))
    for page in sorted(pages):
        uc.mem_map(page, 4096)
        offset = image.offset(page - image.pe.base)
        uc.mem_write(page, raw[offset:offset + 4096])
    scratch = 0x20000000
    uc.mem_map(scratch, 0x20000)
    guid, desc, text, stack, stop = (scratch + n for n in (0x1000, 0x2000, 0x3000, 0x10000, 0x1f000))
    uc.mem_write(guid, struct.pack('<IIII', *words))
    # Empty FString with sufficient capacity avoids allocator fixture calls.
    uc.mem_write(desc, struct.pack('<QII', text, 0, 64))
    uc.mem_write(stack, struct.pack('<Q', stop))
    for register, value in ((x.UC_X86_REG_RCX, guid), (x.UC_X86_REG_RDX, desc),
                            (x.UC_X86_REG_R8, 0), (x.UC_X86_REG_RSP, stack)):
        uc.reg_write(register, value)
    captures = []

    def hook(uc, address, size, user):
        if address in allowed:
            return
        if address != 0x148796040:
            raise ValueError('Unexpected GUID format execution at ' + hex(address))
        captures.append('security_cookie_check_not_executed')
        rsp = uc.reg_read(x.UC_X86_REG_RSP)
        target = struct.unpack('<Q', bytes(uc.mem_read(rsp, 8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(x.UC_X86_REG_RIP, target)

    uc.hook_add(unicorn.UC_HOOK_CODE, hook)
    uc.emu_start(0x141548fd0, stop, count=4096)
    if uc.reg_read(x.UC_X86_REG_RIP) != stop:
        raise ValueError('GUID formatter instruction budget exceeded')
    pointer, count, capacity = struct.unpack('<QII', bytes(uc.mem_read(desc, 16)))
    if not 1 <= count <= capacity <= 64:
        raise ValueError('GUID formatter FString bound')
    value = bytes(uc.mem_read(pointer, count * 2)).decode('utf-16le')
    if not value.endswith('\0'):
        raise ValueError('GUID formatter missing terminator')
    return dict(words=list(words), formatted=value[:-1], count=count, captures=captures)


def build():
    report_path = source.config.native.ROOT / 'code-clues/headless-device-identity.json'
    report = json.loads(report_path.read_text('utf-8'))
    raw = Path(report['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != report['sha256']:
        raise ValueError('GUID formatter source changed')
    image = source.config.native.Image(raw)
    fixtures = [(0, 0, 0, 0), (0xffffffff,) * 4,
                (0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210)]
    cases = [capture(raw, image, report, words) for words in fixtures]
    return dict(schema_version=1, source=report['source'], sha256=report['sha256'],
                evidence_sha256=hashlib.sha256(report_path.read_bytes()).hexdigest(),
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), cases=cases,
                native_execution=True, user_identity_read=False, limitations=[
                    'Only default format=0 GUID branch and native hex writer executed, using synthetic words.',
                    'FString destination capacity and stack cookie are fixtures; security check captured.',
                    'CoCreateGuid, registry, GUID parsing and SDK device getter branches not executed.'])


if __name__ == '__main__':
    report = build()
    path = source.config.native.ROOT / 'code-clues/device-guid-format-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
