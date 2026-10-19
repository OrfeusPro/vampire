"""Prove immediate NetworkSetting callback invocation; not full mount precedence."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('startup_flow', HERE / 'build-headless-cdn-json-flow.py')
flow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flow)
config = flow.body.head.headers.uri.http.preparation.url.settings.config
native = config.native
START, STOP = 0x1445cd6f9, 0x1445cd739
THUNK, LOADER, GETTER = 0x144aa7500, 0x144aa6f20, 0x141408910
INSERT = 0x1445bb590
ROOTS = (0x144aa4810, 0x144aa6e70, LOADER, 0x1445cd6c0,
         0x14563e2f0, 0x144a97cc0, 0x144a97f60, 0x144aa5810, 0x144aa5620)


def replay(raw, image, fragments, external, marker):
    """Execute binder slice/getter/thunk; capture loader and map insertion calls.

    TLS/static initialization and binder prologue are outside this slice.
    Closure descriptor is synthetic, matching constructor field offsets.
    """
    ping = flow.body.head.headers.uri.http.preparation.url.settings.ping
    x = ping.x
    uc = ping.unicorn.Uc(ping.unicorn.UC_ARCH_X86, ping.unicorn.UC_MODE_64)
    scratch, stack = 0x20000000, 0x20030000
    uc.mem_map(scratch, 0x40000)
    allowed = [(START, STOP), (GETTER, GETTER + 5), (THUNK, THUNK + 5)]
    pages = {a & ~4095 for lo, hi in allowed for a in range(lo, hi + 4095, 4096)}
    pages.update(a & ~4095 for a in (LOADER, INSERT, 0x14b1177f0))
    for page in sorted(pages):
        uc.mem_map(page, 4096)
        off = image.offset(page - image.pe.base)
        uc.mem_write(page, raw[off:off + 4096])
    descriptor, name, closure, vtable = [scratch + o for o in (0x1000, 0x2000, 0x4000, 0x5000)]
    context = closure if external else descriptor + 0x20
    uc.mem_write(descriptor, struct.pack('<Q', THUNK))
    uc.mem_write(descriptor + 0x10, struct.pack('<Q', context if external else 0))
    uc.mem_write(context, struct.pack('<QQ', vtable, marker))
    uc.mem_write(vtable + 8, struct.pack('<Q', GETTER))
    events = []

    def hook(machine, address, size, user):
        if any(lo <= address < hi for lo, hi in allowed):
            return
        a, b, c, d = [machine.reg_read(reg) for reg in
            (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        if address == LOADER:
            if a != context + 8:
                raise ValueError('Wrong closure context')
            value = struct.unpack('<Q', bytes(machine.mem_read(a, 8)))[0]
            events.append(dict(kind='loader_capture', marker=value,
                               closure_pointer_matches=True))
        elif address == INSERT:
            if bytes(machine.mem_read(c, 16)) != struct.pack('<QQ', name, descriptor) or d != 0:
                raise ValueError('Unexpected registry insertion arguments')
            events.append(dict(kind='registry_insert_capture', key_and_descriptor_match=True))
        else:
            raise ValueError('Unreviewed startup target ' + hex(address))
        rsp = machine.reg_read(x.UC_X86_REG_RSP)
        ret = struct.unpack('<Q', bytes(machine.mem_read(rsp, 8)))[0]
        machine.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        machine.reg_write(x.UC_X86_REG_RIP, ret)

    uc.hook_add(ping.unicorn.UC_HOOK_CODE, hook)
    for reg, value in ((x.UC_X86_REG_RSP, stack), (x.UC_X86_REG_RBP, name), (x.UC_X86_REG_RSI, descriptor)):
        uc.reg_write(reg, value)
    uc.emu_start(START, STOP, count=256)
    if uc.reg_read(x.UC_X86_REG_RIP) != STOP or [e['kind'] for e in events] != ['loader_capture', 'registry_insert_capture']:
        raise ValueError('Startup order or instruction budget mismatch')
    return dict(context_storage='external' if external else 'inline', marker=marker,
                events=events, start=START, stop=STOP, full_loader_executed=False)


def build():
    source_report = native.ROOT / 'code-clues/headless-cdn-json-flow.json'
    prior = json.loads(source_report.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('Compiled startup source changed')
    image = native.Image(raw)
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in ROOTS})
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    literal_address = rows[0x144aa6e99]['rip_references'][0]
    literal = config.read_literal(raw, image, literal_address)
    if literal['text'] != 'FNnNetworkVar':
        raise ValueError('Network callback name changed')
    anchors = []
    for address, length in ((THUNK, 5), (GETTER, 5), (0x1489a4e88 + 8, 8), (0x14961a320, 8)):
        offset = image.offset(address - image.pe.base)
        anchors.append(dict(address=address, file_offset=offset, bytes=raw[offset:offset + length].hex()))
    if (bytes.fromhex(anchors[0]['bytes']) != b'\xe9' + struct.pack('<i', LOADER - THUNK - 5) or
            bytes.fromhex(anchors[1]['bytes']) != bytes.fromhex('488d4108c3') or
            struct.unpack('<Q', bytes.fromhex(anchors[2]['bytes']))[0] != GETTER):
        raise ValueError('Callback thunk/context getter changed')
    if (struct.unpack('<Q', bytes.fromhex(anchors[3]['bytes']))[0] != 0x144aa4810 or
            rows[0x144aa5828]['rip_references'] != [0x14961a318] or
            rows[0x144aa5684]['rip_references'] != [0x144aa5810]):
        raise ValueError('Owner factory/vtable binding changed')
    for address, target in ((0x144aa4886, 0x144aa6e70), (0x144aa6ecc, 0x1445cd6c0),
                            (0x14563e3ac, 0x144a97cc0), (0x144a97f30, 0x144a97f60)):
        if rows[address]['direct_target'] != target:
            raise ValueError('Startup source edge changed')
    cases = [replay(raw, image, fragments, external, marker)
             for external in (False, True) for marker in (0, 1, 0x12345678, 0xffffffffffffffff)]
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        source_report_sha256=hashlib.sha256(source_report.read_bytes()).hexdigest(),
        callback_name=literal, anchors=anchors, fragments=fragments, cases=cases,
        callback_invoked_before_registry_insert=True, config_precedence_verified=False,
        active_runtime_settings_verified=False, network_ready=False,
        limitations=['Native binder slice, context getter and callback thunk executed on synthetic descriptors.',
            'Loader body and registry insertion are capture shims; no configuration is applied.',
            'TLS/static initialization/prologue and full owner/module startup not executed.',
            'Patch initialization callsites are static evidence, not a proven order relative to config loading.',
            'Archive mount order, GConfig cache, reload and late overrides remain unresolved.'])


if __name__ == '__main__':
    report = build()
    target = native.ROOT / 'code-clues/headless-config-startup.json'
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                         cases=len(report['cases']), config_precedence_verified=False), indent=2))
