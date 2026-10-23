"""Source-bound customize screen identity and whole constructor scale default."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def run():
    spec = importlib.util.spec_from_file_location('customize_scale_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec); spec.loader.exec_module(archive)
    hooks = dict.fromkeys((0x144a71810, 0x1445e04f0, 0x145979550))
    h = archive.make_harness(extra_addresses=(0x1464166f0,), fixtures=hooks)
    exports = {}
    for run_name, sha in [('run-0e689084e517', '9bda15f0ddb7d11ffac6c476f14082c3d5a97f8065e1f1b2c0aa3e88c53d7181'),
                          ('run-508d565cecb3', '11648ad0f104dfd4d3b89d1ee051a62d4288fdd82bf9628a87f4255f1229cf0f'),
                          ('run-fb0a2b76c21f', 'f5333575c5088e2e3c79997a344aa47440225098cf142692c1e2646a1c4bdc3d')]:
        path = h.comparison / 'details' / run_name / 'details.json'
        if h.audit.sha256(path) != sha: raise ValueError('Customize scale export changed')
        exports[str(path)] = sha
    def raw_at(address, count):
        offset = h.image.offset(address - h.image.pe.base)
        return h.raw[offset:offset + count]
    wrapper = 0x14640a3f0
    if raw_at(wrapper, 16) != bytes.fromhex('488b094885c90f85f4c20000c3cccccc'):
        raise ValueError('Customize conditional constructor wrapper changed')
    # The registration points here; the JNE transfers the non-null object to
    # 1464166f0. This tiny leaf has no standalone unwind-root export.
    h.ranges.append((wrapper, wrapper + 13))
    name_raw = raw_at(0x149c94ab2, 128)
    class_name = name_raw.decode('utf-16le').split('\0')[0]
    uc, x = h.uc, h.x
    page = wrapper & ~4095
    if not any(a <= page <= b for a, b, _ in uc.mem_regions()):
        uc.mem_map(page, 4096); uc.mem_write(page, raw_at(page, 4096))
    obj, initializer, settings = [h.scratch + n for n in (0x10000, 0x12000, 0x13000)]
    uc.mem_write(settings, bytes(0x60))  # Explicit zero initial capacity setting.
    events = []
    def fixture(machine):
        address = machine.reg_read(x.UC_X86_REG_RIP)
        a = machine.reg_read(x.UC_X86_REG_RCX)
        if address == 0x144a71810:
            if a != obj: raise ValueError('Customize base constructor input differs')
            events.append('base_constructor')
        elif address == 0x1445e04f0:
            if a not in [obj + offset for offset in (0xa00, 0xa18, 0xa30, 0xa48, 0xa60, 0xa78)]:
                raise ValueError('Customize member constructor outside expected members')
            events.append('member_constructor')
        else:
            events.append('settings_lookup'); machine.reg_write(x.UC_X86_REG_RAX, settings)
        sp = machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(x.UC_X86_REG_RSP, sp + 8)
    for address in hooks: hooks[address] = fixture
    cases = []
    for poison in (0, 0xa5, 0xff):
        for present in (False, True):
            events.clear(); uc.mem_write(obj - 16, bytes((poison,)) * (0xca0 + 32))
            uc.mem_write(initializer, struct.pack('<Q', obj if present else 0))
            h.call(wrapper, initializer, budget=200000)
            if not present:
                if events or bytes(uc.mem_read(obj - 16, 0xca0 + 32)) != bytes((poison,)) * (0xca0 + 32):
                    raise ValueError('Customize null initializer changed state')
                cases.append(dict(poison=poison, object_present=False, events=[])); continue
            scale = int.from_bytes(uc.mem_read(obj + 0xc48, 4), 'little')
            presets = struct.unpack('<ii', bytes(uc.mem_read(obj + 0xc54, 8)))
            if scale != 1000 or presets != (-1, -1) or bytes(uc.mem_read(obj + 0xc90, 16)) != bytes(16):
                raise ValueError('Customize scale/preset/owner initialization differs')
            if int.from_bytes(uc.mem_read(obj, 8), 'little') != 0x149c9cee0:
                raise ValueError('Customize constructor vptr differs')
            if events != ['base_constructor'] + ['member_constructor'] * 6 + ['settings_lookup']:
                raise ValueError('Customize constructor event order differs')
            if bytes(uc.mem_read(obj - 16, 16)) != bytes((poison,)) * 16 or bytes(uc.mem_read(obj + 0xca0, 16)) != bytes((poison,)) * 16:
                raise ValueError('Customize constructor crossed allocation size')
            cases.append(dict(poison=poison, object_present=True, scale=scale, preset_ids=list(presets),
                owner_pointer=0, vptr=hex(0x149c9cee0), guards_unchanged=True, events=events.copy()))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)), native_execution=True,
        network_used=False, class_name=class_name, registration=hex(0x146404090), allocation_size=0xca0,
        constructor_wrapper=hex(wrapper), constructor=hex(0x1464166f0), ghidra_exports=exports, cases=cases,
        dependencies={name: h.audit.sha256(HERE / name) for name in ('replay-release-archive-input.py',
            'build-native-entry-code.py', 'extract-native-enums.py', 'build-object-zero-init-code.py', 'requirements-native.txt')},
        limits=['Whole non-null native constructor and reviewed conditional wrapper execute; null wrapper path also checked.',
            'Base/member constructors and settings lookup are fixtures; settings count is explicitly zero, resizing branches not covered.',
            '1000 is the native constructor default; later Blueprint/property deserialization or runtime overrides are not excluded.',
            'Real slider min/max, actual preset CDO defaults, full producer and live creation remain unverified.',
            'No game, authorization or network.'])
    path = h.audit.save_snapshot(h.native.ROOT / 'code-clues/release-customize-scale', report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), class_name=report['class_name'], cases=len(report['cases']))))
