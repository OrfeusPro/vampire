"""Static source-bound Windows SDK device identity/storage evidence; no user data."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


config = load('device_identity_config', HERE / 'build-headless-sdk-config.py')
imports = load('device_identity_imports', HERE / 'build-object-zero-init-code.py')
ADDRESSES = (0x1444e5ff0, 0x144522820, 0x14454b390, 0x14452f230,
             0x14452f170, 0x14155a550, 0x14155abf0, 0x1415c59c0, 0x1415d1990,
             0x1415ce230, 0x1415ad580, 0x14452bcd0)
GLOBALS = (0x14b4f1030, 0x14b4f1040, 0x14b4f1070, 0x14b4f1a88, 0x14b4f1a68)


def build():
    native = config.native
    prior = json.loads((native.ROOT / 'code-clues/headless-auth-index.json').read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('Device identity source changed')
    image = native.Image(raw)
    roots = {image.roots[image.containing(a)] for a in ADDRESSES}
    candidates = native.rip_candidates(image, set(GLOBALS))
    initializers = {image.roots[image.containing(a)] for a, _ in candidates
                    if image.containing(a) and image.roots[image.containing(a)][0] < 0x2000000}
    fragments = native.decode_ranges(image, roots | initializers)
    rows = {i['address']: i for f in fragments for i in f['instructions']}
    bindings = []
    for address, target in candidates:
        if address not in rows or target not in rows[address]['rip_references']:
            continue
        root = image.roots[image.containing(address)]
        if root not in initializers:
            continue
        literals = []
        for f in fragments:
            if f['root_begin_rva'] != root[0]:
                continue
            for row in f['instructions']:
                if row['mnemonic'] == 'lea':
                    for ref in row['rip_references']:
                        if literal := config.read_literal(raw, image, ref):
                            literals.append(dict(instruction=row['address'], **literal))
        bindings.append(dict(global_address=target, initializer_reference=address, literals=literals))
    # Formatter contains a jump table: export only reviewed instruction spans.
    cs = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    cs.detail = True
    spans = []
    for begin, end in ((0x1415bf470, 0x1415bf477), (0x141548fd0, 0x141549019),
                       (0x141549610, 0x141549674)):
        offset = image.offset(begin - image.pe.base)
        data = raw[offset:offset + end - begin]
        instructions = list(cs.disasm(data, begin))
        if sum(i.size for i in instructions) != len(data):
            raise ValueError('Device identity span not fully decoded')
        literals = []
        for i in instructions:
            for op in i.operands:
                if op.type == native.capstone.x86_const.X86_OP_MEM and op.mem.base == native.capstone.x86_const.X86_REG_RIP:
                    ref = i.address + i.size + op.mem.disp
                    if literal := config.read_literal(raw, image, ref):
                        literals.append(dict(instruction=i.address, **literal))
        spans.append(dict(begin=begin, end=end, file_offset=offset, bytes=data.hex(),
                          sha256=hashlib.sha256(data).hexdigest(), literals=literals,
                          instructions=[dict(address=i.address, mnemonic=i.mnemonic, operands=i.op_str) for i in instructions]))
    literals = []
    named_imports = []
    for row in rows.values():
        for ref in row['rip_references']:
            if row['mnemonic'] == 'lea' and (literal := config.read_literal(raw, image, ref)):
                literals.append(dict(instruction=row['address'], **literal))
            if row['mnemonic'] == 'call':
                try:
                    named = imports.import_at(raw, image, ref)
                except ValueError:
                    continue
                named_imports.append(dict(instruction=row['address'], **named))
    guid_import = imports.import_at(raw, image, 0x1415bf477 + 0x7386fd1)
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                fragments=fragments, bindings=bindings, literals=literals, spans=spans,
                guid_import=guid_import, named_imports=named_imports,
                native_execution=False, user_identity_read=False,
                limitations=[
                    'Static compiled Windows client evidence only; no native emulation or live process.',
                    'Registry reads/writes and GUID generation not executed; no Saved/profile/registry data read.',
                    'PlatformType selection, full GUID parser/formatter and active SDK settings need verification.',
                    'Device keys alone do not prove full server device fingerprint or confirmation protocol.'])


if __name__ == '__main__':
    report = build()
    path = config.native.ROOT / 'code-clues/headless-device-identity.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                          fragments=len(report['fragments']), guid_import=report['guid_import']['name'])))
