"""Locate source-checked GMC2 request slices; static audit, no native execution."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
OLD = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'
NEW = 'd00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
EXPORT_SHA = 'a0509eeaa329af68616c59bbb695a7440c1487aaa894f808615cebe0139bf2fa'
PAIRS = [('url', 0x1444faff0, 0x1444fa180, 0x1444fb178, 0x1444fb48d),
         ('headers', 0x1444fca30, 0x1444fbbc0, 0x1444fcc70, 0x1444fcec1)]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def audit(root=None):
    native = load('gmc_request_native', HERE/'build-native-entry-code.py')
    if native.capstone.__version__ != '5.0.6':
        raise ValueError('Pinned Capstone required')
    root = Path(root) if root else native.ROOT
    images, sources = {}, {}
    for sha in (OLD, NEW):
        path = root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != sha:
            raise ValueError('GMC2 source SHA changed')
        images[sha] = native.Image(raw)
        sources[sha] = dict(path=str(path), sha256=sha)
    export = root/'ghidra/request-exports'/NEW/'run-777fc0535ec7/details.json'
    payload = export.read_bytes()
    if hashlib.sha256(payload).hexdigest() != EXPORT_SHA:
        raise ValueError('GMC2 export SHA changed')
    report = json.loads(payload)
    if report['new_source_sha256'] != NEW:
        raise ValueError('GMC2 export source differs')
    functions = {int(f['address'], 16): f for f in report['functions']}
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    decoder.detail = True

    def body(image, entry):
        containing = image.containing(entry)
        if containing is None or image.roots[containing][0] + image.pe.base != entry:
            raise ValueError('GMC2 root differs')
        fragments = native.decode_ranges(image, {image.roots[containing]})
        rows = [r for f in fragments for r in f['instructions']]
        ranges = [(image.pe.base+f['begin_rva'], image.pe.base+f['end_rva']) for f in fragments]
        shapes = []
        for row in rows:
            ins = next(decoder.disasm(bytes.fromhex(row['bytes']), row['address']))
            masked = bytearray(ins.bytes)
            if row['rip_references']:
                masked[ins.disp_offset:ins.disp_offset+ins.disp_size] = bytes(ins.disp_size)
            target = row['direct_target']
            if target is not None:
                masked[ins.imm_offset:ins.imm_offset+ins.imm_size] = bytes(ins.imm_size)
            local = target-entry if target is not None and any(a <= target < b for a,b in ranges) else None
            shapes.append((masked.hex(), local))
        return rows, shapes

    results = []
    for name, old, new, start, stop in PAIRS:
        old_rows, old_shapes = body(images[OLD], old)
        new_rows, new_shapes = body(images[NEW], new)
        exported = functions[new]
        if not exported['decompilation_completed']:
            raise ValueError('Incomplete GMC2 export')
        if {int(r['address'],16):r['bytes'] for r in exported['instructions']} != {r['address']:r['bytes'] for r in new_rows}:
            raise ValueError('GMC2 export does not cover whole source root')
        if len(old_rows) != len(new_rows):
            raise ValueError('GMC2 instruction count differs; review before aligning slices')
        by_address = {r['address']:i for i,r in enumerate(old_rows)}
        begin, end = by_address[start], by_address[stop]
        if old_shapes[begin:end] != new_shapes[begin:end]:
            raise ValueError('GMC2 request slice changed; port manually')
        results.append(dict(kind=name, old_root=hex(old), new_root=hex(new),
            start=hex(new_rows[begin]['address']), stop=hex(new_rows[end]['address']),
            slice_instruction_count=end-begin, whole_instruction_count=len(new_rows),
            whole_shape_differences=[i for i,(a,b) in enumerate(zip(old_shapes,new_shapes)) if a!=b],
            instructions=new_rows[begin:end], external_targets_verified=False))
    return dict(schema=1, sources=sources, export=dict(path=str(export),sha256=EXPORT_SHA), slices=results,
        dependencies={name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
                      ('audit-gmc2-request-11316.py','build-native-entry-code.py','extract-native-enums.py')},
        compatibility='not_established', native_execution=False,
        limits=['Exact full source/export SHA and whole Ghidra coverage checked.',
                'Slice alignment compares nonrelative instruction bytes and local branch offsets; RIP displacements and external direct targets masked.',
                'Whole-body differences remain explicit; external callees, globals, fixtures and actual URL/header outputs require separate native checks.'])


if __name__ == '__main__':
    result = audit()
    native = load('gmc_request_root', HERE/'build-native-entry-code.py')
    snapshots = load('gmc_request_snapshot', HERE/'audit-client-release.py')
    path = snapshots.save_snapshot(native.ROOT/'code-clues/gmc2-request-11316', result)
    print(json.dumps(dict(report=str(path), slices=[{k:v for k,v in row.items() if k!='instructions'} for row in result['slices']])))
