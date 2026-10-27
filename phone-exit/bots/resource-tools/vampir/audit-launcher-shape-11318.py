"""Compare complete source-bound launcher functions, preserving local control flow."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCES = (
    ('d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960',
     'run-e6508b986175', 'c9923787de462d4bdca9e03cdcf59a9ff333003cae0b574e9ee43c74fb71e101',
     (0x1444ee9d0, 0x144503b10)),
    ('d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c',
     'run-5e88e50e265d', '8a81049376b63fbb7b476c3381aae08b0f9e325360c73ddf249f2108e3d799b4',
     (0x1444eecd0, 0x144503e10)),
)


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE/(name+'.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def normalize_function(native, image, function, legacy=False):
    if function.get('block_coverage_complete') is not True and not (legacy and function.get('block_coverage_complete') is None):
        raise ValueError('Incomplete launcher block metadata')
    if load('knowledge-index').missing_conditional_fallthroughs(function['instructions']):
        raise ValueError('Incomplete launcher block/fallthrough coverage')
    if function.get('direct_flow_coverage_complete') is False:
        raise ValueError('Incomplete launcher direct flow')
    # Legacy None metadata is accepted only with explicit instruction/edge validation below.
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    decoder.detail = True
    start = int(function['address'], 16)
    part = image.containing(start)
    if part is None or image.roots[part][0]+image.pe.base != start:
        raise ValueError('Launcher must begin at the declared unwind root')
    exported = {int(r['address'], 16):r['bytes'] for r in function['instructions']}
    actual = {r['address']:r['bytes'] for fragment in native.decode_ranges(image, {image.roots[part]})
        for r in fragment['instructions']}
    if exported != actual:
        raise ValueError('Launcher export does not cover the complete native ranges')
    shape, calls, refs = [], [], []
    for at, encoded in sorted(exported.items()):
        data = bytearray.fromhex(encoded)
        if image.data[image.offset(at-image.pe.base):image.offset(at-image.pe.base)+len(data)] != data:
            raise ValueError('Launcher instruction differs from pinned EXE')
        instructions = list(decoder.disasm(data, at))
        if len(instructions)!=1 or instructions[0].size!=len(data):
            raise ValueError('Invalid launcher instruction boundary')
        ins = instructions[0]; edge = None
        if ins.group(native.capstone.CS_GRP_CALL) or ins.group(native.capstone.CS_GRP_JUMP):
            if ins.imm_size:
                target = ins.operands[0].imm
                edge = ('local', target-start) if target in exported else ('external', len(calls))
                if target not in exported:calls.append(dict(offset=at-start, target=hex(target)))
                data[ins.imm_offset:ins.imm_offset+ins.imm_size] = bytes(ins.imm_size)
            else:edge = ('indirect', ins.mnemonic, ins.op_str)
        for op in ins.operands:
            if op.type == native.X86_OP_MEM and op.mem.base == native.X86_REG_RIP:
                target = ins.address+ins.size+op.mem.disp
                refs.append(dict(offset=at-start, target=hex(target)))
                data[ins.disp_offset:ins.disp_offset+ins.disp_size] = bytes(ins.disp_size)
        shape.append((at-start, data.hex(), edge))
    return dict(shape=shape, calls=calls, references=refs,
        legacy_metadata=function.get('direct_flow_coverage_complete') is None)


def run():
    native = load('build-native-entry-code'); audit = load('audit-client-release')
    images, results, evidence = [], [], []
    for sha, run_id, expected, addresses in SOURCES:
        source = native.ROOT/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'
        raw = source.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=sha:raise ValueError('Launcher source SHA changed')
        image = native.Image(raw); images.append(image)
        path = native.ROOT/'ghidra/request-exports'/sha/run_id/'details.json'
        if audit.sha256(path)!=expected:raise ValueError('Launcher export SHA changed')
        document = json.loads(path.read_text('utf-8'))
        if document['new_source_sha256']!=sha:raise ValueError('Launcher export source changed')
        functions = {int(f['address'],16):f for f in document['functions']}
        results.append([normalize_function(native, image, functions[a], legacy=sha==SOURCES[0][0]) for a in addresses])
        evidence.append(dict(path=str(path), sha256=expected))
    pairs = []
    for number, route in enumerate(('launcher/token', 'launcher/sign-in')):
        old, new = results[0][number], results[1][number]
        if old['shape']!=new['shape']:
            raise ValueError('Full launcher instruction/local-control-flow shape changed')
        routes = []
        for image, result in zip(images, (old,new)):
            found = []
            for ref in result['references']:
                target = int(ref['target'],16)
                try:off = image.offset(target-image.pe.base)
                except ValueError:continue
                literal = (route+'\0').encode('utf-16le')
                if image.data[off:off+len(literal)]==literal:found.append(ref)
            if len(found)!=1:raise ValueError('Launcher route reference absent or ambiguous')
            routes.append(found[0])
        if [c['offset'] for c in old['calls']]!=[c['offset'] for c in new['calls']]:
            raise ValueError('Launcher external call sites changed')
        if [r['offset'] for r in old['references']]!=[r['offset'] for r in new['references']]:
            raise ValueError('Launcher RIP reference sites changed')
        pairs.append(dict(route=route, old=hex(SOURCES[0][3][number]), current=hex(SOURCES[1][3][number]),
            instructions=len(new['shape']), equal_shape=True, route_references=routes,
            external_calls=[dict(old=a,current=b) for a,b in zip(old['calls'],new['calls'])],
            data_references=[dict(old=a,current=b) for a,b in zip(old['references'],new['references'])],
            old_legacy_coverage=old['legacy_metadata']))
    report = dict(source_sha256=SOURCES[1][0], baseline_sha256=SOURCES[0][0], exports=evidence,
        tool_sha256=audit.sha256(Path(__file__)), pairs=pairs, network_used=False,
        profile_activation=False, compatibility='not_established',
        limits=['Complete instruction shapes and local edges agree; RIP targets and external callees are recorded unresolved pairs.',
                'No native execution, request serialization, response callbacks, SDK context or live authentication verified.'])
    target = audit.save_snapshot(native.ROOT/'code-clues/launcher-shape-11318', report)
    return target, report


if __name__=='__main__':
    target, result = run()
    print(json.dumps(dict(artifact=str(target), functions=len(result['pairs'])), ensure_ascii=False))
