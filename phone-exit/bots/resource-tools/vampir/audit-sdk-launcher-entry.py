"""Check exported SDK and Launcher entry functions against two pinned clients."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct


HERE = Path(__file__).resolve().parent
ROLES = ('sdk-constructor', 'nid-context', 'nid-result', 'launcher-token',
         'launcher-sign-in', 'launcher-token-response', 'launcher-sign-in-response')
CRT = ('api-ms-win-crt-convert-l1-1-0.dll', '_wtoi')


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def checked(path, sha):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != sha:
        raise ValueError('SDK/Launcher input SHA differs: ' + path.name)
    return raw


def file_bytes(image, address, size):
    first = image.offset(address - image.pe.base)
    last = image.offset(address + size - 1 - image.pe.base)
    if last != first + size - 1:
        raise ValueError('SDK/Launcher bytes cross PE sections')
    return image.data[first:last + 1]


def read_release(native, root, release):
    sha = release['sha256']
    if len(sha) != 64 or any(c not in '0123456789abcdef' for c in sha):
        raise ValueError('Full client SHA required')
    exe = root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'
    image = native.Image(checked(exe, sha))
    inputs = {exe: sha}
    entries = release['entries']
    if set(entries) != set(ROLES) or len(set(entries.values())) != len(ROLES):
        raise ValueError('SDK/Launcher entry set differs')
    exports = {}
    for run, digest in release['exports'].items():
        if Path(run).name != run or not run.startswith('run-'):
            raise ValueError('Invalid entry export path')
        path = root / 'ghidra/request-exports' / sha / run / 'details.json'
        document = json.loads(checked(path, digest))
        inputs[path] = digest
        if document['new_source_sha256'] != sha:
            raise ValueError('SDK/Launcher export client differs')
        for function in document['functions']:
            address = function['address']
            if address not in entries.values():
                continue
            if address in exports or not all(function.get(key) is True for key in (
                    'decompilation_completed', 'block_coverage_complete', 'direct_flow_coverage_complete')):
                raise ValueError('Duplicate or incomplete SDK/Launcher entry export')
            exports[address] = function
    if set(exports) != set(entries.values()):
        raise ValueError('Missing SDK/Launcher entry export')
    return image, {role: exports[address] for role, address in entries.items()}, inputs


def switch_shape(native, decoder, image, function, offset):
    entry = int(function['address'], 16)
    root = image.containing(entry)
    if root is None or root != image.roots[root] or image.pe.base + root[0] != entry:
        raise ValueError('NID context is not the declared unwind root')
    cursor = entry
    instructions = []
    for row in function['instructions']:
        data = bytes.fromhex(row['bytes'])
        if int(row['address'], 16) != cursor or file_bytes(image, cursor, len(data)) != data:
            raise ValueError('NID code prefix has a gap or differing bytes')
        decoded = list(decoder.disasm(data, cursor))
        if len(decoded) != 1 or decoded[0].size != len(data):
            raise ValueError('NID instruction boundary differs')
        instructions.append(decoded[0])
        cursor += len(data)
    if not instructions or instructions[-1].mnemonic != 'ret':
        raise ValueError('NID code prefix has no final RET')
    code = {ins.address for ins in instructions}
    shape, table, calls, references = [], None, [], []
    for ins in instructions:
        data = bytearray(ins.bytes)
        edge = None
        relative = ins.address - entry
        if ins.group(native.capstone.CS_GRP_JUMP) or ins.group(native.capstone.CS_GRP_CALL):
            if ins.operands[0].type == native.X86_OP_IMM:
                target = ins.operands[0].imm
                if ins.group(native.capstone.CS_GRP_JUMP) and target not in code:
                    raise ValueError('NID direct branch outside code')
                edge = target - entry if target in code else 'external'
                if target not in code:
                    calls.append(dict(offset=relative, target=hex(target)))
                data[ins.imm_offset:ins.imm_offset + ins.imm_size] = bytes(ins.imm_size)
        for op in ins.operands:
            if op.type == native.X86_OP_MEM and op.mem.base == native.X86_REG_RIP:
                references.append(dict(offset=relative, target=hex(ins.address + ins.size + op.mem.disp)))
                data[ins.disp_offset:ins.disp_offset + ins.disp_size] = bytes(ins.disp_size)
        if relative == offset:
            if ins.mnemonic != 'mov' or ins.operands[1].type != native.X86_OP_MEM or ins.disp_size != 4:
                raise ValueError('NID switch instruction differs')
            address = image.pe.base + ins.operands[1].mem.disp
            if address != cursor + 1 or file_bytes(image, cursor, 1) != b'\x90' or address + 24 != image.pe.base + root[1]:
                raise ValueError('NID switch padding or table boundary differs')
            targets = [image.pe.base + rva for rva in struct.unpack('<6I', file_bytes(image, address, 24))]
            if not set(targets) <= code:
                raise ValueError('NID switch targets outside code')
            table = [target - entry for target in targets]
            data[ins.disp_offset:ins.disp_offset + ins.disp_size] = bytes(ins.disp_size)
        shape.append((relative, data.hex(), edge))
    if table is None:
        raise ValueError('NID switch not found')
    return dict(shape=(shape, table), calls=calls, references=references)


def response_shape(imports, image, shape, offset):
    refs = {row['offset']: int(row['target'], 16) for row in shape['references']}
    identity = imports.import_at(image.data, image, refs[offset])
    if (identity['dll'].lower(), identity['name']) != CRT:
        raise ValueError('Launcher response CRT import differs')
    rows = shape['shape']
    if not any(at == offset and edge and edge[:2] == ('indirect', 'call') for at, _, edge in rows):
        raise ValueError('Launcher response CRT site is not an indirect call')
    return [(at, data, ('import', *CRT) if at == offset else edge) for at, data, edge in rows]


def route_edges(image, request, response, data, route):
    literal = (route + '\0').encode('utf-16le')
    refs = [int(row['target'], 16) for row in request['references']]
    matches = 0
    for ref in refs:
        # Mutable BSS references are outside this literal check.
        try:
            value = file_bytes(image, ref, len(literal))
        except ValueError:
            continue
        matches += value == literal
    if matches != 1:
        raise ValueError('Launcher route literal differs')
    thunk = int(next(row['target'] for row in request['references'] if row['offset'] == data['thunk']), 16)
    body = file_bytes(image, thunk, 5)
    if body[0] != 0xe9 or thunk + 5 + struct.unpack_from('<i', body, 1)[0] != response:
        raise ValueError('Launcher callback thunk differs')
    return hex(thunk)


def audit(context, root):
    native = load('build-native-entry-code')
    normalizer = load('audit-launcher-shape-11318')
    imports = load('build-object-zero-init-code')
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    decoder.detail = True
    if context['schema'] != 1 or context['baseline']['sha256'] == context['target']['sha256']:
        raise ValueError('SDK/Launcher comparison requires two distinct releases')
    if set(context['launcher']) != {'token', 'sign-in'}:
        raise ValueError('SDK/Launcher route set differs')
    releases = [read_release(native, root, context[name]) for name in ('baseline', 'target')]
    results = []
    for image, functions, _ in releases:
        normalized = {}
        switch = switch_shape(native, decoder, image, functions['nid-context'], context['nid_switch_offset'])
        for role, function in functions.items():
            if role != 'nid-context':
                normalized[role] = normalizer.normalize_function(native, image, function)
        routes = {}
        for route, data in context['launcher'].items():
            role = 'launcher-' + route
            response = role + '-response'
            normalized[response]['shape'] = response_shape(imports, image, normalized[response], data['crt'])
            routes[route] = route_edges(image, normalized[role], int(functions[response]['address'], 16),
                                       data, 'launcher/' + route)
        normalized['nid-context'] = switch
        results.append((normalized, routes))
    (old, _), (new, routes) = results
    for role in ROLES:
        if old[role]['shape'] != new[role]['shape']:
            raise ValueError('SDK/Launcher instruction or local control flow differs: ' + role)
    for _, _, inputs in releases:
        for path, sha in inputs.items():
            checked(path, sha)
    dependencies = {role: dict(
        calls=[dict(baseline=a, target=b) for a, b in zip(old[role]['calls'], new[role]['calls'])],
        references=[dict(baseline=a, target=b) for a, b in zip(old[role]['references'], new[role]['references'])])
        for role in ROLES}
    return dict(source_sha256=context['target']['sha256'], baseline_sha256=context['baseline']['sha256'],
                instructions={role: len(new[role]['shape'][0] if role == 'nid-context' else new[role]['shape'])
                              for role in ROLES}, callback_thunks=routes, scope='static_entries_only',
                unresolved_dependencies=dependencies,
                network_used=False, semantic_verification=False, runtime_admitted=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, default=HERE / 'knowledge/native-contexts/sdk-launcher-entry-11322.json')
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    context_bytes = args.context.read_bytes()
    result = audit(json.loads(context_bytes), args.root)
    result['context'] = dict(path=str(args.context.resolve()), sha256=hashlib.sha256(context_bytes).hexdigest())
    result['tool_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    path = load('research-workflow').snapshot(args.root, 'sdk-launcher-entry-checks', result)
    print(json.dumps(dict(report=str(path), source_sha256=result['source_sha256'],
                          instructions=result['instructions'], runtime_admitted=False)))
