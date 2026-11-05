"""Compare a declared Launcher source contract without authentication or network."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct


HERE = Path(__file__).resolve().parent
KEYS = {'buildCode', 'countryCode', 'credential', 'deviceKey', 'gameCode',
        'launcherToken', 'nmDeviceKey', 'os', 'errorCode', 'resultData'}
ENDPOINTS = {'launcher/token', 'launcher/sign-in'}
CRT = ('api-ms-win-crt-convert-l1-1-0.dll', '_wtoi')
LIMITS = [
    'Whole source bytes, blocks, key constructor arguments, cleanup tails and declared request/response links are checked statically.',
    'Field values, JSON/HTTP execution, external implementations and runtime callbacks require their separate checks.',
    'No SDK/browser/server acceptance or whole game protocol is established.']


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def checked(path, expected):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('Launcher source or export SHA changed: ' + str(path))
    return raw


def address(value):
    if not isinstance(value, str) or not re.fullmatch('0x[0-9a-f]+', value):
        raise ValueError('Launcher address is not canonical')
    return int(value, 16)


def data(image, at, size):
    start = image.offset(at - image.pe.base)
    end = image.offset(at + size - 1 - image.pe.base)
    if end != start + size - 1:
        raise ValueError('Launcher data crosses file-backed sections')
    return image.data[start:end + 1]


def literal_matches(image, at, value):
    try:
        return data(image, at, len(value)) == value
    except ValueError:
        return False


def read_release(native, normalizer, root, declaration):
    sha = declaration['source_sha256']
    if not isinstance(sha, str) or not re.fullmatch('[0-9a-f]{64}', sha):
        raise ValueError('Launcher full source SHA required')
    keys = declaration['keys']
    requests = declaration['requests']
    if set(keys) != KEYS or {row['endpoint'] for row in requests} != ENDPOINTS or len(requests) != 2:
        raise ValueError('Launcher key or route set differs')
    roots = {address(value['entry']) for value in keys.values()}
    roots.update(address(value[name]) for value in requests for name in ('entry', 'response'))
    if len(roots) != 14:
        raise ValueError('Launcher fourteen whole roots required')
    source = root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'
    image = native.Image(checked(source, sha))
    inputs = {str(source): sha}
    functions = {}
    evidence = []
    for run, expected in declaration['exports'].items():
        if not re.fullmatch('run-[0-9a-f]{12}', run) or not re.fullmatch('[0-9a-f]{64}', expected):
            raise ValueError('Launcher export declaration differs')
        path = root / 'ghidra/request-exports' / sha / run / 'details.json'
        document = json.loads(checked(path, expected))
        inputs[str(path)] = expected
        evidence.append(dict(path=str(path), sha256=expected))
        if document['new_source_sha256'] != sha:
            raise ValueError('Launcher export source differs')
        for function in document['functions']:
            at = address(function['address'])
            if at not in roots:
                continue
            if at in functions or not all(function.get(field) is True for field in (
                    'decompilation_completed', 'block_coverage_complete', 'direct_flow_coverage_complete')):
                raise ValueError('Launcher duplicate or incomplete whole root')
            functions[at] = function
    if set(functions) != roots:
        raise ValueError('Launcher whole root missing')
    shapes = {at: normalizer.normalize_function(native, image, function) for at, function in functions.items()}
    return image, functions, shapes, inputs, evidence


def key_binding(native, decoder, image, function, spec, label, constructor, cleanup):
    entry, literal, global_at = (address(spec[name]) for name in ('entry', 'literal', 'global'))
    if data(image, literal, (len(label) + 1) * 2) != (label + '\0').encode('utf-16le'):
        raise ValueError('Launcher key literal changed')
    arguments = {}
    constructors = 0
    tails = 0
    for row in function['instructions']:
        ins = next(decoder.disasm(bytes.fromhex(row['bytes']), address(row['address'])))
        if ins.mnemonic == 'lea' and ins.operands[1].type == native.X86_OP_MEM and ins.operands[1].mem.base == native.X86_REG_RIP:
            arguments[ins.reg_name(ins.operands[0].reg)] = ins.address + ins.size + ins.operands[1].mem.disp
        if ins.mnemonic == 'call':
            if (ins.operands[0].type != native.X86_OP_IMM or ins.operands[0].imm != constructor
                    or arguments.get('rcx') != global_at or arguments.get('rdx') != literal):
                raise ValueError('Launcher key constructor arguments or target differ')
            constructors += 1
        if ins.mnemonic == 'jmp':
            if ins.operands[0].type != native.X86_OP_IMM or ins.operands[0].imm != cleanup:
                raise ValueError('Launcher key cleanup tail differs')
            tails += 1
    if constructors != 1 or tails != 1:
        raise ValueError('Launcher key constructor or cleanup count differs')
    return dict(key=label, function=hex(entry), literal=hex(literal), global_address=hex(global_at),
                constructor=hex(constructor), cleanup=hex(cleanup))


def response_crt(native, imports, decoder, image, function, shape, offset):
    entry = address(function['address'])
    found = []
    for row in function['instructions']:
        ins = next(decoder.disasm(bytes.fromhex(row['bytes']), address(row['address'])))
        if (ins.mnemonic != 'call' or ins.operands[0].type != native.X86_OP_MEM
                or ins.operands[0].mem.base != native.X86_REG_RIP):
            continue
        identity = imports.import_at(image.data, image, ins.address + ins.size + ins.operands[0].mem.disp)
        if (ins.address - entry != offset or (identity['dll'].lower(), identity['name']) != CRT):
            raise ValueError('Launcher response CRT import or call site differs')
        found.append(dict(offset=offset, identity=identity))
    if len(found) != 1:
        raise ValueError('Launcher response CRT call count differs')
    normalized = [(at, encoded, ('import', *CRT) if at == offset else edge)
                  for at, encoded, edge in shape['shape']]
    return normalized, found[0]


def release_contract(native, imports, normalizer, root, declaration):
    image, functions, shapes, inputs, evidence = read_release(native, normalizer, root, declaration)
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    decoder.detail = True
    labels = [key_binding(native, decoder, image, functions[address(spec['entry'])], spec, label,
                          address(declaration['string_constructor']), address(declaration['cleanup_tail']))
              for label, spec in declaration['keys'].items()]
    by_name = {row['key']: row for row in labels}
    requests, responses = [], []
    for spec in declaration['requests']:
        route = spec['endpoint']
        entry, response = address(spec['entry']), address(spec['response'])
        proof = shapes[entry]
        refs = {address(row['target']) for row in proof['references']}
        calls = {address(row['target']) for row in proof['calls']}
        required = {'nmDeviceKey', 'deviceKey', 'countryCode', 'os'}
        required |= {'gameCode', 'buildCode', 'credential'} if route == 'launcher/token' else {'launcherToken'}
        if any(address(by_name[label]['global_address']) not in refs for label in required):
            raise ValueError('Launcher request key reference absent')
        callback, transport, shared = (address(spec[name]) for name in ('callback', 'transport', 'shared_literal'))
        if not {callback, shared} <= refs or transport not in calls:
            raise ValueError('Launcher callback, transport or shared reference differs')
        shared_bytes = (spec['shared_literal_text'] + '\0').encode('ascii')
        if data(image, shared, len(shared_bytes)) != shared_bytes:
            raise ValueError('Launcher shared literal changed')
        endpoints = [ref for ref in refs if literal_matches(image, ref, (route + '\0').encode('utf-16le'))]
        if len(endpoints) != 1:
            raise ValueError('Launcher endpoint literal missing or ambiguous')
        jump = data(image, callback, 5)
        if jump[0] != 0xe9 or callback + 5 + struct.unpack_from('<i', jump, 1)[0] != response:
            raise ValueError('Launcher callback thunk differs')
        result = shapes[response]
        result_refs = {address(row['target']) for row in result['references']}
        result_calls = {address(row['target']) for row in result['calls']}
        getter, dispatcher = address(spec['result_getter']), address(spec['dispatcher'])
        if (not {address(by_name[label]['global_address']) for label in ('errorCode', 'resultData')} <= result_refs
                or not {getter, dispatcher} <= result_calls):
            raise ValueError('Launcher result key, getter or dispatcher differs')
        normalized, crt = response_crt(native, imports, decoder, image, functions[response], result, spec['crt_offset'])
        shapes[response] = dict(result, shape=normalized)
        requests.append(dict(function=hex(entry), endpoint=route, callback=hex(callback),
            callback_root=hex(response), transport=hex(transport), key_references=sorted(required),
            header_reference=hex(shared), shared_literal_text=spec['shared_literal_text']))
        responses.append(dict(function=hex(response), result_getter=hex(getter), dispatcher=hex(dispatcher), crt=crt))
    return dict(keys=labels, requests=requests, responses=responses,
        functions=[dict(address=hex(at), instruction_count=len(shapes[at]['shape'])) for at in sorted(functions)],
        evidence=evidence, inputs=inputs, shapes=shapes)


def audit(context, root):
    root = Path(root).resolve()
    if (context.get('schema') != 1 or context.get('recipe') != 'launcher-contract-v1'
            or set(context) != {'schema', 'recipe', 'baseline', 'target'}
            or context['baseline']['source_sha256'] == context['target']['source_sha256']):
        raise ValueError('Launcher contract declaration differs')
    native = load('build-native-entry-code')
    normalizer = load('audit-launcher-shape-11318')
    imports = load('build-object-zero-init-code')
    before = release_contract(native, imports, normalizer, root, context['baseline'])
    after = release_contract(native, imports, normalizer, root, context['target'])
    pairs = {address(context['baseline']['keys'][label]['entry']): address(spec['entry'])
             for label, spec in context['target']['keys'].items()}
    old_requests = {row['endpoint']: row for row in context['baseline']['requests']}
    for row in context['target']['requests']:
        prior = old_requests[row['endpoint']]
        pairs[address(prior['entry'])] = address(row['entry'])
        pairs[address(prior['response'])] = address(row['response'])
    dependencies = []
    for previous, current in pairs.items():
        old, new = before['shapes'][previous], after['shapes'][current]
        if old['shape'] != new['shape']:
            raise ValueError('Launcher complete instruction or local control shape differs: ' + hex(current))
        dependencies.append(dict(baseline=hex(previous), target=hex(current),
            calls=[dict(baseline=a, target=b) for a, b in zip(old['calls'], new['calls'])],
            references=[dict(baseline=a, target=b) for a, b in zip(old['references'], new['references'])]))
    for path, expected in {**before['inputs'], **after['inputs']}.items():
        checked(Path(path), expected)
    return dict(schema=1, recipe='launcher-contract-v1', source_sha256=context['target']['source_sha256'],
        source=str(root / 'client-code-snapshots' / context['target']['source_sha256'] / 'ProjectRED-Win64-Shipping.exe'),
        baseline_sha256=context['baseline']['source_sha256'], method='static', network_requests=0,
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        evidence=before['evidence'] + after['evidence'], keys=after['keys'], requests=after['requests'],
        responses=after['responses'], functions=after['functions'], unresolved_dependencies=dependencies,
        native_execution=False, network_used=False, runtime_admitted=False, profile_activated=False, limits=LIMITS)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, default=HERE / 'knowledge/native-contexts/launcher-contract-11322.json')
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    context_bytes = args.context.read_bytes()
    result = audit(json.loads(context_bytes), args.root)
    if args.context.read_bytes() != context_bytes:
        raise ValueError('Launcher context changed during audit')
    result['context'] = dict(path=str(args.context.resolve()), sha256=hashlib.sha256(context_bytes).hexdigest())
    result['tool_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    path = load('audit-client-release').save_snapshot(args.root / 'code-clues/launcher-contract-v1', result)
    print(json.dumps(dict(report=str(path), source_sha256=result['source_sha256'],
                          functions=len(result['functions']), native_execution=False)))
