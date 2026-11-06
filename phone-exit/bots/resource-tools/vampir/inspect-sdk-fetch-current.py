"""Static, source-bound Fetch-only contract; no auth, native execution or admission."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
RECIPE = 'sdk-fetch-current-static-v1'
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
BASELINE = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def checked(path, expected, inputs):
    raw = Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('Fetch source, evidence or tool SHA changed: ' + Path(path).name)
    inputs[str(Path(path).resolve())] = expected
    return raw


def path_at(root, value):
    path = (root / value).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError('Fetch evidence path escapes resource root')
    return path


def whole(native, normalizer, root, spec, inputs):
    image = native.Image(checked(path_at(root, spec['source']), spec['source_sha256'], inputs))
    wanted = {int(spec[name], 16) for name in ('request', 'response')}
    functions = {}
    for pointer in spec['exports']:
        document = json.loads(checked(path_at(root, pointer['path']), pointer['sha256'], inputs))
        if document['new_source_sha256'] != spec['source_sha256']:
            raise ValueError('Fetch export source differs')
        for function in document['functions']:
            at = int(function['address'], 16)
            if at not in wanted:
                continue
            if at in functions or function.get('decompilation_completed') is not True:
                raise ValueError('Fetch duplicate or incomplete whole export')
            functions[at] = function
    if set(functions) != wanted:
        raise ValueError('Fetch whole request/response missing')
    shapes = {at: normalizer.normalize_function(native, image, function,
              legacy=spec['source_sha256'] == BASELINE) for at, function in functions.items()}
    return image, functions, shapes


def verify_fragment(native, shared, image, spec):
    at = int(spec['entry'], 16)
    code = bytes.fromhex(spec['bytes'])
    if len(code) != 39 or shared.data(image, at, len(code)) != code:
        raise ValueError('Fetch scope initializer fragment differs')
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(code, at))
    if len(instructions) != 7 or sum(i.size for i in instructions) != 39:
        raise ValueError('Fetch scope fragment instruction coverage differs')
    function = dict(address=spec['entry'], instructions=[dict(address=hex(i.address), bytes=bytes(i.bytes).hex()) for i in instructions])
    proof = shared.key_binding(native, decoder, image, function, spec, 'scope',
        int(spec['constructor'], 16), int(spec['cleanup'], 16))
    return dict(proof, byte_count=39, instruction_count=7, coverage='explicit_fragment',
                crt_cleanup_executed=False, whole_function_export=False)


def verify_contract(context, image, functions, shapes, shared):
    spec = context['contract']
    request = shapes[int(context['target']['request'], 16)]
    response = shapes[int(context['target']['response'], 16)]
    refs = {r['target'] for r in request['references']}
    calls = {r['target'] for r in request['calls']}
    if spec['endpoint'] != 'v1/fetch-player' or spec['scope'] != 'channel':
        raise ValueError('Fetch endpoint or scope declaration differs')
    for name, value, encoding in (('endpoint_literal', spec['endpoint'], 'utf-16le'),
                                 ('channel_literal', 'channel', 'utf-16le'),
                                 ('auth_literal', 'authUrl', 'ascii')):
        at = spec[name]
        encoded = (value + '\0').encode(encoding)
        if at not in refs or shared.data(image, int(at, 16), len(encoded)) != encoded:
            raise ValueError('Fetch endpoint/scope/auth literal is missing or changed')
    for name in ('credential_global', 'scope_global', 'callback'):
        if spec[name] not in refs:
            raise ValueError('Fetch body key or callback reference missing')
    if any(spec[name] not in calls for name in ('transport', 'object_builder', 'serializer', 'auth_getter')):
        raise ValueError('Fetch shared transport/JSON/config call missing')
    callback = int(spec['callback'], 16)
    jump = shared.data(image, callback, 5)
    if jump[0] != 0xe9 or callback + 5 + struct.unpack_from('<i', jump, 1)[0] != int(context['target']['response'], 16):
        raise ValueError('Fetch callback does not reach the declared whole response')
    response_refs = {r['target'] for r in response['references']}
    response_calls = {r['target'] for r in response['calls']}
    if not {spec['error_global'], spec['result_global']} <= response_refs:
        raise ValueError('Fetch error/result keys absent')
    if not {spec['presence_getter'], spec['text_getter'], spec['object_getter'], spec['dispatcher']} <= response_calls:
        raise ValueError('Fetch response getter or dispatcher absent')
    # These byte-checked instruction sequences bind argument flow and branches;
    # equal whole-function shape alone is never used as the contract proof.
    required_windows = {'credential-virtual8-body-pairs': ('request',912,1018),
        'authurl-lookup': ('request',1180,1220), 'endpoint-suffix': ('request',1692,1715),
        'request-callback-and-transport': ('request',1930,2033),
        'errorCode-presence-text-wtoi': ('response',1212,1311),
        'http200-206-gate': ('response',1736,1750), 'resultData-optional-object': ('response',2104,2162)}
    if set(spec['instruction_windows']) != set(required_windows):
        raise ValueError('Fetch instruction contract windows are incomplete')
    for name, evidence in spec['instruction_windows'].items():
        root = int(evidence['root'], 16)
        role, lower, upper = required_windows[name]
        if root != int(context['target'][role],16):
            raise ValueError('Fetch instruction window has the wrong whole root')
        rows = {int(r['address'], 16) - root: r for r in functions[root]['instructions']}
        if [item['offset'] for item in evidence['instructions']] != sorted(off for off in rows if lower <= off <= upper):
            raise ValueError('Fetch instruction window omits source instructions')
        selected = [rows.get(item['offset']) for item in evidence['instructions']]
        if any(row is None or row['bytes'] != expected['bytes'] for row, expected in zip(selected, evidence['instructions'])):
            raise ValueError('Fetch instruction contract window changed: ' + name)
    return spec


def audit(context, root):
    root = Path(root).resolve()
    if (context.get('schema') != 1 or context.get('recipe') != RECIPE
            or context['baseline']['source_sha256'] != BASELINE or context['target']['source_sha256'] != SOURCE):
        raise ValueError('Fetch contract context/source differs')
    native, normalizer, shared, imports = [load(name) for name in (
        'build-native-entry-code', 'audit-launcher-shape-11318', 'audit-launcher-contract', 'build-object-zero-init-code')]
    inputs = {}
    before = whole(native, normalizer, root, context['baseline'], inputs)
    after = whole(native, normalizer, root, context['target'], inputs)
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64); decoder.detail = True
    crt = []
    for spec, (image, functions, shapes) in zip((context['baseline'], context['target']), (before, after)):
        at = int(spec['response'], 16)
        normalized, identity = shared.response_crt(native, imports, decoder, image, functions[at], shapes[at], 1298)
        shapes[at] = dict(shapes[at], shape=normalized)
        crt.append(identity)
    pairs = []
    for role in ('request', 'response'):
        prior, current = int(context['baseline'][role], 16), int(context['target'][role], 16)
        old, new = before[2][prior], after[2][current]
        if old['shape'] != new['shape']:
            raise ValueError('Fetch complete instruction/local-control shape changed: ' + role)
        pairs.append(dict(role=role, baseline=hex(prior), target=hex(current),
            instruction_count=len(new['shape']), calls=[dict(baseline=a, target=b) for a,b in zip(old['calls'],new['calls'])],
            references=[dict(baseline=a,target=b) for a,b in zip(old['references'],new['references'])]))
    spec = verify_contract(context, after[0], after[1], after[2], shared)
    fragment = verify_fragment(native, shared, after[0], context['scope_initializer'])
    reuse = {}
    for label, pointer in context['reuse'].items():
        proof = json.loads(checked(path_at(root, pointer['path']), pointer['sha256'], inputs))
        if proof.get('source_sha256') != SOURCE:
            raise ValueError('Fetch shared proof source differs')
        reuse[label] = proof
    launcher = reuse['launcher']
    route = next(row for row in launcher['requests'] if row['endpoint'] == 'launcher/token')
    keys = {row['key']: row for row in launcher['keys']}
    if (route['transport'] != spec['transport'] or route['header_reference'] != spec['auth_literal']
            or any(keys[key]['global_address'] != spec[field] for key,field in (
                ('credential','credential_global'),('errorCode','error_global'),('resultData','result_global')))):
        raise ValueError('Fetch existing Launcher transport/key linkage differs')
    shared_calls = {row['target']['target'] for function in launcher['unresolved_dependencies'] for row in function['calls']}
    if not {spec[name] for name in ('transport','object_builder','serializer','auth_getter','object_getter')} <= shared_calls:
        raise ValueError('Fetch shared implementation link is absent from Launcher evidence')
    primitives = reuse['sdk_native']
    if (primitives.get('native_case_executions') != 3667 or primitives.get('network_used') is not False
            or primitives.get('runtime_admitted') is not False
            or primitives.get('primitive_cases') != dict(channels=176, numeric=112)):
        raise ValueError('Fetch SDK native proof state differs')
    for name in ('inspect-sdk-fetch-current', 'build-native-entry-code', 'extract-native-enums',
                 'audit-launcher-shape-11318', 'audit-launcher-contract', 'build-object-zero-init-code', 'knowledge-index'):
        path = HERE / (name + '.py')
        inputs[str(path.resolve())] = hashlib.sha256(path.read_bytes()).hexdigest()
    # Final fresh endpoint SHA barrier: report never approves a changing source.
    for name, digest in inputs.copy().items(): checked(Path(name), digest, {})
    return dict(schema=1, recipe=RECIPE, producer='sdk-fetch-current-contract-v1',
        operation='v1/fetch-player', read_only=True, source_sha256=SOURCE, baseline_sha256=BASELINE,
        method='static', contract_subset_verified=True, native_execution=False, network_used=False,
        runtime_admitted=False, profile_activated=False, inputs=inputs, functions=pairs,
        scope_initializer=fragment, crt=crt,
        contract=dict(endpoint=spec['endpoint'], method='POST', payload_keys=['credential','scope'],
            scope='channel', credential_channel=33, device_fields_in_body=False,
            transport=spec['transport'], auth_config_key='authUrl', shared_headers=['gameCode','buildCode'],
            response_subset='Local strict zero errorCode and object resultData; no SDK token/player/session'),
        closure=dict(subset='read-only Fetch request and bounded local response policy',
            blockers=[], native_wide_unknowns=[
                'Credential virtual provider and JSON object/serialization implementations are linked to existing evidence, not executed here.',
                'Native nested result identity, error objects, callback lifetime and dispatcher are not reproduced by the local summary parser.',
                'Scope initializer proves an explicit 39-byte fragment only; CRT cleanup target is not executed or whole-exported.']),
        evidence=[dict(path=name, sha256=digest) for name,digest in inputs.items()
                  if Path(name).is_relative_to(root)], reuse=context['reuse'], limits=[
            'This static contract does not grant admission. The runtime owner must validate its separate Fetch-only profile and all retained SDK inputs.',
            'No SignUp, Terms, direct SignIn, launcher Fetch, lobby, creation or world capability.',
            'Whole functions and explicit data/argument windows are checked; shared SDK proofs remain within their original fixture boundaries.'])


def build_report(context_path, root):
    context_path = Path(context_path).resolve()
    if context_path.stat().st_size > 1048576:
        raise ValueError('Fetch context exceeds budget')
    raw = context_path.read_bytes()
    report = audit(json.loads(raw), root)
    if context_path.read_bytes() != raw: raise ValueError('Fetch context changed during audit')
    digest = hashlib.sha256(raw).hexdigest()
    report['inputs'][str(context_path)] = digest
    report['context'] = dict(path=str(context_path), sha256=digest)
    return report


def verify_report(report_path, *, root=Path('F:/PhoneExit Resources/Vampir'), workspace=HERE.parents[3]):
    """Rebuild the static audit before a Fetch-only package is published.

    Runtime admission must use pinned inputs; it must not import this analyzer.
    """
    root, workspace, report_path = Path(root).resolve(), Path(workspace).resolve(), Path(report_path).resolve()
    if (workspace / 'phone-exit/bots/resource-tools/vampir').resolve() != HERE:
        raise ValueError('Fetch inspector workspace differs')
    if (not report_path.is_relative_to(root / 'code-clues/sdk-fetch-current-static-v1')
            or report_path.name != 'manifest.json' or report_path.stat().st_size > 32 * 1024 * 1024):
        raise ValueError('Fetch report path or budget differs')
    raw = report_path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if report_path != root / 'code-clues/sdk-fetch-current-static-v1' / digest / 'manifest.json':
        raise ValueError('Fetch report content-addressed path differs')
    report = json.loads(raw)
    context_path = (workspace / 'phone-exit/bots/resource-tools/vampir/knowledge/native-contexts/sdk-fetch-current.json').resolve()
    pointer = report.get('context', {})
    if (pointer.get('path') != str(context_path) or report.get('inputs', {}).get(str(context_path)) != pointer.get('sha256')
            or hashlib.sha256(context_path.read_bytes()).hexdigest() != pointer.get('sha256')):
        raise ValueError('Fetch report context pointer differs')
    expected = build_report(context_path, root)
    if expected != report or report_path.read_bytes() != raw:
        raise ValueError('Fetch report no longer matches the complete source audit')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--context', type=Path, default=HERE / 'knowledge/native-contexts/sdk-fetch-current.json')
    args = parser.parse_args()
    report = build_report(args.context, args.root)
    target = load('audit-client-release').save_snapshot(args.root / 'code-clues/sdk-fetch-current-static-v1', report)
    print(json.dumps(dict(report=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                          contract_subset_verified=True, native_execution=False, runtime_admitted=False)))


if __name__ == '__main__': main()
