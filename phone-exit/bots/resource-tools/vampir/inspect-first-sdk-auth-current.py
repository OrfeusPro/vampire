"""Source-bound static SignUp/direct SignIn subset; no network or native replay."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/first-sdk-auth-current.json'
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
RECIPE = 'first-sdk-auth-current-v1'
OWNER_KEYS = {0x20: 'playerInfo', 0x28: 'player', 0x30: 'playerId', 0x38: 'playerStatus',
              0x40: 'gameRegion', 0x48: 'idpInfo', 0x50: 'joinedCountryCode'}
BODY_KEYS = ('nmDeviceKey', 'deviceKey', 'countryCode', 'os', 'credential')


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def checked(path, sha, inputs):
    path = Path(path).resolve(); raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != sha: raise ValueError('First SDK auth input changed: ' + path.name)
    inputs[str(path)] = sha
    return raw


def data(image, at, size):
    offset = image.offset(at - image.pe.base)
    if image.offset(at + size - 1 - image.pe.base) != offset + size - 1:
        raise ValueError('First SDK auth file-backed range differs')
    return image.data[offset:offset + size]


def owner_keys(native, decoder, image, fragment):
    at, raw = int(fragment['address'], 16), bytes.fromhex(fragment['bytes'])
    if len(raw) != 403 or data(image, at, len(raw)) != raw:
        raise ValueError('Current auth owner fragment changed')
    rows = list(decoder.disasm(raw, at))
    if (sum(row.size for row in rows) != len(raw) or rows[-1].mnemonic != 'ret'
            or any(row.mnemonic.startswith(('call', 'j')) for row in rows)):
        raise ValueError('Auth owner initializer is not a complete linear leaf')
    from capstone.x86_const import X86_REG_RAX, X86_REG_RCX, X86_OP_REG
    pointer, keys = None, {}
    for row in rows:
        operands = row.operands
        if (row.mnemonic == 'lea' and operands[0].type == X86_OP_REG and operands[0].reg == X86_REG_RAX
                and operands[1].type == native.X86_OP_MEM and operands[1].mem.base == native.X86_REG_RIP):
            pointer = row.address + row.size + operands[1].mem.disp
        if (row.mnemonic == 'mov' and operands[0].type == native.X86_OP_MEM
                and operands[0].mem.base == X86_REG_RCX and operands[1].type == X86_OP_REG
                and operands[1].reg == X86_REG_RAX and operands[0].mem.disp in OWNER_KEYS):
            offset = operands[0].mem.disp
            text = OWNER_KEYS[offset]
            if pointer is None or data(image, pointer, 2 * (len(text) + 1)) != (text + '\0').encode('utf-16le'):
                raise ValueError('Auth owner field name differs')
            if offset in keys: raise ValueError('Auth owner field stored twice')
            keys[offset] = dict(offset=offset, text=text, literal=hex(pointer), store=hex(row.address))
    if set(keys) != set(OWNER_KEYS): raise ValueError('Auth owner keys incomplete')
    return list(keys.values())


def audit(context_path=CONTEXT, *, root=ROOT):
    root, context_path = Path(root).resolve(), Path(context_path).resolve()
    inputs = {}; raw_context = context_path.read_bytes(); context = json.loads(raw_context)
    inputs[str(context_path)] = hashlib.sha256(raw_context).hexdigest()
    if context.get('schema') != 1 or context.get('recipe') != RECIPE or context.get('source_sha256') != SOURCE:
        raise ValueError('Current auth context source differs')
    native, normalize, shared = [load(n) for n in ('build-native-entry-code', 'audit-launcher-shape-11318', 'audit-launcher-contract')]
    source = root / 'client-code-snapshots' / SOURCE / 'ProjectRED-Win64-Shipping.exe'
    image = native.Image(checked(source, SOURCE, inputs))
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64); decoder.detail = True
    roles = context['functions']
    if set(roles) != {'signup_request', 'signup_response', 'signin_request', 'signin_response'}:
        raise ValueError('Auth role declarations differ')
    wanted = {int(at, 16) for at in roles.values()}; functions = {}
    for run, expected in context['exports'].items():
        path = root / 'ghidra/request-exports' / SOURCE / run / 'details.json'
        document = json.loads(checked(path, expected, inputs))
        if document['new_source_sha256'] != SOURCE: raise ValueError('Auth export source differs')
        for f in document['functions']:
            at = int(f['address'], 16)
            if at not in wanted: continue
            if at in functions or f.get('decompilation_completed') is not True:
                raise ValueError('Auth whole export incomplete or duplicated')
            functions[at] = f
    if set(functions) != wanted: raise ValueError('Auth whole export missing')
    shapes = {role: normalize.normalize_function(native, image, functions[int(at, 16)]) for role, at in roles.items()}
    # Reuse the proven current transport and key initializers. Every retained input
    # is copied into the contract so a later profile cannot drop a dependency.
    pointer = context['launcher']
    launcher = json.loads(checked(root / pointer['path'], pointer['sha256'], inputs))
    if launcher.get('source_sha256') != SOURCE: raise ValueError('Auth Launcher proof source differs')
    declared_context = launcher['context']
    old_context = json.loads(checked(Path(declared_context['path']), declared_context['sha256'], inputs))
    for item in launcher['evidence']: checked(Path(item['path']), item['sha256'], inputs)
    for side in ('baseline', 'target'):
        sha = old_context[side]['source_sha256']
        checked(root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe', sha, inputs)
    checked(HERE / 'audit-launcher-contract.py', launcher['tool_sha256'], inputs)
    keys = {row['key']: row['global_address'] for row in launcher['keys']}
    transport = next(row['transport'] for row in launcher['requests'] if row['endpoint'] == 'launcher/token')
    owners = owner_keys(native, decoder, image, context['owner'])
    access = context['access_token_initializer']
    raw = bytes.fromhex(access['bytes']); at = int(access['address'], 16)
    if len(raw) != 39 or data(image, at, len(raw)) != raw: raise ValueError('Auth accessToken initializer changed')
    fragment = dict(address=hex(at), instructions=[dict(address=hex(row.address), bytes=bytes(row.bytes).hex())
        for row in decoder.disasm(raw, at)])
    shared.key_binding(native, decoder, image, fragment, dict(entry=hex(at), global_address=access['global'],
        **{'global': access['global']}, literal=access['literal']), 'accessToken',
        int(access['constructor'], 16), int(access['cleanup'], 16))
    for prefix, suffix in (('signup', 'v1/sign-up'), ('signin', 'v1/sign-in')):
        role = prefix + '_request'; shape = shapes[role]
        refs, calls = {r['target'] for r in shape['references']}, {r['target'] for r in shape['calls']}
        declaration = context['requests'][prefix]
        if not {keys[key] for key in BODY_KEYS} <= refs or transport not in calls:
            raise ValueError('Auth body key or shared POST transport missing')
        for name, value, encoding in (('endpoint_literal', suffix, 'utf-16le'), ('auth_literal', 'authUrl', 'ascii')):
            target = declaration[name]
            if target not in refs or data(image, int(target, 16), len((value + '\0').encode(encoding))) != (value + '\0').encode(encoding):
                raise ValueError('Auth endpoint/config reference changed')
        callback = int(declaration['callback'], 16)
        raw = data(image, callback, 5)
        if (hex(callback) not in refs or raw[0] != 0xe9
                or callback + 5 + struct.unpack_from('<i', raw, 1)[0] != int(roles[prefix + '_response'], 16)):
            raise ValueError('Auth request callback does not reach its response')
        if not set(context['required_calls']['request']) <= calls:
            raise ValueError('Auth body/config/serializer linkage differs')
        response = shapes[prefix + '_response']
        response_refs = {r['target'] for r in response['references']}
        response_calls = {r['target'] for r in response['calls']}
        required_keys = {keys['errorCode'], keys['resultData']}
        if prefix == 'signin': required_keys.add(access['global'])
        if not required_keys <= response_refs or not set(context['required_calls']['response']) <= response_calls:
            raise ValueError('Auth response key/getter linkage differs')
    # Reviewed argument/control windows cover body pairs, credential virtual+8,
    # optional input playerId, callback/transport, HTTP gate and owner-key reads.
    expected_windows = {role + '-' + label: (role, start, end)
        for role in roles for label, start, end in (
            (('body-and-credential', 620, 1338), ('authurl-callback-POST', 1339, 2440))
            if role.endswith('request') else
            (('error-http-and-result', 1000, 1760), ('nested-owner-fields', 1761, 2950)))}
    if set(context['windows']) != set(expected_windows):
        raise ValueError('Auth instruction window coverage is incomplete')
    for label, window in context['windows'].items():
        if (window['role'], window['start'], window['end']) != expected_windows[label]:
            raise ValueError('Auth instruction window coverage differs')
        role = window['role']; rows = functions[int(roles[role], 16)]['instructions']; start = int(roles[role], 16)
        actual = [dict(offset=int(row['address'], 16) - start, bytes=row['bytes']) for row in rows
                  if window['start'] <= int(row['address'], 16) - start <= window['end']]
        if not actual or actual != window['instructions']: raise ValueError('Auth instruction window differs: ' + label)
    for name in ('inspect-first-sdk-auth-current', 'build-native-entry-code', 'extract-native-enums',
                 'audit-launcher-shape-11318', 'audit-launcher-contract'):
        path = HERE / (name + '.py'); inputs[str(path)] = digest(path)
    for name, sha in inputs.copy().items(): checked(Path(name), sha, {})
    if context_path.read_bytes() != raw_context: raise ValueError('Auth context changed during audit')
    return dict(schema=1, recipe=RECIPE, source_sha256=SOURCE, inputs=inputs, method='static',
        contract_subset_verified=True, native_execution=False, network_used=False, runtime_admitted=False,
        functions=[dict(role=role, address=at, instructions=len(shapes[role]['shape'])) for role, at in roles.items()],
        operations=['v1/sign-up', 'v1/sign-in'], body_keys=list(BODY_KEYS), credential_channel=33,
        headers=['gameCode', 'buildCode'], transport=transport, owner_keys=owners,
        response_subset='Strict canonical zero errorCode, nested playerInfo/player/playerId; SignIn also requires nonempty accessToken.',
        limits=['Whole current requests/responses and argument windows are checked statically; native HTTP/JSON/getters are not executed here.',
                'Current Launcher key/POST proof is reused with all inputs; provider/device values come from the admitted fresh context.',
                'Native optional/coercing branches are wider than the local strict parser. No arbitrary extra identity or prior token is accepted.',
                'Owner initialization is a complete linear 403-byte leaf and accessToken initialization an explicit 39-byte fragment; CRT cleanup is not executed.',
                'No account mutation or SDK/world admission follows from this static report alone.'])


def verify_report(path, *, root=ROOT, workspace=HERE.parents[3]):
    root, path, workspace = Path(root).resolve(), Path(path).resolve(), Path(workspace).resolve()
    raw = path.read_bytes(); sha = hashlib.sha256(raw).hexdigest()
    if path != root / 'code-clues' / RECIPE / sha / 'manifest.json': raise ValueError('Auth immutable report path differs')
    report = json.loads(raw)
    context_path = workspace / 'phone-exit/bots/resource-tools/vampir/knowledge/native-contexts/first-sdk-auth-current.json'
    # Static audit is cheap and ensures the complete report and current input set
    # still match the registered contract; no old native suites are rerun.
    current = audit(context_path, root=root)
    if report != current or path.read_bytes() != raw: raise ValueError('Auth report differs from current source contract')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT); parser.add_argument('--context', type=Path, default=CONTEXT)
    args = parser.parse_args(); report = audit(args.context, root=args.root)
    path = load('audit-client-release').save_snapshot(args.root / 'code-clues' / RECIPE, report)
    print(json.dumps(dict(report=str(path), sha256=digest(path), functions=len(report['functions']))))
