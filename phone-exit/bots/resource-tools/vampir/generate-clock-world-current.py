"""Generate source-specific bounded Clock/Ping/world replays from checked links."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
OLD = 'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
SHA = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
PLAN_SHA = 'e78ff91fc8af851687c5955920887b4e26b7a8c417a233996fd30a5140b36705'
RUN_SHA = '8a3e629ec401d80e3d5393249b3c96e21d46bc9d59ad81455b3259b2a7b34c0b'
INPUT_SHA = '6fad7861f8d4b4c6890236ba4b06775c78d5b420d53d86e16b3a0f0259d43a09'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def generate(root=ROOT):
    root = Path(root)
    plan_path = root / 'knowledge/clock-world-current-plan.json'
    if digest(plan_path) != PLAN_SHA:
        raise ValueError('Current Clock/world plan changed')
    plan = json.loads(plan_path.read_bytes())
    if plan['source_sha256'] != SHA or plan['baseline_sha256'] != OLD:
        raise ValueError('Current Clock/world source pair changed')
    native = load('build-native-entry-code')
    raw = (root / 'client-code-snapshots' / SHA / 'ProjectRED-Win64-Shipping.exe').read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA:
        raise ValueError('Current Clock/world EXE changed')
    image = native.Image(raw)

    def data(at, size):
        offset = image.offset(at - image.pe.base)
        result = raw[offset:offset + size]
        if len(result) != size:
            raise ValueError('Source window incomplete')
        return result

    target = plan['target_contexts']
    if any(len(values) != 1 for values in target['links'].values()):
        raise ValueError('Ambiguous Clock/world relocation')
    links = {int(at, 16): int(values[0], 16) for at, values in target['links'].items()}
    links.update({int(at, 16): int(value, 16) for at, value in target['roots'].items()})
    links.update({int(at, 16): int(value['address'], 16) for at, value in target['windows'].items()})
    inp_path = root / 'knowledge/generated-native-contexts' / INPUT_SHA / 'manifest.json'
    if digest(inp_path) != INPUT_SHA:
        raise ValueError('Current native INPUT changed')
    inp_document = json.loads(inp_path.read_bytes())
    inp = inp_document['native_input']
    if inp['source_sha256'] != SHA:
        raise ValueError('Native INPUT source differs')
    for value in plan['shared_native_input']['subset'].values():
        links[int(value['baseline'], 16)] = int(value['target'], 16)
    links.update({int(a, 16): int(b, 16) for a, b in plan['shared_native_input']['leaves'].items()})
    # These callback/memcpy identities are read from the existing current INPUT
    # whole-function call sites. They remain explicit diagnostics/copy fixtures.
    sites = inp['call_sites']
    links.update({0x1487f60d9: int(sites['0x144aac6eb']['target'], 16),
                  0x1445e06f0: int(sites['0x144aac3c6']['target'], 16),
                  0x1445e0720: int(sites['0x144aac5c7']['target'], 16)})

    def address(at):
        if at not in links:
            raise ValueError('Unmapped current address ' + hex(at))
        return links[at]

    replacements = {}
    windows = {}
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    for old_at, item in target['windows'].items():
        at = int(item['address'], 16)
        payload = bytes.fromhex(item['bytes'])
        if data(at, len(payload)) != payload:
            raise ValueError('Current source window changed')
        replacements[item['baseline_bytes']] = item['bytes']
        before = list(decoder.disasm(bytes.fromhex(item['baseline_bytes']), int(old_at, 16)))
        after = list(decoder.disasm(payload, at))
        if len(before) == len(after):
            for a, b in zip(before, after):
                if a.size == b.size:
                    replacements[a.bytes.hex()] = b.bytes.hex()
        windows[hex(at)] = dict(bytes=item['bytes'], sha256=hashlib.sha256(payload).hexdigest())
    tables = {item['address']: item['bytes'] for item in target['tables'].values()}
    for at, encoded in tables.items():
        if data(int(at, 16), len(bytes.fromhex(encoded))) != bytes.fromhex(encoded):
            raise ValueError('Current table source changed')
    system_call = address(0x1415da8c1)
    call_bytes = data(system_call, 6)
    if call_bytes[:2] != b'\xff\x15':
        raise ValueError('Current UTC import call shape differs')
    replacements['ff1561003c07'] = call_bytes.hex()
    windows[hex(system_call)] = dict(bytes=call_bytes.hex(), sha256=hashlib.sha256(call_bytes).hexdigest())
    exports = {'run-4496e2332dcf': RUN_SHA}
    for run, expected in dict(exports, **inp['exports']).items():
        path = root / 'ghidra/request-exports' / SHA / run / 'details.json'
        if digest(path) != expected or json.loads(path.read_bytes())['new_source_sha256'] != SHA:
            raise ValueError('Current ready export changed')

    class Port(ast.NodeTransformer):
        def visit_Constant(self, node):
            value = node.value
            if type(value) is int and 0x140000000 <= value < 0x150000000:
                value = address(value)
            elif isinstance(value, str):
                if value in replacements:
                    value = replacements[value]
                elif value == OLD:
                    value = SHA
                elif value == '488b057993f906c3':
                    value = data(address(0x1445cd6c0), 8).hex()
                elif value == 'Lobby handler receives a synthetic decoded packet; maintenance/manager/tail are fixtures.':
                    value = 'Lobby VersionResult is excluded here and has its own current source proof.'
                else:
                    def replace(match):
                        if match[0] == '1445cd3c0':
                            return match[0]  # Original lineage key, not an executed address.
                        return hex(address(int(match[0], 16)))[2:]
                    if re.search(r'(?<![0-9a-f])1[0-9a-f]{8}(?![0-9a-f])', value):
                        value = re.sub(r'(?<![0-9a-f])1[0-9a-f]{8}(?![0-9a-f])', replace, value)
                    value = value.replace('11318', 'current').replace('1.13.18', 'current SHA')
                    value = value.replace('audit-launcher-shape-current', 'audit-launcher-shape-11318')
                    value = value.replace('character-record-current.json', 'clock-world-native-input-current.json')
                    value = value.replace('ping-world-current.json', 'clock-world-current.json')
            return ast.copy_location(ast.Constant(value), node)

    generated = {}
    for name in ('replay-login-clock', 'replay-login-ping', 'replay-world-entry',
                 'replay-ping-result', 'verify-clock-replay-source', 'verify-ping-world-source'):
        old_path = HERE / (name + '-11318.py')
        tree = ast.parse(old_path.read_text('utf-8'))
        if name == 'replay-login-clock':
            # New lobby VersionResult is independently proved by its own current
            # package; do not execute or preserve the old 26-instruction handler.
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name == 'verify':
                    start = next(i for i, part in enumerate(node.body)
                                 if isinstance(part, ast.Assign) and isinstance(part.targets[0], ast.Tuple)
                                 and isinstance(part.targets[0].elts[0], ast.Name)
                                 and part.targets[0].elts[0].id == 'packet')
                    end = next(i for i, part in enumerate(node.body)
                               if isinstance(part, ast.Assign) and isinstance(part.targets[0], ast.Name)
                               and part.targets[0].id == 'report')
                    node.body[start:end] = ast.parse('lobby_cases = []').body
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Tuple):
                    if isinstance(node.targets[0].elts[0], ast.Name) and node.targets[0].elts[0].id == 'LOBBY_HANDLER':
                        node.value.elts[0] = ast.Constant(0)
                if isinstance(node, ast.Set):
                    node.elts = [v for v in node.elts if not isinstance(v, ast.Name) or v.id != 'LOBBY_HANDLER']
        tree = Port().visit(tree)
        ast.fix_missing_locations(tree)
        text = ast.unparse(tree) + '\n'
        if name == 'verify-clock-replay-source':
            text = text.replace('clock-replays-current.json', 'clock-world-current.json')
        else:
            text = text.replace('clock-replays-current.json', 'clock-world-current.json')
        generated[HERE / (name + '-current.py')] = text

    old_context = json.loads((HERE / 'knowledge/native-contexts/ping-world-11318.json').read_bytes())
    context = dict(schema=1, source_sha256=SHA,
                   source=str(root / 'client-code-snapshots' / SHA / 'ProjectRED-Win64-Shipping.exe'),
                   baseline_sha256=OLD, exports=exports,
                   mapping={a: hex(address(int(b, 16))) for a, b in old_context['mapping'].items()
                            if int(b, 16) in links},
                   functions={a: hex(address(int(b, 16))) for a, b in old_context['functions'].items()},
                   leaves={hex(address(int(a, 16))): data(address(int(a, 16)), len(bytes.fromhex(b))).hex()
                           for a, b in old_context['leaves'].items()},
                   blocks={hex(address(int(a, 16))): data(address(int(a, 16)), len(bytes.fromhex(b))).hex()
                           for a, b in old_context['blocks'].items()},
                   ping=target['ping'], copy_thunk=inp_document['helpers']['memcpy'],
                   windows=windows, tables=tables, network_used=False, profile_activated=False,
                   plan=dict(path=str(plan_path), sha256=PLAN_SHA),
                   native_input=dict(path=str(inp_path), sha256=INPUT_SHA),
                   generation_inputs={str(p): digest(p) for p in [Path(__file__), *[HERE / (n + '-11318.py') for n in
                       ('replay-login-clock', 'replay-login-ping', 'replay-world-entry', 'replay-ping-result',
                        'verify-clock-replay-source', 'verify-ping-world-source')]]})
    context['mapping']['0x1445cd3c0'] = hex(address(0x1445cd6c0))
    for path, text in generated.items():
        compile(text, str(path), 'exec')
        path.write_text(text, encoding='utf-8', newline='\n')
    (HERE / 'knowledge/native-contexts/clock-world-current.json').write_text(json.dumps(context, indent=2) + '\n', encoding='utf-8', newline='\n')
    (HERE / 'knowledge/native-contexts/clock-world-native-input-current.json').write_text(json.dumps(dict(native_input=inp), indent=2) + '\n', encoding='utf-8', newline='\n')
    return dict(files=len(generated), source_sha256=SHA, network_used=False)


if __name__ == '__main__':
    print(json.dumps(generate()))
