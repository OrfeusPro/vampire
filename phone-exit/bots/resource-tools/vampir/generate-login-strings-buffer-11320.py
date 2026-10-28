"""Generate an explicit current string/buffer context from reviewed source links."""
import json
import re
import struct
from pathlib import Path
from importlib.util import spec_from_file_location, module_from_spec

HERE = Path(__file__).resolve().parent
ALIGNMENT = '99974a080331ea0ab6ad3bfecf1a173a7ee65f3b308f0be1c58691f9222e4d07'


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def generate(root):
    d = load('discover-login-result-11320')
    path = root / 'knowledge/login-batch-alignment-11320' / ALIGNMENT / 'manifest.json'
    alignment = json.loads(path.read_bytes())
    if d.digest(path) != ALIGNMENT or alignment['source_sha256'] != d.SOURCE or d.digest(HERE / 'align-login-batch-11320.py') != alignment['tool_sha256']:
        raise ValueError('String context alignment identity changed')
    for name, sha in alignment['inputs'].items():
        if d.digest(name) != sha:
            raise ValueError('String context alignment input changed')
    old_path = HERE / 'knowledge/native-contexts/login-result-buffer-11318.json'
    old = json.loads(old_path.read_bytes())['native_input']
    source = root / 'client-code-snapshots' / d.SOURCE / 'ProjectRED-Win64-Shipping.exe'
    raw = source.read_bytes()
    if d.digest(source) != d.SOURCE:
        raise ValueError('String context source changed')
    image = load('build-native-entry-code').Image(raw)
    links = alignment['links'].copy()

    def mapped(at):
        values = links.get(at, [])
        if len(values) != 1:
            raise ValueError('Missing/ambiguous string context reference ' + at)
        return values[0]

    old_table = bytes.fromhex(old['table_bytes'])
    off = image.offset(int(mapped(old['table']), 16) - image.pe.base)
    table = raw[off:off + len(old_table)]
    for at in old['leaves']:
        if at in links:
            continue
        slots = [i for i in range(0, len(old_table) - 7, 8) if struct.unpack_from('<Q', old_table, i)[0] == int(at, 16)]
        candidates = {hex(struct.unpack_from('<Q', table, i)[0]) for i in slots}
        if len(candidates) != 1:
            raise ValueError('Missing/ambiguous table-linked input leaf')
        target = next(iter(candidates))
        data_off = image.offset(int(target, 16) - image.pe.base)
        data = bytes.fromhex(old['leaves'][at]['bytes'])
        if raw[data_off:data_off + len(data)] != data:
            raise ValueError('Table-linked input thunk changed')
        links[at] = [target]

    def convert(value, key=None):
        if key == 'source_sha256':
            return d.SOURCE
        if key == 'exports':
            return {}
        if key == 'table_bytes':
            return table.hex()
        if key == 'call_sites':
            calls = {}
            for at, spec in value.items():
                target = spec['target']
                match = re.fullmatch(r'qword ptr \[rip ([+-]) (0x[0-9a-f]+)\]', target)
                if match:
                    # FF /2 RIP-relative indirect CALL is six bytes. Relocate
                    # the reviewed import-slot link, not its textual displacement.
                    old_slot = int(at, 16) + 6 + (1 if match[1] == '+' else -1) * int(match[2], 16)
                    displacement = int(mapped(hex(old_slot)), 16) - int(mapped(at), 16) - 6
                    target = 'qword ptr [rip ' + ('+ ' if displacement >= 0 else '- ') + hex(abs(displacement)) + ']'
                else:
                    target = mapped(target) if target.startswith('0x') else target
                calls[mapped(at)] = dict(target=target)
            return calls
        if key == 'leaves':
            return {mapped(at): dict(bytes=raw[image.offset(int(mapped(at), 16) - image.pe.base):image.offset(int(mapped(at), 16) - image.pe.base) + len(bytes.fromhex(spec['bytes']))].hex()) for at, spec in value.items()}
        if isinstance(value, dict):
            return {(mapped(k) if k.startswith('0x') else k): convert(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [convert(v) for v in value]
        if isinstance(value, str) and re.fullmatch('0x[0-9a-f]+', value):
            return mapped(value)
        return value

    ni = convert(old)
    context = json.loads((HERE / 'knowledge/native-contexts/login-input-11320.json').read_bytes())
    context.update(input=ni, native_strings=True, function_budget=20, budget_scope='login-result-buffer')
    context['leaves'].update({at: spec['bytes'] for at, spec in ni['leaves'].items()})
    wanted = set(ni['functions'].values()) | set(context['functions'].values())
    context['exports'] = {}
    for run in ('run-cc90e4f503ac', 'run-cd7653218083', 'run-85faf6d508b5'):
        export = root / 'ghidra/request-exports' / d.SOURCE / run / 'details.json'
        data = json.loads(export.read_bytes())
        found = {f['address'] for f in data['functions'] if f.get('decompilation_completed')}
        if wanted & found:
            context['exports'][run] = d.digest(export)
            wanted -= found
    if wanted:
        raise ValueError('String context exports missing')
    context['provenance'] = dict(alignment_sha256=ALIGNMENT, baseline_context_sha256=d.digest(old_path))
    return context


if __name__ == '__main__':
    result = generate(Path('F:/PhoneExit Resources/Vampir'))
    target = HERE / 'knowledge/native-contexts/login-strings-buffer-11320.json'
    target.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(target)
