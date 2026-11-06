"""Generate immutable CharacterList contexts and ordinary reviewed replay files."""
import argparse
import ast
import copy
from functools import lru_cache
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct


HERE = Path(__file__).resolve().parent
NAMES = ('waiting-end', 'character-list-envelope', 'character-record',
         'character-extensions', 'character-list-records', 'character-list-handler')
CATEGORY = 'character-list-current-generated'
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
BASELINE = 'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'


@lru_cache(None)
def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def document(pointer):
    path = Path(pointer['path']).resolve()
    raw = path.read_bytes()
    if set(pointer) != {'path', 'sha256'} or len(raw) > 32 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != pointer['sha256']:
        raise ValueError('CharacterList input pointer differs')
    return json.loads(raw)


def objects(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from objects(child)


class Generator:
    def __init__(self, root, plan_path, export_paths):
        self.root = Path(root).resolve()
        self.plan_path = Path(plan_path).resolve()
        self.plan = document(dict(path=str(self.plan_path), sha256=digest(self.plan_path)))
        if self.plan.get('recipe') != 'character-list-current-plan-v1' or self.plan.get('root_count') != 40:
            raise ValueError('CharacterList plan recipe or root set differs')
        self.old, self.new = (self.plan[name] for name in ('baseline_sha256', 'source_sha256'))
        if (self.old, self.new) != (BASELINE, SOURCE):
            raise ValueError('CharacterList reviewed source pair differs')
        self.inputs = {str(self.plan_path): digest(self.plan_path)}
        discovery = document(self.plan['discovery'])
        resize = document(self.plan['constrained_resize'])
        document(self.plan['baseline_native'])
        self.inputs[self.plan['baseline_native']['path']] = self.plan['baseline_native']['sha256']
        self.inputs.update(discovery['inputs'])
        self.inputs.update(resize['inputs'])
        self.inputs[self.plan['discovery']['path']] = self.plan['discovery']['sha256']
        self.inputs[self.plan['constrained_resize']['path']] = self.plan['constrained_resize']['sha256']
        self.mapping = {}
        for at, values in discovery['links'].items():
            if len(values) == 1:
                self.add(int(at, 16), int(values[0], 16))
        for at, value in resize['links'].items():
            self.add(int(at, 16), int(value, 16))
        self.contexts = {name: document(self.plan['baseline_contexts'][name]) for name in NAMES}
        for pointer in self.plan['baseline_contexts'].values():
            self.inputs[pointer['path']] = pointer['sha256']
        for name in ('generate-character-list-current.py', 'verify-character-list-current.py',
                     'update-native-harness.py', 'build-native-entry-code.py', 'extract-native-enums.py',
                     'update-native-contexts.py', 'result-gate-transfer-rules.py', 'research-workflow.py'):
            path = HERE / name
            self.inputs[str(path)] = digest(path)
        self.native = load('build-native-entry-code')
        self.signature = load('update-native-contexts').signature
        self.images = {}
        for sha in (self.old, self.new):
            path = self.root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'
            if digest(path) != sha:
                raise ValueError('CharacterList source snapshot SHA differs')
            self.inputs[str(path)] = sha
            self.images[sha] = self.native.Image(path.read_bytes())
        self.decoder = self.native.capstone.Cs(self.native.capstone.CS_ARCH_X86, self.native.capstone.CS_MODE_64)
        self.decoder.detail = True
        self.fragments = {}
        for sha, image in self.images.items():
            self.fragments[sha] = {}
            for fragment, entry in image.roots.items():
                self.fragments[sha].setdefault(entry, []).append(fragment)
        self.calls = {}
        self.gate = document(self.plan['shared_gate']['context'])
        gate_check = document(self.plan['shared_gate']['check'])
        input_context = document(self.plan['shared_input']['context'])
        input_check = document(self.plan['shared_input']['check'])
        if self.gate['source_sha256'] != self.new or gate_check['source_sha256'] != self.new:
            raise ValueError('CharacterList shared gate source differs')
        if input_context['source_sha256'] != self.new or input_check['source_sha256'] != self.new:
            raise ValueError('CharacterList shared input source differs')
        self.inputs.update({p['path']: p['sha256'] for p in (
            self.plan['shared_gate']['context'], self.plan['shared_gate']['check'],
            self.plan['shared_input']['context'], self.plan['shared_input']['check'])})
        self.exports, self.functions = {}, {}
        paths = set(map(Path, export_paths))
        for choices in self.plan['ready_exports'].values():
            paths.add(Path(choices[0]['path']))
        for run in self.gate['exports']:
            paths.add(self.root / 'ghidra/request-exports' / self.new / run / 'details.json')
        for path in sorted(paths):
            self.read_export(path)

    def add(self, before, after):
        if before in self.mapping and self.mapping[before] != after:
            raise ValueError('CharacterList inconsistent relocation edge ' + hex(before))
        self.mapping[before] = after

    def read_export(self, path):
        path = path.resolve()
        if path.parent.parent != self.root / 'ghidra/request-exports' / self.new or path.name != 'details.json':
            raise ValueError('CharacterList export outside target source')
        receipt = path.parent / 'provenance.json'
        provenance = json.loads(receipt.read_bytes())
        expected = provenance.get('files', {}).get('details.json')
        if provenance.get('source_sha256') != self.new or digest(path) != expected:
            raise ValueError('CharacterList export provenance differs')
        self.inputs[str(path)] = expected
        self.inputs[str(receipt)] = digest(receipt)
        report = json.loads(path.read_bytes())
        if report['new_source_sha256'] != self.new:
            raise ValueError('CharacterList export source differs')
        self.exports[path.parent.name] = expected
        for function in report['functions']:
            address = int(function['address'], 16)
            if address in self.functions:
                if self.functions[address]['instructions'] != function['instructions']:
                    raise ValueError('Conflicting target CharacterList exports')
                continue
            self.functions[address] = function

    def data(self, sha, address, size):
        return load('update-native-contexts').image_bytes(self.images[sha], address, size)

    def decode(self, raw, address):
        rows = []
        for ins in self.decoder.disasm(raw, address):
            call = ins.group(self.native.capstone.CS_GRP_CALL)
            branch = ins.group(self.native.capstone.CS_GRP_JUMP)
            target = ins.operands[0].imm if (call or branch) and ins.operands[0].type == self.native.X86_OP_IMM else None
            rows.append(dict(address=ins.address, bytes=bytes(ins.bytes).hex(), call=call, branch=branch,
                direct_target=target, mnemonic=ins.mnemonic, operands=ins.op_str,
                rip_references=[ins.address + ins.size + op.mem.disp for op in ins.operands
                                if op.type == self.native.X86_OP_MEM and op.mem.base == self.native.X86_REG_RIP]))
        if sum(len(bytes.fromhex(row['bytes'])) for row in rows) != len(raw):
            raise ValueError('CharacterList code has an instruction gap')
        return rows

    def rows(self, sha, address):
        image = self.images[sha]
        part = image.containing(address)
        if part is None or image.pe.base + image.roots[part][0] != address:
            raise ValueError('CharacterList selected address is not an unwind root')
        root = image.roots[part]
        return [row for fragment in self.native.decode_ranges(image, {root}, functions=self.fragments[sha][root])
                for row in fragment['instructions']]

    def pair(self, before, after):
        if self.signature(self.native, before) != self.signature(self.native, after):
            raise ValueError('CharacterList whole or bounded instruction shape differs')
        for old, new in zip(before, after):
            self.add(old['address'], new['address'])
            if len(old['rip_references']) != len(new['rip_references']):
                raise ValueError('CharacterList RIP reference arity differs')
            for a, b in zip(old['rip_references'], new['rip_references']):
                self.add(a, b)
            if old['direct_target'] is not None:
                self.add(old['direct_target'], new['direct_target'])
            if old['call']:
                self.calls[old['address']] = (new['address'], hex(new['direct_target']) if new['direct_target'] is not None else new['operands'])

    def address(self, value):
        address = int(value, 16)
        if address not in self.mapping:
            raise ValueError('Unmapped CharacterList address ' + value)
        return hex(self.mapping[address])

    def registration(self):
        current = json.loads((HERE / 'knowledge/native-contexts/version-result-flow-11322.json').read_bytes())
        if current['source_sha256'] != self.new:
            raise ValueError('Current registration owner proof source differs')
        owner = int(current['registration']['owner'], 16)
        self.inputs[str(HERE / 'knowledge/native-contexts/version-result-flow-11322.json')] = digest(
            HERE / 'knowledge/native-contexts/version-result-flow-11322.json')
        image = self.images[self.new]
        windows = {}
        owner_rows = self.rows(self.new, owner)
        for name in ('waiting-end', 'character-list-handler'):
            context = self.contexts[name]
            window = context['registration']
            old = int(window['address'], 16)
            old_owner = int(window['owner'], 16)
            self.add(old_owner, owner)
            payload = bytes.fromhex(window['bytes'])
            if self.data(self.old, old, len(payload)) != payload:
                raise ValueError('Historical CharacterList registration bytes differ')
            before = self.decode(payload, old)
            desired = self.signature(self.native, before)
            guessed = owner + old - old_owner
            choices = []
            for row in owner_rows:
                at = row['address']
                if abs(at - guessed) > 4096 or self.data(self.new, at, 4) != payload[:4]:
                    continue
                try:
                    after = self.decode(self.data(self.new, at, len(payload)), at)
                except ValueError:
                    continue
                if self.signature(self.native, after) != desired:
                    continue
                old_table = int(context['bindings']['handler_table'], 16)
                old_handler = int(context['functions']['handler'], 16)
                candidates = [ref for old_row, new_row in zip(before, after)
                              for a, ref in zip(old_row['rip_references'], new_row['rip_references']) if a == old_table]
                if len(candidates) != 1 or struct.unpack('<Q', self.data(self.new, candidates[0] + 16, 8))[0] != self.mapping[old_handler]:
                    continue
                choices.append((at, after))
            if len(choices) != 1:
                raise ValueError('Missing or ambiguous CharacterList registration window ' + name)
            at, after = choices[0]
            self.pair(before, after)
            windows[window['address']] = dict(address=hex(at), owner=hex(owner),
                bytes=self.data(self.new, at, len(payload)).hex(),
                register=hex(after[-1]['direct_target']),
                instructions=[(hex(row['address']), row['mnemonic'], row['operands']) for row in after])
        return windows

    def complete_links(self):
        gate_old = int(self.contexts['character-list-handler']['functions']['gate'], 16)
        gate_rows = load('result-gate-transfer-rules').rows(self.native, self.images[self.new], self.gate)
        for before, after in zip(self.contexts['character-list-handler']['call_sites']['gate'].items(),
                                 [row for row in gate_rows if row['call']]):
            at, target = before
            self.calls[int(at, 16)] = (after['address'], hex(after['direct_target']) if after['direct_target'] is not None else after['operands'])
            if target.startswith('0x'):
                self.add(int(target, 16), after['direct_target'])
        for role in ('gate_state', 'gate_error'):
            before = self.contexts['character-list-handler']['fixtures'][role]
            self.add(int(before, 16), int(self.gate['fixtures'][role], 16))
        self.add(gate_old, int(self.gate['function'], 16))
        for before, after in self.plan['shared_input']['leaves'].items():
            self.add(int(before, 16), int(after, 16))
        items = [item for context in self.contexts.values() for item in objects(context)]
        leaves = {int(at, 16): spec['bytes'] if isinstance(spec, dict) else spec
                  for item in items for at, spec in item.get('leaves', {}).items()}
        blocks = {int(block['address'], 16): block for item in items for block in item.get('blocks', [])}
        packet = int(self.contexts['character-list-envelope']['bindings']['packet_table'], 16)
        notify = int(self.contexts['waiting-end']['bindings']['notify_table'], 16)
        while leaves or blocks:
            for table in (packet, notify):
                if table in self.mapping:
                    self.add(table + 0x50, self.mapping[table] + 0x50)
            ready_blocks = [at for at in blocks if at in self.mapping]
            ready_leaves = [at for at in leaves if at in self.mapping]
            if not ready_blocks and not ready_leaves:
                raise ValueError('Unmapped CharacterList leaf/table closure ' + ','.join(hex(at) for at in (*blocks, *leaves)))
            for at in ready_blocks:
                block = blocks.pop(at)
                old = bytes.fromhex(block['bytes'])
                if self.data(self.old, at, len(old)) != old or hashlib.sha256(old).hexdigest() != block['sha256']:
                    raise ValueError('Historical CharacterList table bytes differ')
                new = self.data(self.new, self.mapping[at], len(old))
                if at in (packet + 0x50, notify + 0x50):
                    if old != new:
                        raise ValueError('CharacterList packet name differs')
                    continue
                for offset in range(0, len(old) - len(old) % 8, 8):
                    a, b = (struct.unpack_from('<Q', raw, offset)[0] for raw in (old, new))
                    if 0x140000000 <= a < 0x150000000:
                        self.add(a, b)
                    elif a != b:
                        raise ValueError('CharacterList non-pointer table data differs')
            for at in ready_leaves:
                raw = bytes.fromhex(leaves.pop(at))
                if self.data(self.old, at, len(raw)) != raw:
                    raise ValueError('Historical CharacterList leaf bytes differ')
                self.pair(self.decode(raw, at), self.decode(self.data(self.new, self.mapping[at], len(raw)), self.mapping[at]))

    def run(self):
        for before, after in self.plan['roots'].items():
            old, new = int(before, 16), int(after, 16)
            if old == int(self.contexts['character-list-handler']['functions']['gate'], 16):
                continue
            self.pair(self.rows(self.old, old), self.rows(self.new, new))
            function = self.functions.get(new)
            if function is None or not all(function.get(field) is True for field in (
                    'decompilation_completed', 'block_coverage_complete', 'direct_flow_coverage_complete')):
                raise ValueError('Current CharacterList root export missing or incomplete ' + hex(new))
            if {int(row['address'], 16): row['bytes'] for row in function['instructions']} != {
                    row['address']: row['bytes'] for row in self.rows(self.new, new)}:
                raise ValueError('Current CharacterList export differs from complete native code')
        windows = self.registration()
        self.complete_links()
        generated = {}

        def payload(at, raw):
            return self.data(self.new, int(self.address(at), 16), len(bytes.fromhex(raw)))

        def convert(value, key=None, parent=None):
            if key == 'source_sha256':
                return self.new
            if key == 'source':
                return str(self.root / 'client-code-snapshots' / self.new / 'ProjectRED-Win64-Shipping.exe')
            if key == 'exports':
                return self.exports
            if key == 'table_bytes':
                if self.data(self.old, int(parent['table'], 16), len(bytes.fromhex(value))).hex() != value:
                    raise ValueError('Historical CharacterList input table bytes differ')
                return payload(parent['table'], value).hex()
            if key == 'leaves':
                result = {}
                for at, spec in value.items():
                    raw = payload(at, spec['bytes'] if isinstance(spec, dict) else spec)
                    result[self.address(at)] = dict(bytes=raw.hex(), sha256=hashlib.sha256(raw).hexdigest()) if isinstance(spec, dict) else raw.hex()
                return result
            if key == 'blocks':
                return [dict(address=self.address(item['address']), bytes=(raw := payload(item['address'], item['bytes'])).hex(),
                             sha256=hashlib.sha256(raw).hexdigest()) for item in value]
            if key == 'registration':
                return windows[value['address']]
            if key == 'call_sites':
                if value and not next(iter(value)).startswith('0x'):
                    return {name: convert(item, 'call_sites') for name, item in value.items()}
                return {hex(self.calls[int(at, 16)][0]): dict(target=self.calls[int(at, 16)][1])
                        if isinstance(item, dict) else self.calls[int(at, 16)][1] for at, item in value.items()}
            if key and key.endswith('_bytes'):
                raise ValueError('Undeclared CharacterList byte field ' + key)
            if isinstance(value, dict):
                if any(re.fullmatch('0x[0-9a-fA-F]+', name) for name in value):
                    raise ValueError('Undeclared CharacterList address map ' + str(key))
                return {name: convert(item, name, value) for name, item in value.items()}
            if isinstance(value, list):
                return [convert(item) for item in value]
            if isinstance(value, str) and re.fullmatch('0x[0-9a-fA-F]+', value):
                return self.address(value)
            return value

        for name, context in self.contexts.items():
            current = convert(context)
            if name == 'character-list-handler':
                current['switch_gate'] = 'result-gate-current'
                current['current_gate'] = self.gate
            else:
                current['verify_whole_exports'] = True
            generated[name] = current
        for path, sha in self.inputs.items():
            if digest(path) != sha:
                raise ValueError('CharacterList selected input changed before generation')
        return generated


def source_files(generator, directory):
    """Generate reviewed variants once, preserving every scenario body."""
    sources = {}
    templates = ['verify-' + name + '-context.py' for name in NAMES]
    harness_path = HERE / 'update-native-harness.py'
    generator.inputs[str(harness_path)] = digest(harness_path)
    tree = ast.parse(harness_path.read_bytes())
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'make_harness')
    first = next(i for i, node in enumerate(function.body) if isinstance(node, ast.Assign)
                 and any(isinstance(target, ast.Name) and target.id == 'budget' for target in node.targets))
    last = next(i for i, node in enumerate(function.body) if isinstance(node, ast.For)
                and isinstance(node.iter, ast.Call) and ast.unparse(node.iter) == 'exports.items()')
    function.body[first:last] = ast.parse("admitted = None").body
    sources['native-harness.py'] = ast.unparse(tree) + '\n'
    for name in templates:
        path = HERE / name
        generator.inputs[str(path)] = digest(path)
        tree = ast.parse(path.read_bytes())
        class Port(ast.NodeTransformer):
            def visit_Assign(self, node):
                if any(isinstance(target, ast.Name) and target.id == 'HERE' for target in node.targets):
                    node.value = ast.Call(func=ast.Name(id='Path', ctx=ast.Load()), args=[ast.Constant(str(HERE))], keywords=[])
                    return node
                return self.generic_visit(node)
            def visit_Constant(self, node):
                if node.value == 'update-native-harness':
                    return ast.copy_location(ast.Constant('verify-character-list-current'), node)
                return node
            def visit_IfExp(self, node):
                # Only the historical registration target selector changes;
                # the complete 75-byte window and argument sequence stay checked.
                if (isinstance(node.body, ast.Constant) and node.body.value == '0x1467cbb90'
                        and isinstance(node.orelse, ast.Constant) and node.orelse.value == '0x1467cb6c0'):
                    return ast.copy_location(ast.parse("context['registration']['register']", mode='eval').body, node)
                return self.generic_visit(node)
        tree = Port().visit(tree)
        if name == 'verify-character-list-handler-context.py':
            verify = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'verify')
            selected = next(node for node in verify.body if isinstance(node, ast.If) and ast.unparse(node.test) == 'switch')
            selected.body = ast.parse("""if switch != 'result-gate-current':
    raise ValueError('Unreviewed CharacterList current gate')
gate_module = load('result-gate-transfer-rules')
gate_module.export_coverage(root, context['current_gate'], native, None, h.image)
""").body
            class GateCalls(ast.NodeTransformer):
                def visit_Call(self, node):
                    node = self.generic_visit(node)
                    if ast.unparse(node.func) == 'gate_module.rows':
                        node.args[-1] = ast.parse("context['current_gate']", mode='eval').body
                    return node
            tree = GateCalls().visit(tree)
        ast.fix_missing_locations(tree)
        sources[name] = ast.unparse(tree) + '\n'
    for name, text in sources.items():
        if name == 'native-harness.py':
            # Its loader resolves shared analysis modules from the repository.
            text = text.replace('HERE = Path(__file__).resolve().parent', 'HERE = Path(' + repr(str(HERE)) + ')')
            sources[name] = text
        compile(text, str(directory / name), 'exec')
    return sources


def run(root, plan, exports):
    generator = Generator(root, plan, exports)
    contexts = generator.run()
    workflow = load('research-workflow')
    # The output path includes every source/context/export and verifier input.
    for name in ['verify-' + value + '-context.py' for value in NAMES]:
        generator.inputs[str(HERE / name)] = digest(HERE / name)
    for name in ('update-bindings.py', 'audit-launcher-shape-11318.py', 'knowledge-index.py',
                 'build-object-zero-init-code.py', 'character-list-storage-fixtures.py',
                 'login-result-string-fixtures.py', 'version-system-transfer-rules.py',
                 'update-native-archive-wire.py', 'requirements-native.txt'):
        generator.inputs[str(HERE / name)] = digest(HERE / name)
    for name in ('character_list.py', 'login_result.py'):
        path = HERE.parents[1] / 'vampir-shared/vampir_core' / name
        generator.inputs[str(path)] = digest(path)
    definition = dict(schema=1, recipe=CATEGORY, source_sha256=generator.new,
                      baseline_sha256=generator.old, inputs=generator.inputs)
    key = hashlib.sha256(workflow.canonical(definition)).hexdigest()
    directory = generator.root / 'knowledge/character-list-current-code' / key
    sources = source_files(generator, directory)
    if definition['inputs'] != generator.inputs:
        raise ValueError('CharacterList generator omitted a producer input')
    scopes = {}
    for name, context in contexts.items():
        if name == 'character-record':
            roots = set(context['functions'].values()) | set(context['native_input']['functions'].values())
            leaves = {**context['native_input']['leaves'], **context['leaves']}
        elif name == 'character-extensions':
            roots = set(context['input_functions'].values())
            for values in context['components'].values():
                roots.update(values.values())
            leaves = context['leaves']
        else:
            roots = set(context['functions'].values())
            leaves = context['leaves']
        scopes[name] = dict(roots=sorted(roots), leaves={at: item['bytes'] if isinstance(item, dict) else item
                                                       for at, item in leaves.items()})
        if name == 'character-extensions':
            scopes[name]['variants'] = {kind: sorted(set(context['input_functions'].values()) | set(values.values()))
                                       for kind, values in context['components'].items()}
    scope = dict(definition, scopes=scopes, roots=generator.plan['roots'], links={hex(a): hex(b) for a, b in generator.mapping.items()},
                 runtime_admitted=False, semantic_verification=False)
    scope_path = workflow.snapshot(generator.root, 'character-list-current-scopes', scope)
    harness_data = sources['native-harness.py'].encode()
    harness = dict(path=str(directory / 'native-harness.py'), sha256=hashlib.sha256(harness_data).hexdigest())
    files = {}
    for name, text in sources.items():
        files[directory / name] = text.encode()
    for name, context in contexts.items():
        context['current_character_scope'] = dict(path=str(scope_path), sha256=digest(scope_path), name=name)
        context['current_character_harness'] = harness
        files[directory / (name + '.json')] = workflow.canonical(context)
    directory.mkdir(parents=True, exist_ok=True)
    for path, data in files.items():
        try:
            with path.open('xb') as stream:
                stream.write(data)
        except FileExistsError:
            if path.read_bytes() != data:
                raise ValueError('Immutable CharacterList output differs')
    for path, sha in generator.inputs.items():
        if digest(path) != sha:
            raise ValueError('CharacterList input changed during publication')
    report = dict(definition, files={str(path): hashlib.sha256(data).hexdigest() for path, data in files.items()},
                  contexts={name: str(directory / (name + '.json')) for name in NAMES},
                  verifiers={name: str(directory / ('verify-' + name + '-context.py')) for name in NAMES},
                  scope=dict(path=str(scope_path), sha256=digest(scope_path)), runtime_admitted=False,
                  semantic_verification=False, network_used=False)
    path = workflow.snapshot(generator.root, CATEGORY, report)
    return path, report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--export', type=Path, action='append', default=[])
    args = parser.parse_args()
    path, report = run(args.root, args.plan, args.export)
    print(json.dumps(dict(report=str(path), contexts=len(report['contexts']))))
