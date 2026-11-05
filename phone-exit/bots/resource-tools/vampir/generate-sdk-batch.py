"""Generate ordinary SDK replay files from a pinned template and transfer proof.

AST transformation happens only while generating files. The published Python
files retain the reviewed scenarios and run without an AST adapter.
"""
import argparse
import ast
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import platform
import re
import struct
import sys
import tempfile
import tokenize


HERE = Path(__file__).resolve().parent
RECIPE = 'sdk-batch-generated-v1'
SHA = re.compile('[0-9a-f]{64}')


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def checked(path, expected):
    raw = Path(path).read_bytes()
    if not isinstance(expected, str) or not SHA.fullmatch(expected) or hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('SDK generation input SHA differs: ' + str(path))
    return raw


def pin(inputs, path, expected):
    path = str(Path(path).resolve())
    if path in inputs and inputs[path] != expected:
        raise ValueError('SDK generation input declarations conflict: ' + path)
    inputs[path] = expected


def manifest(path, category):
    path = Path(path).resolve()
    if path.name != 'manifest.json' or path.parent.parent.name != category or not SHA.fullmatch(path.parent.name):
        raise ValueError('SDK generation manifest category differs')
    return json.loads(checked(path, path.parent.name))


def image_bytes(image, address, size):
    if type(size) is not int or not 1 <= size <= 65536:
        raise ValueError('SDK generation byte range exceeds budget')
    start = image.offset(address - image.pe.base)
    end = image.offset(address + size - 1 - image.pe.base)
    if end != start + size - 1:
        raise ValueError('SDK generation byte range crosses sections')
    return image.data[start:end + 1]


def image_bounds(image):
    pe = struct.unpack_from('<I', image.data, 0x3c)[0]
    size = struct.unpack_from('<I', image.data, pe + 24 + 56)[0]
    return image.pe.base, image.pe.base + size


def unique_map(links):
    result = {}
    for before, after in links.items():
        if not re.fullmatch('0x[0-9a-f]+', before) or not isinstance(after, list):
            raise ValueError('SDK transfer address relation differs')
        if len(after) == 1 and isinstance(after[0], str) and re.fullmatch('0x[0-9a-f]+', after[0]):
            result[int(before, 16)] = int(after[0], 16)
    return result


def leaf_replacements(transfer, images, links):
    replacements = {}
    leaves = transfer.get('leaves', [])
    if not isinstance(leaves, list) or len(leaves) != 6:
        raise ValueError('SDK explicit body and boundary leaf set differs')
    for leaf in leaves:
        before = int(leaf['baseline'], 16)
        after = int(leaf['target'], 16)
        size = leaf['size']
        old = image_bytes(images[0], before, size)
        new = image_bytes(images[1], after, size)
        if (links.get(before) != after or old.hex() != leaf['baseline_bytes'] or new.hex() != leaf['target_bytes']
                or hashlib.sha256(old).hexdigest() != leaf['baseline_sha256']
                or hashlib.sha256(new).hexdigest() != leaf['target_sha256']):
            raise ValueError('SDK explicit leaf record differs from source')
        for a, b in ((old.hex(), new.hex()), (hashlib.sha256(old).hexdigest(), hashlib.sha256(new).hexdigest())):
            if a in replacements and replacements[a] != b:
                raise ValueError('SDK leaf byte replacement is ambiguous')
            replacements[a] = b
    return replacements


def exports_for(root, source_sha, paths, image):
    entries, exports, inputs = {}, {}, {}
    folder = (root / 'ghidra/request-exports' / source_sha).resolve()
    for value in paths:
        path = Path(value).resolve()
        if path.name != 'details.json' or path.parent.parent != folder:
            raise ValueError('SDK target export is outside its source folder')
        receipt_path = path.parent / 'provenance.json'
        receipt = json.loads(receipt_path.read_bytes())
        expected = receipt.get('files', {}).get('details.json')
        if receipt.get('source_sha256') != source_sha:
            raise ValueError('SDK target export receipt source differs')
        document = json.loads(checked(path, expected))
        if document.get('new_source_sha256') != source_sha:
            raise ValueError('SDK target export source differs')
        if path.parent.name in exports:
            raise ValueError('Duplicate SDK target export')
        exports[path.parent.name] = expected
        inputs[str(path)] = expected
        inputs[str(receipt_path)] = digest(receipt_path)
        for function in document['functions']:
            address = int(function['address'], 16)
            if address in entries:
                raise ValueError('Duplicate SDK target root export')
            if not all(function.get(key) is True for key in (
                    'decompilation_completed', 'block_coverage_complete', 'direct_flow_coverage_complete')):
                continue
            for row in function['instructions']:
                raw = bytes.fromhex(row['bytes'])
                if image_bytes(image, int(row['address'], 16), len(raw)) != raw:
                    raise ValueError('SDK target export instruction differs from source')
            entries[address] = path.parent.name
    return dict(sorted(exports.items())), entries, inputs


def alias_name(name):
    stem = Path(name).stem
    prefix, _, suffix = stem.rpartition('-')
    return (prefix if suffix.isdigit() else stem) + '.py'


def native_numbers(text, bounds):
    tokens = []
    for token in tokenize.generate_tokens(io.StringIO(text).readline):
        if token.type == tokenize.NUMBER:
            try:
                value = int(token.string, 0)
            except ValueError:
                value = 0
            if bounds[0] <= value < bounds[1]:
                token = token._replace(string=hex(value))
        tokens.append(token)
    return tokenize.untokenize(tokens)


class Port(ast.NodeTransformer):
    def __init__(self, baseline, target, links, replacements, old_exports, exports, names, bounds):
        self.baseline = baseline
        self.target = target
        self.links = links
        self.replacements = replacements
        self.old_exports = old_exports
        self.exports = exports
        self.names = names
        self.bounds = bounds

    def visit_Assign(self, node):
        targets = {target.id for target in node.targets if isinstance(target, ast.Name)}
        if targets == {'HERE'}:
            node.value = ast.Call(func=ast.Name(id='Path', ctx=ast.Load()),
                                  args=[ast.Constant(str(HERE))], keywords=[])
            return node
        return self.generic_visit(node)

    def visit_Dict(self, node):
        try:
            value = ast.literal_eval(node)
        except (ValueError, TypeError):
            value = None
        if (isinstance(value, dict) and value and set(value) <= set(self.old_exports)
                and all(value[key] == self.old_exports[key] for key in value)):
            return ast.copy_location(ast.parse(repr(self.exports), mode='eval').body, node)
        return self.generic_visit(node)

    def visit_Constant(self, node):
        value = node.value
        if type(value) is int and self.bounds[0] <= value < self.bounds[1]:
            if value not in self.links:
                raise ValueError('Unmapped SDK replay address ' + hex(value))
            value = self.links[value]
        elif isinstance(value, str):
            if value in self.replacements:
                value = self.replacements[value]
            elif value in self.names:
                value = str(self.names[value])
            elif self.baseline in value:
                value = value.replace(self.baseline, self.target)
            elif 'code-clues/' in value:
                prefix, category = value.rsplit('code-clues/', 1)
                if '/' not in category:
                    category = Path(alias_name(category + '.py')).stem
                    value = prefix + 'code-clues/' + category + '-generated'
        return ast.copy_location(ast.Constant(value), node)

    def visit_Subscript(self, node):
        self.generic_visit(node)
        if (isinstance(node.slice, ast.Attribute) and node.slice.attr == 'name'
                and ast.unparse(node.slice.value) == 'Path(__file__)'):
            node.slice = ast.parse('str(Path(__file__).resolve())', mode='eval').body
        return node


def scalar_exports(tree, exports, root_entries, address_map, bounds):
    declarations = {target.id: node for node in tree.body if isinstance(node, ast.Assign)
                    for target in node.targets if isinstance(target, ast.Name)}
    if 'EXPORT' not in declarations:
        return tree
    if 'EXPORT_SHA' not in declarations:
        raise ValueError('SDK scalar export has no hash declaration')
    uses = [node for node in tree.body if isinstance(node, ast.FunctionDef)
            and any(isinstance(child, ast.Name) and child.id == 'EXPORT' for child in ast.walk(node))]
    if not uses:
        required = {address_map[node.value] for node in ast.walk(tree) if isinstance(node, ast.Constant)
                    and type(node.value) is int and node.value in address_map
                    and address_map[node.value] in root_entries}
        selected = {run: exports[run] for run in sorted({root_entries[at] for at in required})}
        if not selected:
            raise ValueError('SDK helper export roots cannot be selected')
        if len(selected) == 1:
            run = next(iter(selected))
            declarations['EXPORT'].value = ast.Constant(run)
            declarations['EXPORT_SHA'].value = ast.Constant(selected[run])
        else:
            declarations['EXPORT'].targets = [ast.Name(id='EXPORTS', ctx=ast.Store())]
            declarations['EXPORT'].value = ast.parse(repr(selected), mode='eval').body
            tree.body.remove(declarations['EXPORT_SHA'])
        return tree
    if len(uses) != 1:
        raise ValueError('SDK scalar export consumer shape differs')
    function = uses[0]
    starts = [i for i, node in enumerate(function.body)
              if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'path' for t in node.targets)
              and any(isinstance(c, ast.Name) and c.id == 'EXPORT' for c in ast.walk(node.value))]
    ends = [i for i, node in enumerate(function.body) if isinstance(node, ast.Assign)
            and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'functions'
            and isinstance(node.value, ast.DictComp)]
    if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
        raise ValueError('SDK scalar export validation block differs')
    start, end = starts[0], ends[0]
    assignment = function.body[end]
    native = {value.value for value in ast.walk(assignment.value) if isinstance(value, ast.Constant)
              and type(value.value) is int and bounds[0] <= value.value < bounds[1]}
    required = {address_map[at] for at in native}
    if not required or not required <= set(root_entries):
        raise ValueError('SDK scalar export required roots are missing')
    chosen = {root_entries[at] for at in required}
    selected = {run: exports[run] for run in sorted(chosen)}
    if len(selected) == 1:
        run = next(iter(selected))
        declarations['EXPORT'].value = ast.Constant(run)
        declarations['EXPORT_SHA'].value = ast.Constant(selected[run])
        return tree

    class ExportNames(ast.NodeTransformer):
        def visit_Name(self, node):
            name = {'EXPORT': 'sdk_export_run', 'EXPORT_SHA': 'sdk_export_sha'}.get(node.id)
            return ast.copy_location(ast.Name(id=name, ctx=node.ctx), node) if name else node

    block = [ExportNames().visit(node) for node in function.body[start:end]]
    block.append(ast.Expr(value=ast.Call(func=ast.Attribute(value=ast.Name(id='functions', ctx=ast.Load()),
        attr='update', ctx=ast.Load()), args=[assignment.value], keywords=[])))
    block.extend(ast.parse("sdk_evidence.append(dict(path=str(path), sha256=sdk_export_sha))").body)
    loop = ast.For(target=ast.Tuple(elts=[ast.Name(id='sdk_export_run', ctx=ast.Store()),
        ast.Name(id='sdk_export_sha', ctx=ast.Store())], ctx=ast.Store()),
        iter=ast.Call(func=ast.Attribute(value=ast.parse(repr(selected), mode='eval').body,
            attr='items', ctx=ast.Load()), args=[], keywords=[]), body=block, orelse=[])
    function.body[start:end + 1] = ast.parse('functions = {}\nsdk_evidence = []').body + [loop]
    evidence = [node for node in ast.walk(function) if isinstance(node, ast.keyword) and node.arg == 'evidence']
    if len(evidence) != 1 or 'EXPORT_SHA' not in ast.unparse(evidence[0].value):
        raise ValueError('SDK scalar export evidence site differs')
    evidence[0].value = ast.Name(id='sdk_evidence', ctx=ast.Load())
    tree.body.remove(declarations['EXPORT'])
    tree.body.remove(declarations['EXPORT_SHA'])
    return tree


def run(root, baseline_path, transfer_path, exports):
    root = Path(root).resolve()
    baseline_path, transfer_path = Path(baseline_path).resolve(), Path(transfer_path).resolve()
    baseline_raw = baseline_path.read_bytes()
    baseline = json.loads(baseline_raw)
    transfer = manifest(transfer_path, 'sdk-batch-transfer-v1')
    if not transfer_path.is_relative_to(root / 'knowledge/sdk-batch-transfer-v1'):
        raise ValueError('SDK transfer manifest is outside the selected library')
    old, new = baseline['source_sha256'], transfer['source_sha256']
    if (baseline.get('schema') != 1 or transfer.get('schema') != 1
            or transfer.get('recipe') != 'sdk-batch-transfer-v1' or transfer.get('unresolved')
            or old != transfer['baseline_sha256'] or not SHA.fullmatch(old) or not SHA.fullmatch(new) or old == new
            or len(baseline.get('generated_files', {})) != 12 or len(baseline.get('roots', {})) != 34):
        raise ValueError('SDK generation source, template set or transfer scope differs')
    inputs = dict(transfer['inputs'])
    if str(baseline_path) not in inputs:
        raise ValueError('SDK transfer does not pin the selected baseline context')
    pin(inputs, baseline_path, hashlib.sha256(baseline_raw).hexdigest())
    pin(inputs, transfer_path, digest(transfer_path))
    for name in ('generate-sdk-batch.py', 'build-native-entry-code.py', 'extract-native-enums.py', 'research-workflow.py'):
        pin(inputs, HERE / name, digest(HERE / name))
    executable = Path(sys.executable).resolve()
    pin(inputs, executable, digest(executable))
    for path, expected in inputs.items():
        checked(Path(path), expected)
    templates = {}
    for name, expected in baseline['generated_files'].items():
        if Path(name).name != name or not name.endswith('.py'):
            raise ValueError('SDK template path differs')
        path = HERE / name
        templates[name] = checked(path, expected).decode('utf-8')
        pin(inputs, path, expected)
    native = load('build-native-entry-code')
    images = []
    for sha in (old, new):
        path = root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'
        images.append(native.Image(checked(path, sha)))
        pin(inputs, path, sha)
    for run, expected in baseline['exports'].items():
        if Path(run).name != run or not run.startswith('run-'):
            raise ValueError('SDK baseline export path differs')
        path = root / 'ghidra/request-exports' / old / run / 'details.json'
        if json.loads(checked(path, expected))['new_source_sha256'] != old:
            raise ValueError('SDK baseline export source differs')
        pin(inputs, path, expected)
    current_exports, root_entries, export_inputs = exports_for(root, new, exports, images[1])
    for path, expected in export_inputs.items():
        pin(inputs, path, expected)
    links = unique_map(transfer['links'])
    if (set(transfer['roots']) != set(baseline['roots'].values())
            or any(links.get(int(a, 16)) != int(b, 16) for a, b in transfer['roots'].items())
            or not {int(at, 16) for at in transfer['roots'].values()} <= set(root_entries)):
        raise ValueError('SDK target root mapping or export set differs')
    replacements = leaf_replacements(transfer, images, links)
    definition = dict(schema=1, recipe=RECIPE, source_sha256=new, baseline_sha256=old,
                      inputs=dict(sorted(inputs.items())), templates=baseline['generated_files'],
                      tools_directory=str(HERE), exports=current_exports,
                      runtime=dict(python=platform.python_version(), implementation=platform.python_implementation(),
                                   executable=str(executable)))
    workflow = load('research-workflow')
    key = hashlib.sha256(workflow.canonical(definition)).hexdigest()
    directory = root / 'knowledge/sdk-batch-generated-code' / key
    names = {name: directory / alias_name(name) for name in templates}
    if len(set(names.values())) != len(templates):
        raise ValueError('SDK generated template names collide')
    generated = {}
    for name, source in templates.items():
        known_hex = set(replacements) | set(baseline['exports'].values()) | {old}
        literals = {node.value for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Constant)
                    and isinstance(node.value, str) and len(node.value) >= 10 and len(node.value) % 2 == 0
                    and re.fullmatch('[0-9a-f]+', node.value) and re.search('[a-f]', node.value)}
        if literals - known_hex:
            raise ValueError('SDK template has an undeclared pinned byte or digest literal: ' + name)
        tree = scalar_exports(ast.parse(source), current_exports, root_entries, links, image_bounds(images[0]))
        tree = Port(old, new, links, replacements, baseline['exports'], current_exports,
                    names, image_bounds(images[0])).visit(tree)
        stale = set(baseline['exports']) | set(baseline['exports'].values())
        if any(isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in stale
               for node in ast.walk(tree)):
            raise ValueError('Unported SDK export reference in ' + name)
        if tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Constant) and isinstance(tree.body[0].value.value, str):
            tree.body[0].value.value = 'Generated SDK replay for source ' + new + '.\n' + tree.body[0].value.value
        ast.fix_missing_locations(tree)
        text = '# Generated by generate-sdk-batch.py. Native replay and its source guards remain required.\n'
        text += native_numbers(ast.unparse(tree) + '\n', image_bounds(images[1]))
        compile(text, str(names[name]), 'exec')
        generated[names[name]] = text.encode('utf-8')
    for path, expected in inputs.items():
        checked(Path(path), expected)
    directory.parent.mkdir(parents=True, exist_ok=True)
    if directory.exists():
        for path, data in generated.items():
            if path.read_bytes() != data:
                raise ValueError('Immutable SDK generated file differs')
    else:
        with tempfile.TemporaryDirectory(prefix='.sdk-generation-', dir=directory.parent) as temporary:
            staging = Path(temporary)
            for path, data in generated.items():
                (staging / path.name).write_bytes(data)
            try:
                staging.rename(directory)
            except FileExistsError:
                for path, data in generated.items():
                    if path.read_bytes() != data:
                        raise ValueError('Concurrent SDK generated file differs') from None
    report = dict(definition, generation_key=key, files={str(path): hashlib.sha256(data).hexdigest()
        for path, data in generated.items()}, generated_templates={name: str(path) for name, path in names.items()},
        roots=transfer['roots'], switches=transfer['switches'], transfer=dict(path=str(transfer_path), sha256=digest(transfer_path)),
        semantic_verification=False, network_used=False, profile_activated=False)
    for path, expected in inputs.items():
        checked(Path(path), expected)
    for path, data in generated.items():
        checked(path, hashlib.sha256(data).hexdigest())
    path = workflow.snapshot(root, RECIPE, report)
    return path, report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--transfer', type=Path, required=True)
    parser.add_argument('--export', type=Path, action='append', required=True)
    args = parser.parse_args()
    path, report = run(args.root, args.baseline, args.transfer, args.export)
    print(json.dumps(dict(report=str(path), files=len(report['files']), generation_key=report['generation_key'])))
