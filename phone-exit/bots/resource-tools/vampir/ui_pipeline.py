"""Content-bound offline pipeline cache. Timings never participate in artifact identity."""
import hashlib
import ast
import inspect
import json
import textwrap
import time
from pathlib import Path


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


def action_source_sha(source):
    """Hash executable structure, excluding comments and unrelated line offsets."""
    tree = ast.parse(textwrap.dedent(source))
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef):
        raise ValueError('Expected one explicit stage function')
    return hashlib.sha256(ast.dump(tree, include_attributes=False).encode('utf8')).hexdigest()


def invocation_inputs(inputs, action, arguments, helpers=()):
    def serial(value):
        if isinstance(value, Path):
            return {'path': str(value.resolve())}
        if isinstance(value, (list, tuple)):
            return [serial(v) for v in value]
        if isinstance(value, dict):
            if any(not isinstance(k, str) for k in value):
                raise ValueError('Stage argument keys must be strings')
            return {k: serial(v) for k, v in value.items()}
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        raise ValueError('Unsupported stage argument type: ' + type(value).__name__)
    functions = (action, *helpers)
    if len({f.__name__ for f in functions}) != len(functions):
        raise ValueError('Ambiguous stage function names')
    return dict(dependencies=inputs, arguments=serial(arguments),
        action_contracts={f.__name__: action_source_sha(inspect.getsource(f)) for f in functions})


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def tree(folder):
    folder = Path(folder).resolve()
    if not folder.is_dir():
        raise ValueError('Missing input directory: ' + str(folder))
    return {p.relative_to(folder).as_posix(): sha(p) for p in sorted(folder.rglob('*'))
            if p.is_file() and '__pycache__' not in p.parts}


def artifacts(folder):
    return {p.relative_to(folder).as_posix(): sha(p) for p in sorted(folder.rglob('*'))
            if p.is_file() and p.name != 'receipt.json'}


def stage(cache, name, inputs, action):
    """Reuse only identical dependencies and intact outputs; corruption fails closed."""
    started = time.perf_counter()
    identity = hashlib.sha256(encoded(dict(stage=name, inputs=inputs))).hexdigest()
    folder = Path(cache) / name / identity
    receipt = folder / 'receipt.json'
    reused = receipt.exists()
    if reused:
        result = json.loads(receipt.read_bytes())
        if result['id'] != identity or result['inputs'] != inputs or result['artifacts'] != artifacts(folder):
            raise ValueError('Pipeline cache differs: ' + str(folder))
    else:
        if folder.exists():
            raise ValueError('Incomplete stage; preserve for diagnosis: ' + str(folder))
        folder.mkdir(parents=True)
        value = action(folder)
        result = dict(id=identity, inputs=inputs, result=value, artifacts=artifacts(folder))
        with receipt.open('xb') as stream:
            stream.write(encoded(result))
    return dict(name=name, id=identity, output=str(folder), result=result['result'],
                reused=reused, seconds=round(time.perf_counter() - started, 3))
