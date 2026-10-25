"""Content-bound offline pipeline cache. Timings never participate in artifact identity."""
import hashlib
import json
import time
from pathlib import Path


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


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
