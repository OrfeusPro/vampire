"""Five source20 -> source22 function closures; no semantic or runtime promotion."""
import argparse
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from importlib.util import spec_from_file_location, module_from_spec

HERE = Path(__file__).resolve().parent
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
BASELINE = '544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c'


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify(context, root):
    root = Path(root)
    if context['source_sha256'] != SOURCE or context['baseline_sha256'] != BASELINE or len(context['functions']) != 5:
        raise ValueError('Explicit five-function closure scope required')
    bindings, native = load('update-bindings'), load('build-native-entry-code')
    catalog = load('function-reuse-plan')
    images = {sha: native.Image(bindings.source(None, root, sha)) for sha in (BASELINE, SOURCE)}
    contract = context['contract']
    if len(contract['recipes']) != 5 or any(r['method'] != 'closed_shape' or r['baseline_sha256'] != BASELINE for r in contract['recipes']):
        raise ValueError('Reviewed source20 closure recipes required')
    coverage = {}
    for sha, declared, functions in ((BASELINE, context['baseline_exports'], contract['bindings'][BASELINE]),
                                      (SOURCE, context['exports'], context['functions'])):
        exports = {}
        for run, expected in declared.items():
            if Path(run).name != run or not run.startswith('run-'):
                raise ValueError('Invalid closure export name')
            path = root / 'ghidra/request-exports' / sha / run / 'details.json'
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != expected:
                raise ValueError('Closure export changed')
            report = json.loads(raw)
            if report.get('new_source_sha256', report.get('source_sha256')) != sha:
                raise ValueError('Closure export source differs')
            exports[str(path)] = dict(report=report, sha256=expected)
        if not exports or len(exports) > 4:
            raise ValueError('Closure export scope differs')
        for key, at in functions.items():
            rows = bindings.rows(native, images[sha], int(at, 16))
            record = dict(address=at, exports=set(exports))
            path = catalog.export_covers(record, rows, exports)
            if not path:
                raise ValueError('Closure full export coverage missing')
            coverage[sha + ':' + key] = path
    result = bindings.resolve(load('knowledge-index').api(), SimpleNamespace(root=root),
                              dict(contracts=[contract]), SOURCE, [])['contracts'][contract['id']]
    if set(result['bindings']) != set(context['functions']) or result['bindings'] != context['functions']:
        raise ValueError('Closure target bindings differ')
    for key, proof in result['verification'].items():
        if proof['state'] not in ('unchanged', 'moved_verified') or proof['baseline_sha256'] != BASELINE:
            raise ValueError('Function closure not verified')
    return dict(schema=1, source_sha256=SOURCE, baseline_sha256=BASELINE, verified=5,
                verification=result, coverage=coverage, scope='function_only',
                network_used=False, runtime_activated=False, profile_activated=False,
                limits=['Whole instruction/branch/callee/data equivalence with full source-bound exports for both releases.',
                        'No execution of game semantic scenarios, new protocol support or runtime admission.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    context = json.loads((HERE / 'knowledge/native-contexts/function-closure-11322.json').read_bytes())
    result = verify(context, args.root)
    path = load('research-workflow').snapshot(args.root, 'function-closure-11322', result)
    print(json.dumps(dict(report=str(path), verified=result['verified'], scope=result['scope'])))
