"""Run existing offline UI audits and generation with immutable, verified stage reuse."""
import argparse
import hashlib
import importlib.util
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import ui_pipeline as cache
import ui_rule_impact


def load(name):
    spec = importlib.util.spec_from_file_location('pipeline_' + name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def checked_readiness(path, expected_sha):
    if cache.sha(path) != expected_sha:
        raise ValueError('Baseline readiness SHA differs')
    ready = json.loads(Path(path).read_bytes())
    layer = Path(ready['component_layer'])
    if cache.sha(layer / 'index.json') != ready['component_index_sha256']:
        raise ValueError('Baseline component index differs')
    if cache.sha(layer / 'composition-graph.json') != ready.get('component_graph_sha256'):
        raise ValueError('Baseline graph is missing a verified SHA; create a new baseline with audit-only')
    return ready, json.loads((layer / 'composition-graph.json').read_bytes())


def run(root, snapshot, output, build_ready=False, baseline_readiness=None, baseline_sha256=None, widget_root_request=None):
    root, snapshot, output = (Path(p).resolve() for p in (root, snapshot, output))
    if any(output.is_relative_to(p) or p.is_relative_to(output) for p in
           [HERE.parents[3], snapshot, root / 'ui-catalog', root / 'ui-layout-study']):
        raise ValueError('Use a separate external pipeline output directory')
    started = time.perf_counter()
    if bool(baseline_readiness) != bool(baseline_sha256):
        raise ValueError('Baseline readiness and full SHA must be supplied together')
    baseline = checked_readiness(baseline_readiness, baseline_sha256) if baseline_readiness else None
    steps = []
    def tools(*names):
        return {name: cache.sha(HERE / name) for name in (*names, 'ui_pipeline.py', 'build-ui-pipeline.py')}
    def execute(name, inputs, action):
        value = cache.stage(output / 'cache', name, inputs, action)
        steps.append(value)
        print(json.dumps(dict(stage=name, reused=value['reused'], seconds=value['seconds'])), flush=True)
        return value
    common = tools('audit-ui-sources.py', 'inspect-ui.py', 'audit-ui-slot-coverage.py',
                   'ui_layout_schema.py', 'ui_source_roots.py', 'inventory-ui-names.py', 'build-ui-prototype.py')
    inputs = dict(root=str(root), snapshot=str(snapshot), tools=common,
                  catalogs=cache.tree(root / 'ui-catalog'), raw=cache.tree(root / 'ui-layout-study'),
                  published=cache.tree(snapshot))
    def audit_action(folder):
        value = load('audit-ui-sources').build(root, snapshot, [], 'all')
        if any(cache.sha(HERE / name) != expected for name, expected in common.items()):
            raise ValueError('Pipeline tools changed during source audit; rerun with stable inputs')
        (folder / 'audit.json').write_bytes(cache.encoded(value))
        errors = [v['error'] for r in value['records'] for v in r['variants'] if 'error' in v]
        return dict(counts=value['counts'], errors=errors)
    audit = execute('source-audit', inputs, audit_action)
    if audit['result']['errors']:
        raise ValueError('Source audit failed; inspect ' + audit['output'])
    audit_path = Path(audit['output']) / 'audit.json'
    scopes = execute('outer-scopes', dict(audit=audit['id'], audit_sha256=cache.sha(audit_path),
        tools=tools('scan-ui-outer-scopes.py', 'ui_outer_scope.py', 'ui_layout_schema.py')),
        lambda folder: load('scan-ui-outer-scopes').build(root, audit_path, cache.sha(audit_path), folder / 'layers'))
    request_path = Path(widget_root_request or root / 'knowledge/requests/7dc3d7b0a03afafed6f82c362776d8ecda440e1eeaf3e564a8303bd49299ba47/manifest.json').resolve()
    request = json.loads(request_path.read_bytes())
    native_sha = cache.sha(request['source'])
    if native_sha != request['source_sha256']:
        raise ValueError('Widget root native source SHA differs')
    roots = execute('widget-roots', dict(scopes=scopes['id'], request=str(request_path),
        request_sha256=cache.sha(request_path), native_sha256=native_sha,
        tools=tools('scan-ui-widget-roots.py', 'ui_widget_tree.py', 'ui_source_roots.py',
            'decode-basic-slot-candidates.py', 'decode-canvas-slots.py', 'decode-package-references.py',
            'extract-ui-properties.py', 'extract-native-enums.py', 'inspect-ui.py', 'audit-ui-sources.py', 'build-native-entry-code.py',
            'scan-ui-outer-scopes.py', 'ui_outer_scope.py', 'ui_layout_schema.py')),
        lambda folder: load('scan-ui-widget-roots').build(root, Path(scopes['result']['output']), request_path, folder / 'layers'))
    root_index = Path(roots['result']['output']) / 'index.json'
    consumers = execute('component-consumers', dict(scopes=scopes['id'],
        tools=tools('scan-ui-component-consumers.py', 'ui_component_consumers.py', 'ui_composition_graph.py')),
        lambda folder: load('scan-ui-component-consumers').build(root, Path(scopes['result']['output']), folder / 'layers'))
    index = json.loads((Path(consumers['result']['output']) / 'index.json').read_bytes())
    graph = json.loads((Path(consumers['result']['output']) / 'composition-graph.json').read_bytes())
    priorities = ['WBP_PopupBgTitle_C', 'WBP_ShortcutkeyHudT_C', 'WBP_ItemIconT_C', 'WBP_Badge_C']
    readiness = dict(schema=1, source_snapshot=str(snapshot), component_dataset=index['dataset_id'],
        source_scopes=scopes['result']['output'], component_layer=consumers['result']['output'],
        source_widget_roots=str(root_index), source_widget_roots_sha256=cache.sha(root_index),
        widget_root_request=str(request_path), widget_root_request_sha256=cache.sha(request_path),
        source_widget_root_statistics=roots['result'],
        component_index_sha256=cache.sha(Path(consumers['result']['output']) / 'index.json'),
        component_graph_sha256=cache.sha(Path(consumers['result']['output']) / 'composition-graph.json'),
        components={name: index['classes'].get(name) for name in priorities},
        priority_coverage=ui_rule_impact.priority_coverage(graph, priorities),
        impact_analysis_tools=tools('ui_rule_impact.py', 'ui_composition_graph.py'),
        confirmed_checks=['source_hashes_and_exports', 'source_outer_ownership', 'static_consumer_indices',
                          'serialized_widget_roots', 'named_slot_import_classification'],
        renderer_rules=[],
        unknowns=['Active resource variants and runtime roots', 'Inherited defaults and dynamic bindings',
                  'Brush/style/state contracts and event handlers', 'Per-consumer runtime layout and DPI'],
        implementation_verified=False, visual_verified=False)
    registry = HERE.parents[1] / 'vampir' / 'UI-RULES.json'
    rules = json.loads(registry.read_bytes())
    readiness['rule_registry_sha256'] = cache.sha(registry)
    readiness['providers'] = {r['provider']: cache.sha(HERE / r['provider']) for r in rules['rules']}
    readiness['rules'] = [{**rule, 'checks_passed': all(c in readiness['confirmed_checks'] for c in rule['checks'])}
                          for rule in rules['rules']]
    readiness_id = hashlib.sha256(cache.encoded(readiness)).hexdigest()
    ready_folder = output / 'readiness' / readiness_id
    ready_folder.mkdir(parents=True, exist_ok=True)
    ready_file = ready_folder / 'index.json'
    if ready_file.exists() and ready_file.read_bytes() != cache.encoded(readiness):
        raise ValueError('Readiness artifact differs')
    if not ready_file.exists():
        with ready_file.open('xb') as stream:
            stream.write(cache.encoded(readiness))
    impact_result = None
    if baseline:
        old_ready, old_graph = baseline
        impact = ui_rule_impact.compile_impact(old_graph, graph, old_ready, readiness)
        impact['inputs'] = dict(baseline_sha256=baseline_sha256, current_sha256=cache.sha(ready_file),
            tools=tools('ui_rule_impact.py', 'ui_composition_graph.py'))
        impact_id = hashlib.sha256(cache.encoded(impact)).hexdigest()
        folder = output / 'impact' / impact_id
        folder.mkdir(parents=True, exist_ok=True)
        for name, raw in [('index.json', cache.encoded(impact)), ('TASKS.md', ui_rule_impact.markdown(impact).encode('utf8'))]:
            target = folder / name
            if target.exists() and target.read_bytes() != raw:
                raise ValueError('Published impact queue differs')
            if not target.exists():
                with target.open('xb') as stream:
                    stream.write(raw)
        impact_result = dict(output=str(folder), **impact['statistics'])
    build_result = None
    if build_ready:
        build_started = time.perf_counter()
        destination = load('build-ui-prototype').build(root, ready_report=ready_file)
        build_result = load('verify-ui-prototype').verify(destination)
        steps.append(dict(name='build-and-verify', seconds=round(time.perf_counter() - build_started, 3),
                          output=str(destination), result=build_result, reused=False))
    report = dict(schema=1, mode='build-ready' if build_ready else 'audit-only', stages=steps,
                  readiness=str(ready_file), impact=impact_result, build=build_result,
                  seconds=round(time.perf_counter() - started, 3),
                  limits=readiness['unknowns'], window_completion_claimed=False)
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / ('run-' + str(time.time_ns()) + '.json')
    with report_path.open('xb') as stream:
        stream.write(cache.encoded(report))
    print(json.dumps(dict(report=str(report_path), seconds=report['seconds'], build=build_result), ensure_ascii=False))
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--audit-only', action='store_true')
    mode.add_argument('--build-ready', action='store_true')
    p.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    p.add_argument('--snapshot', type=Path, required=True)
    p.add_argument('--output', type=Path)
    p.add_argument('--baseline-readiness', type=Path)
    p.add_argument('--baseline-sha256')
    p.add_argument('--widget-root-request', type=Path)
    args = p.parse_args()
    if bool(args.baseline_readiness) != bool(args.baseline_sha256):
        p.error('Use --baseline-readiness and --baseline-sha256 together')
    run(args.root, args.snapshot, args.output or args.root / 'ui-property-scans/pipeline', args.build_ready,
        args.baseline_readiness, args.baseline_sha256, args.widget_root_request)
