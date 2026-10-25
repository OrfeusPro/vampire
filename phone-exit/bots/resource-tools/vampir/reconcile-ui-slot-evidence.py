"""Reuse source-bound slot candidate evidence without promoting it to verified geometry."""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


source_audit = load('slot_evidence_source_audit', 'audit-ui-sources.py')
grid = load('slot_evidence_grid', 'decode-grid-slots.py')
basic = load('slot_evidence_basic', 'decode-basic-slot-candidates.py')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def evidence_index(report):
    if report['kind'] != 'grid_slot_candidate_decode' or report['failures']:
        raise ValueError('Expected successful bounded GridSlot candidate evidence')
    if report['native_source']['sha256'] != grid.SOURCE_SHA:
        raise ValueError('Unreviewed native source SHA')
    if report.get('class_links', {}).get('source_sha256') != grid.SOURCE_SHA:
        raise ValueError('Missing matching class-link evidence')
    if set(report['tools']) != {'decode-grid-slots.py', 'extract-ui-properties.py', 'decode-canvas-slots.py', 'inspect-ui.py'}:
        raise ValueError('Incomplete evidence tool fingerprint')
    for name, expected in report['tools'].items():
        if sha(source_audit.inventory.child(HERE, name).read_bytes()) != expected:
            raise ValueError('Evidence tool changed: ' + name)
    result = {}
    for row in report['records']:
        p = row['source']
        key = (p['file'], p['slot_export'])
        if key in result:
            raise ValueError('Duplicate GridSlot evidence identity')
        result[key] = row
    return result


def reproduce(candidate, variant, source_file, exports, proof):
    """A reused result must still match actual export bytes and its parsed explicit values."""
    source = proof['source']
    actual = exports[candidate['index']]
    kind = proof.get('kind', 'GridSlot')
    if kind not in ('GridSlot', 'PanelSlot', 'UniformGridSlot', 'ScrollBoxSlot', 'NamedSlot') or actual['type'] != kind:
        raise ValueError('Evidence cannot reclassify another export type')
    if any(actual[k] != candidate[k] for k in ['index', 'name', 'type', 'sha256', 'offset', 'size']):
        raise ValueError('Source audit candidate differs from actual export')
    expected = dict(file=source_file, slot_export=actual['index'], offset=actual['offset'],
        size=actual['size'], sha256=actual['sha256'], asset_sha256=variant['source']['asset_sha256'],
        body_sha256=variant['source']['body_sha256'])
    if source != expected:
        raise ValueError('GridSlot evidence belongs to different package/export bytes')
    if kind=='NamedSlot':
        outer=exports[actual['outer']]
        if proof['decoded'] is not None or proof['raw_serialization_hex']!=actual['serialized_hex'] or outer['type']!='WidgetTree':
            raise ValueError('Container candidate source/opaque payload differs')
        if {k:outer[k] for k in ['index','name','type','sha256']} != proof['outer']:
            raise ValueError('Container outer differs')
        return dict(status='container_candidate_classified',automatic_check_passed=True,
            candidate_parse_complete=False,inherited_properties_decoded=False,
            interpretation='NamedSlot container class candidate; inherited serialized fields remain opaque',
            raw_serialization_hex=actual['serialized_hex'],geometry_verified=False,implementation_verified=False)
    raw = bytes.fromhex(actual['serialized_hex'])
    decoded = grid.decode(raw) if kind == 'GridSlot' else basic.decode(raw, kind,allow_size=proof.get('allow_explicit_size',False))
    if decoded != proof['decoded']:
        raise ValueError('Reproduced GridSlot explicit values differ')
    fields = decoded['explicit_properties']
    parent, content = exports[fields['Parent']], exports[fields['Content']]
    expected_parent = {'GridSlot':'GridPanel','UniformGridSlot':'UniformGridPanel','ScrollBoxSlot':'ScrollBox'}.get(kind)
    if expected_parent and parent['type'] != expected_parent:
        raise ValueError('Candidate parent is not ' + expected_parent)
    for value, recorded in [(parent, proof['parent']), (content, proof['content'])]:
        if {k: value[k] for k in ['index', 'name', 'type', 'sha256']} != recorded:
            raise ValueError('Candidate object link differs from actual exports')
    return dict(status='candidate_evidence_reproduced', automatic_check_passed=True,
        interpretation=kind + ' explicit candidate properties; inherited schema/defaults unresolved',
        decoded=decoded, parent=proof['parent'], content=proof['content'], candidate_parse_complete=True,
        geometry_verified=False, implementation_verified=False)


def basic_evidence_index(report):
    if report['kind'] != 'basic_slot_candidate_decode' or report['failures']:
        raise ValueError('Expected successful basic slot candidate evidence')
    expected_tools = {'decode-basic-slot-candidates.py','extract-ui-properties.py','decode-canvas-slots.py','inspect-ui.py','build-native-entry-code.py'}
    if set(report['tools']) != expected_tools:
        raise ValueError('Incomplete basic evidence tool fingerprint')
    for name, expected in report['tools'].items():
        if sha((HERE/name).read_bytes()) != expected:
            raise ValueError('Basic evidence tool changed: ' + name)
    selected=[basic.SPECS[kind] for kind in report['definitions']]
    roots={s['getter'] for s in selected} | {s['parent_getter'] for s in selected if 'parent_getter' in s}
    if 'size_schema' in report['definitions'].get('ScrollBoxSlot',{}):roots.add(basic.SIZE_GETTER)
    request = dict(source_sha256=report['native_source']['sha256'], source=report['native_source']['path'],
        question='ui-nktileview-property-schema',functions=[dict(address=hex(root)) for root in sorted(roots)])
    if basic.schemas(request) != report['definitions']:
        raise ValueError('Basic native schema evidence differs from current bytes')
    result = {}
    for row in report['records']:
        p = row['source']; key=(p['source_file'],p['export'])
        normalized = dict(kind=p['type'],source=dict(file=p['source_file'],slot_export=p['export'],
            offset=p['offset'],size=p['size'],sha256=p['sha256'],asset_sha256=p['asset_sha256'],body_sha256=p['body_sha256']),
            decoded=row['decoded'])
        if p['type']=='NamedSlot':
            normalized.update(raw_serialization_hex=row['raw_serialization_hex'],outer=row['outer'])
        else:
            normalized.update(parent=row['parent'],content=row['content'])
        if p['type']=='ScrollBoxSlot':
            normalized['allow_explicit_size']='size_schema' in report['definitions']['ScrollBoxSlot']
        if key in result and result[key] != normalized:
            raise ValueError('Conflicting basic slot evidence identity')
        result[key]=normalized
    return result


def build(root, audit_path, evidence_path, evidence_sha, basic_path=None, basic_sha=None):
    root = root.resolve()
    evidence_raw = source_audit.checked(evidence_path, evidence_sha)
    evidence = json.loads(evidence_raw)
    proofs = evidence_index(evidence)
    basic_input = None
    if (basic_path is None) != (basic_sha is None):
        raise ValueError('Provide both basic evidence path and SHA')
    if basic_path is not None:
        basic_raw = source_audit.checked(basic_path, basic_sha)
        basic_report = json.loads(basic_raw)
        additions = basic_evidence_index(basic_report)
        if proofs.keys() & additions.keys():
            raise ValueError('Conflicting evidence providers')
        proofs.update(additions)
        basic_input = dict(path=str(basic_path),sha256=basic_sha)
    audit_raw = audit_path.read_bytes()
    audit = json.loads(audit_raw)
    if audit['kind'] != 'automated_ui_source_audit':
        raise ValueError('Wrong source audit kind')
    if basic_input and basic_report['source_audit']['sha256'] != sha(audit_raw):
        raise ValueError('Basic evidence belongs to another source audit')
    snapshot = Path(audit['snapshot']['path'])
    manifest = json.loads(source_audit.checked(snapshot / 'manifest.json', audit['snapshot']['manifest_sha256']))
    if manifest['inputs']['ui-catalog/index.json'] != evidence['catalog_index_sha256']:
        raise ValueError('Source audit snapshot refers to another catalog index')
    if sha((root / 'ui-catalog/index.json').read_bytes()) != evidence['catalog_index_sha256']:
        raise ValueError('GridSlot evidence refers to another catalog index')
    # No evidence is transferred to another current EXE merely because a name/address matches.
    native_path = Path(evidence['native_source']['path'])
    source_audit.checked(native_path, evidence['native_source']['sha256'])
    cache, records, totals = {}, [], Counter()
    for record in audit['records']:
        if not any(v.get('unaccounted_slot_candidates') for v in record['variants']):
            continue
        identity = 'W-' + sha(record['path'].encode())[:12]
        relative = 'windows/' + identity + '.json'
        published = json.loads(source_audit.checked(source_audit.inventory.child(snapshot, relative), manifest['generated_files'][relative]))
        if record['task_id'] != 'UI-' + identity or record['name'] != published['name'] or record['path'] != published['path']:
            raise ValueError('Source audit resource identity differs from snapshot')
        published_variants = {v['file']: v for v in published['variants']}
        for variant in record['variants']:
            if not variant.get('unaccounted_slot_candidates'):
                continue
            original = published_variants[variant['file']]
            expected_source = dict(catalog_sha256=original['sha256'], asset_sha256=original['asset_sha256'], body_sha256=original['body_sha256'])
            if variant['source'] != expected_source:
                raise ValueError('Source audit variant differs from snapshot')
            for candidate in variant.get('unaccounted_slot_candidates', []):
                row = dict(task_id=record['task_id'], resource_path=record['path'],
                    catalog_file=variant['file'], export=candidate['index'], name=candidate['name'],
                    type=candidate['type'], sha256=candidate['sha256'],
                    export_scope=variant.get('export_scope','not_recorded'),
                    package_blueprint_roots=variant.get('package_blueprint_roots',[]),
                    source_audit_unknowns=variant.get('unknowns',[]))
                try:
                    if variant['file'] not in cache:
                        p = source_audit.inventory.child(root / 'ui-catalog', variant['file'])
                        package = json.loads(source_audit.checked(p, variant['source']['catalog_sha256']))
                        file = package.get('source_file', package['file'])
                        base = source_audit.inventory.child(root / 'ui-layout-study', Path(file).stem)
                        asset = source_audit.checked(base.with_suffix('.uasset'), variant['source']['asset_sha256'])
                        body = source_audit.checked(base.with_suffix('.uexp'), variant['source']['body_sha256'])
                        exports = source_audit.inspector.exports(asset, body)['exports']
                        cache[variant['file']] = (file, {e['index']: e for e in exports})
                    file, exports = cache[variant['file']]
                    proof = proofs.get((file, candidate['index']))
                    if proof:
                        row.update(reproduce(candidate, variant, file, exports, proof))
                    else:
                        actual = exports[candidate['index']]
                        if any(actual[k] != candidate[k] for k in ['index', 'name', 'type', 'sha256', 'offset', 'size']):
                            raise ValueError('Unclassified candidate source changed')
                        row.update(status='no_reviewed_provider', automatic_check_passed=False,
                            geometry_verified=False, implementation_verified=False,
                            reason='No confirmed decoder/evidence provider for these source bytes')
                except (ValueError, OSError, KeyError, TypeError, IndexError) as error:
                    row.update(status='source_or_evidence_mismatch', automatic_check_passed=False,
                        geometry_verified=False, implementation_verified=False, error=str(error))
                totals[row['status']] += 1
                totals['candidates'] += 1
                records.append(row)
    return dict(schema=1, kind='slot_candidate_evidence_reconciliation',
        inputs=dict(source_audit=dict(path=str(audit_path), sha256=sha(audit_raw)),
            grid_evidence=dict(path=str(evidence_path), sha256=evidence_sha), basic_evidence=basic_input, snapshot=audit['snapshot'],
            native_source=evidence['native_source']),
        tools={p.name: sha(p.read_bytes()) for p in [Path(__file__), HERE/'audit-ui-sources.py', HERE/'decode-grid-slots.py', HERE/'decode-basic-slot-candidates.py']},
        counts=dict(totals), records=records,
        limits=['Only candidate interpretations are reproduced; missing defaults/inheritance/compatibility stay unknown.',
            'Original catalog/snapshot and source audit checks are unchanged; no verified geometry is added.',
            'No UI window completion, game action or bot-input authorization follows from this report.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--audit', type=Path, required=True)
    parser.add_argument('--grid-evidence', type=Path, required=True)
    parser.add_argument('--grid-evidence-sha256', required=True)
    parser.add_argument('--basic-evidence', type=Path)
    parser.add_argument('--basic-evidence-sha256')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or output.is_relative_to(HERE.parents[3]) or output.is_relative_to((args.root/'maps/ui-prototype').resolve()):
        parser.error('Use a new external report path')
    result = build(args.root, args.audit, args.grid_evidence, args.grid_evidence_sha256,
        args.basic_evidence, args.basic_evidence_sha256)
    with output.open('x', encoding='utf8') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
    print(json.dumps(dict(output=str(output), counts=result['counts']), ensure_ascii=False))
    return int(bool(result['counts'].get('source_or_evidence_mismatch')))


if __name__ == '__main__':
    raise SystemExit(main())
