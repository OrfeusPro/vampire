"""Export all OperationType definitions with explicit client grouping and provenance."""
import csv
import hashlib
import json
import runpy
from collections import Counter
from pathlib import Path

ROOT = Path('F:/PhoneExit Resources/Vampir')


def main(root=ROOT):
    sources = {}

    def read(relative):
        raw = (root/relative).read_bytes()
        sources[relative] = hashlib.sha256(raw).hexdigest()
        return json.loads(raw.decode('utf-8-sig'))

    meta = {t['entry']: t for t in read('table-study/index-pakchunk1-Windows.json')['tables']}

    def table(entry):
        path = root/'table-study'/meta[entry]['file']
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if digest != meta[entry]['sha256']:
            raise ValueError('Changed CSV '+str(entry))
        with path.open(encoding='utf-8-sig', newline='') as stream:
            reader = csv.DictReader(stream)
            if reader.fieldnames != meta[entry]['header']:
                raise ValueError('Changed header '+str(entry))
            rows = [dict(row, provenance=dict(entry=entry, csv_record=i+2)) for i, row in enumerate(reader)]
        if len(rows) != meta[entry]['rows']:
            raise ValueError('Changed count '+str(entry))
        sources['table-study/'+meta[entry]['file']] = digest
        return rows

    native = read('code-clues/native-enums.json')
    dependencies = read('code-clues/table-dependencies.json')
    executable = Path(native['source'])
    raw = executable.read_bytes()
    if hashlib.sha256(raw).hexdigest() != native['sha256'] or dependencies['sha256'] != native['sha256']:
        raise ValueError('Changed client executable')
    diagnostics = []
    for sheet, field, target in [('OperationType', 'DisplayGroupId', 'OperationTypeGroup'),
                                  ('OperationTypeGroup', 'OperationTabId', 'OperationTab')]:
        ref = next(r for r in dependencies['references'] if r['source']['sheet'] == sheet
                   and r['field'] == field and r['target']['sheet'] == target)
        encoded = ref['text'].encode('utf-16le')
        if raw[ref['offset']:ref['offset']+len(encoded)] != encoded:
            raise ValueError('Changed native reference diagnostic')
        diagnostics.append(ref)
    enums = {str(e['value']): e for e in native['enums']['EOperationType']}
    stats = {str(e['value']): e for e in native['enums']['EStat']}
    names = {r['OperationType']: r for r in table(486)}
    groups = {r['GroupId']: r for r in table(1428)}
    tabs = {r['Id']: r for r in table(485)}
    rows = table(1427)
    entries = []
    for row in rows:
        enum = enums.get(row['OperationType'])
        if enum:
            encoded = enum['name'].encode('ascii')+b'\0'
            if raw[enum['name_offset']:enum['name_offset']+len(encoded)] != encoded:
                raise ValueError('Changed operation enum string')
        name = names.get(enum['name'].split('::')[-1]) if enum else None
        group = groups.get(row['DisplayGroupId'])
        stat_enum = stats.get(row['StatType'])
        if stat_enum:
            encoded = stat_enum['name'].encode('ascii')+b'\0'
            if raw[stat_enum['name_offset']:stat_enum['name_offset']+len(encoded)] != encoded:
                raise ValueError('Changed EStat enum string')
        stat_binding = dict(value=row['StatType'], enum=stat_enum,
            status='sentinel' if stat_enum and stat_enum['name']=='EStat::Max' else 'mapped' if stat_enum else 'unknown',
            native_calculation_verified=False)
        tab = group['OperationTabId'] if group and group['OperationTabId'] in tabs else 'unassigned'
        entries.append(dict(id=row['OperationType'], name=name['Name'] if name else 'Параметр '+row['OperationType'],
            description=name['Desc'] if name else '', row=row, enum=enum, name_source=name,
            group=group, tab_id=tab, stat_binding=stat_binding))
    relations = runpy.run_path(str(Path(__file__).with_name('attribute-relations.py')))['build'](entries)
    weight_proof = read('code-clues/attribute-weight-evidence.json')
    if weight_proof['sha256'] != native['sha256'] or weight_proof['csv']['sha256'] != meta[1427]['sha256']:
        raise ValueError('Changed native weight proof source')
    for fragment in weight_proof['fragments']:
        size = fragment['end_rva']-fragment['begin_rva']
        content = raw[fragment['file_offset']:fragment['file_offset']+size]
        if hashlib.sha256(content).hexdigest()!=fragment['sha256']:
            raise ValueError('Changed weight proof fragment')
    for anchor in weight_proof['anchors']:
        content = bytes.fromhex(anchor['bytes'])
        if raw[anchor['file_offset']:anchor['file_offset']+len(content)]!=content:
            raise ValueError('Changed weight proof anchor')
    weight_math = dict(formula=weight_proof['formula'], evidence_file='../../code-clues/attribute-weight-evidence.json',
        evidence_sha256=sources['code-clues/attribute-weight-evidence.json'], statistics=weight_proof['statistics'],
        scope=weight_proof['scope'], native_blocks_verified=weight_proof['verified'],
        total_character_power_verified=False, stat_to_stat_formula_verified=False)
    context = read('code-clues/attribute-score-context.json')
    if context['sha256']!=native['sha256'] or not context['item_comparison_verified'] or context['total_character_power_verified']:
        raise ValueError('Invalid item score context')
    for fragment in context['fragments']:
        size=fragment['end_rva']-fragment['begin_rva']
        if hashlib.sha256(raw[fragment['file_offset']:fragment['file_offset']+size]).hexdigest()!=fragment['sha256']:
            raise ValueError('Changed score context fragment')
    for anchor in context['anchors']+context['data_anchors']:
        content=bytes.fromhex(anchor['bytes'])
        if raw[anchor['file_offset']:anchor['file_offset']+len(content)]!=content:
            raise ValueError('Changed score context anchor')
    binding=context['inherited_binding']
    inherited=read(binding['file'])
    if sources[binding['file']]!=binding['sha256'] or inherited['sha256']!=native['sha256']:
        raise ValueError('Changed inherited item binding')
    weight_math['item_comparison_context']=dict(verified=True,
        evidence_file='../../code-clues/attribute-score-context.json',
        evidence_sha256=sources['code-clues/attribute-score-context.json'],
        statistics=context['statistics'],ui_widget_name_verified=False,total_character_power_verified=False)
    packet_proof=read('code-clues/stat-packet-evidence.json')
    if packet_proof['sha256']!=native['sha256'] or not packet_proof['verified'] or packet_proof['formula_verified']:
        raise ValueError('Invalid stat packet proof')
    for f in packet_proof['fragments']:
        size=f['end_rva']-f['begin_rva']
        if hashlib.sha256(raw[f['file_offset']:f['file_offset']+size]).hexdigest()!=f['sha256']:
            raise ValueError('Changed stat packet fragment')
    for a in packet_proof['anchors']+packet_proof['data_anchors']:
        content=bytes.fromhex(a['bytes'])
        if raw[a['file_offset']:a['file_offset']+len(content)]!=content:
            raise ValueError('Changed stat packet anchor')
    detail_protocol=dict(schema_verified=True,formula_verified=False,live_values_available=False,
        category_names_verified=False,schemas=packet_proof['schemas'],statistics=packet_proof['statistics'],
        evidence_file='../../code-clues/stat-packet-evidence.json',
        evidence_sha256=sources['code-clues/stat-packet-evidence.json'])
    format_proof=read('code-clues/stat-format-evidence.json')
    if format_proof['sha256']!=native['sha256'] or not format_proof['verified'] or format_proof['stat_calculation_verified']:
        raise ValueError('Invalid stat formatter proof')
    for f in format_proof['fragments']:
        size=f['end_rva']-f['begin_rva']
        if hashlib.sha256(raw[f['file_offset']:f['file_offset']+size]).hexdigest()!=f['sha256']:
            raise ValueError('Changed stat formatter fragment')
    for a in format_proof['anchors']+format_proof['data_anchors']:
        content=bytes.fromhex(a['bytes'])
        if raw[a['file_offset']:a['file_offset']+len(content)]!=content:raise ValueError('Changed stat formatter anchor')
    percentage_format=dict(verified=True,scale=format_proof['display_scale'],units='percent',
        stat_calculation_verified=False,statistics=format_proof['statistics'],
        evidence_file='../../code-clues/stat-format-evidence.json',evidence_sha256=sources['code-clues/stat-format-evidence.json'])
    routes=read('code-clues/stat-format-routes.json')
    if routes['sha256']!=native['sha256'] or routes['csv']['sha256']!=meta[1427]['sha256'] or not routes['verified']:
        raise ValueError('Invalid display routes proof')
    for f in routes['fragments']:
        size=f['end_rva']-f['begin_rva']
        if hashlib.sha256(raw[f['file_offset']:f['file_offset']+size]).hexdigest()!=f['sha256']:
            raise ValueError('Changed display routes fragment')
    for a in routes['anchors']+routes['data_anchors']:
        content=bytes.fromhex(a['bytes'])
        if raw[a['file_offset']:a['file_offset']+len(content)]!=content:raise ValueError('Changed display route anchor')
    for entry in entries:entry['display_format']=routes['rules'][entry['id']]
    display_routes=dict(verified=True,statistics=routes['statistics'],stat_calculation_verified=False,
        evidence_file='../../code-clues/stat-format-routes.json',evidence_sha256=sources['code-clues/stat-format-routes.json'])
    payload = dict(schema=6, entries=entries, relations=relations, weight_math=weight_math, detail_protocol=detail_protocol,
        display_routes=display_routes,
        percentage_format=percentage_format,tabs=list(tabs.values()), groups=list(groups.values()),
        statistics=dict(attributes=len(entries), tabs=len(tabs), groups=len(groups),
            unassigned=sum(e['tab_id']=='unassigned' for e in entries),
            hidden=sum(e['row']['InvisibleStat']=='1' for e in entries),
            missing_names=sum(e['name_source'] is None for e in entries),
            by_tab=dict(Counter(e['tab_id'] for e in entries)), relations=len(relations),
            stat_bindings=dict(Counter(e['stat_binding']['status'] for e in entries))))
    out = root/'maps/attributes'
    out.mkdir(parents=True, exist_ok=True)
    path = out/'attributes.json'
    path.write_text(json.dumps(payload, ensure_ascii=False, separators=(',', ':')), 'utf-8')
    manifest = dict(file=path.name, sha256=hashlib.sha256(path.read_bytes()).hexdigest(), sources=sources,
        client_exe=dict(path=str(executable), sha256=native['sha256']), diagnostics=diagnostics,
        statistics=payload['statistics'],
        joins=['CSV1427.DisplayGroupId = CSV1428.GroupId', 'CSV1428.OperationTabId = CSV485.Id',
               'CSV1427.OperationType = EOperationType.value; enum suffix = CSV486.OperationType',
               'CSV1427.StatType = EStat.value; EStat::Max is sentinel, not a shared runtime dependency'],
        limitations=['185 OperationType definitions, not all enum operation kinds (which also include actions/control effects).',
                    'Relations are curated from exact client descriptions, not numeric native formulas; null formula is unknown, not zero.',
                    'CSV485 names joined by exact tab ID; no newly decoded OperationTab binary table.',
                    'CSV484.GroupId labels do not match CSV1428 IDs and are NOT used or rounded.',
                    'Missing display groups retained as unassigned, InvisibleStat retained, not removed.',
                    'No account values, total combat power or live activation inferred; display conversion is not stat-to-stat math.'])
    (out/'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(payload['statistics'], ensure_ascii=False))
    return manifest


if __name__ == '__main__':
    main()
