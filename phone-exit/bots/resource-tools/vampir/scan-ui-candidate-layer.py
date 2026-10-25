"""Join reviewed candidate reports to the property scanner without changing its base dataset."""
import argparse
from collections import Counter, defaultdict
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE/file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


reconciliation = load('candidate_layer_reconciliation', 'reconcile-ui-slot-evidence.py')
base_verifier = load('candidate_layer_base_verifier', 'verify-ui-property-scan.py')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf8')


def identity(prefix, text):
    return prefix + sha(text.encode())[:16]


def compile_layer(base, report, source_exports):
    """Compile candidate-only indices. Property values remain atomic, including nested structs."""
    variants = base['datasets'][base['dataset_id']]['variants']
    nodes, properties, occurrences, omissions, relations = {}, {}, defaultdict(list), defaultdict(list), {}
    reverse, forward, resources, by_variant = defaultdict(list), defaultdict(list), defaultdict(list), defaultdict(dict)
    seen, counts = set(), Counter()
    for row in report['records']:
        file, export = row['catalog_file'], row['export']
        if Path(file).name!=file:
            raise ValueError('Candidate catalog filename must not contain directories')
        key = file+'#'+str(export)
        if key in seen:
            raise ValueError('Duplicate candidate identity')
        seen.add(key)
        if row['task_id'] != 'UI-W-'+sha(row['resource_path'].encode())[:12]:
            raise ValueError('Candidate task identity differs from resource path')
        unresolved=file in variants and not variants[file]['paths'] and row['resource_path']=='unresolved:'+file
        if file not in variants or (row['resource_path'] not in variants[file]['paths'] and not unresolved):
            raise ValueError('Candidate does not belong to base variant/resource')
        source = source_exports(file)
        actual = source[export]
        if any(row[k] != actual[k] for k in ['name','type','sha256']):
            raise ValueError('Candidate source export differs')
        if not row['automatic_check_passed'] or row['geometry_verified'] or row['implementation_verified']:
            raise ValueError('Expected verified candidate transfer, never implementation promotion')
        nid = identity('UI-CN-', key)
        if nid in nodes:
            raise ValueError('Candidate ID collision')
        status = row['status']
        if status not in ('candidate_evidence_reproduced','container_candidate_classified'):
            raise ValueError('Unsupported candidate status')
        decoded = row.get('decoded')
        parse_complete = row.get('candidate_parse_complete',False)
        if status=='container_candidate_classified':
            if parse_complete or decoded is not None or row.get('inherited_properties_decoded') is not False:
                raise ValueError('Container classification cannot claim payload parsing')
            observed, omitted = {}, None
            if row['raw_serialization_hex'] != actual['serialized_hex']:
                raise ValueError('Opaque container payload differs')
        else:
            if not parse_complete or not isinstance(decoded,dict):
                raise ValueError('Missing candidate decoded payload')
            observed = copy.deepcopy(decoded['explicit_properties'])
            omitted = copy.deepcopy(decoded['omitted_properties'])
            if set(observed) != set(decoded['serialized_fields']) or set(observed)&set(omitted):
                raise ValueError('Explicit/omitted property coverage inconsistent')
        unknowns = ['current_client_compatibility','inherited_defaults','native_superclass_contract',
            'runtime_visibility_and_order','desired_size_and_dpi','runtime_geometry','events_and_behavior']
        if not parse_complete:
            unknowns.append('opaque_inherited_payload')
        if omitted:
            unknowns.append('omitted_top_level_properties')
        if any(isinstance(v,(dict,list)) for v in observed.values()):
            unknowns.append('nested_field_explicitness_requires_review')
        node = dict(id=nid,variant=file,export=export,name=row['name'],kind=row['type'],task_id=row['task_id'],
            resource_path=row['resource_path'],source=copy.deepcopy(variants[file]['source']),
            resource_path_resolved=not unresolved,
            export_sha256=row['sha256'],status=status,observed_properties=observed,omitted_properties=omitted,
            candidate_parse_complete=parse_complete,geometry_verified=False,implementation_verified=False,
            unknowns=unknowns,interpretation=row['interpretation'],base_reference=variants[file]['file'])
        if not parse_complete:
            node['raw_serialization_hex']=row['raw_serialization_hex']
        nodes[nid]=node
        by_variant[file][nid]=node
        resources[row['resource_path']].append(nid)
        counts.update(nodes=1,parsed_candidates=int(parse_complete),container_classifications=int(not parse_complete))
        for field in sorted(set(observed)|set(omitted or [])):
            pid=identity('UI-27.CP-',row['type']+'.candidate_value.'+field)
            label=row['type']+'.candidate_value.'+field
            if pid not in properties:
                properties[pid]=dict(key=label,owner=row['type'],scope='candidate_value',field=field,
                    status='requires_review_not_runtime_verified',types=[],observations=0,
                    omitted_observations=0,occurrences='properties/'+pid+'.json',
                    omissions='properties/'+pid+'-omissions.json')
            entry=properties[pid]
            if entry['key']!=label:
                raise ValueError('Property ID collision')
            if field not in observed:
                entry['omitted_observations']+=1
                omissions[pid].append(dict(node=nid,field=field))
                counts['omitted_property_observations']+=1
                continue
            value=observed[field]
            kind='null' if value is None else type(value).__name__
            if kind not in entry['types']:
                entry['types'].append(kind);entry['types'].sort()
            entry['observations']+=1
            occurrences[pid].append(dict(node=nid,field=field))
            counts['property_observations']+=1
        targets = [('outer',source[actual['outer']])] if not parse_complete else [('parent',row['parent']),('content',row['content'])]
        for role,target in targets:
            raw=source[target['index']]
            if {k:raw[k] for k in ['index','name','type','sha256']} != {k:target[k] for k in ['index','name','type','sha256']}:
                raise ValueError('Candidate relation endpoint differs')
            if not parse_complete and raw['type']!='WidgetTree':
                raise ValueError('Container outer is not WidgetTree')
            if parse_complete and observed[role.capitalize()]!=target['index']:
                raise ValueError('Object link differs from observed property')
            target_key=file+'#'+str(target['index'])
            rid=identity('UI-CR-',nid+'.'+role+'.'+target_key)
            if rid in relations:
                raise ValueError('Relation ID collision')
            relations[rid]=dict(id=rid,kind='candidate_'+role,source=nid,target_key=target_key,
                target=dict(variant=file,export=target['index'],name=raw['name'],kind=raw['type'],sha256=raw['sha256']),
                status='candidate_not_runtime_verified')
            forward[nid].append(rid);reverse[target_key].append(rid)
            counts['relations']+=1
    for nid,node in nodes.items():
        node['relations']=sorted(forward[nid])
    files = {'relations.json':relations,'reverse-relations.json':dict(reverse)}
    for file,values in by_variant.items():
        files['variants/'+file]=dict(base_reference=variants[file]['file'],nodes=values)
    for pid,entry in properties.items():
        files[entry['occurrences']]=occurrences[pid]
        files[entry['omissions']]=omissions[pid]
    index=dict(schema=1,kind='ui_candidate_property_layer',phase='candidate_evidence_overlay',
        base_dataset_id=base['dataset_id'],statistics=dict(counts),
        nodes={nid:dict(variant=n['variant'],export=n['export'],kind=n['kind'],ref='variants/'+n['variant']) for nid,n in nodes.items()},
        properties=properties,resources=dict(resources),relations='relations.json',reverse_relations='reverse-relations.json',
        limits=['Candidate evidence is a separate analysis layer, never an override of base/native geometry.',
            'Nested values are atomic; their numeric members are not promoted to independently verified properties.',
            'Opaque payload and omitted fields remain unknown; active variant/defaults/DPI/behavior are not inferred.'])
    return index,files


def materialize(root, base_folder, report_path, report_sha):
    base_path=base_folder/'index.json';base_raw=base_path.read_bytes();base=json.loads(base_raw)
    if base.get('schema')!=1 or base.get('phase')!='property_inventory':
        raise ValueError('Unsupported base property scan schema/phase')
    base_verifier.verify(root,base_folder)
    raw=reconciliation.source_audit.checked(report_path,report_sha);report=json.loads(raw)
    if report.get('schema')!=1 or report.get('kind')!='slot_candidate_evidence_reconciliation':
        raise ValueError('Unsupported reconciliation schema/kind')
    inp=report['inputs']
    reconciliation.source_audit.checked(Path(inp['source_audit']['path']),inp['source_audit']['sha256'])
    basic=inp.get('basic_evidence')
    repeated=reconciliation.build(root,Path(inp['source_audit']['path']),Path(inp['grid_evidence']['path']),
        inp['grid_evidence']['sha256'],Path(basic['path']) if basic else None,basic['sha256'] if basic else None)
    if repeated!=report:
        raise ValueError('Candidate reconciliation is stale or changed')
    cache={}
    variants=base['datasets'][base['dataset_id']]['variants']
    def exports(file):
        if file not in cache:
            entry=variants[file]
            catalog=json.loads(reconciliation.source_audit.checked(
                reconciliation.source_audit.inventory.child(root/'ui-catalog',file),entry['source']['catalog_sha256']))
            source=catalog.get('source_file',catalog['file'])
            stem=reconciliation.source_audit.inventory.child(root/'ui-layout-study',Path(source).stem)
            asset=reconciliation.source_audit.checked(stem.with_suffix('.uasset'),entry['source']['asset_sha256'])
            body=reconciliation.source_audit.checked(stem.with_suffix('.uexp'),entry['source']['body_sha256'])
            cache[file]={e['index']:e for e in reconciliation.source_audit.inspector.exports(asset,body)['exports']}
        return cache[file]
    index,files=compile_layer(base,report,exports)
    tool_names=['scan-ui-candidate-layer.py','verify-ui-property-scan.py','reconcile-ui-slot-evidence.py',
        'decode-basic-slot-candidates.py','decode-grid-slots.py','inspect-ui.py']
    tools={n:sha((HERE/n).read_bytes()) for n in tool_names}
    inputs=dict(base=dict(path=str(base_folder.resolve()),index_sha256=sha(base_raw)),
        reconciliation=dict(path=str(report_path.resolve()),sha256=report_sha))
    dataset_id=sha(encoded(dict(base_sha256=sha(base_raw),report_sha256=report_sha,tools=tools)))
    index.update(dataset_id=dataset_id,inputs=inputs,tools=tools,native_source=copy.deepcopy(report['inputs']['native_source']),
        files={k:sha(encoded(v)) for k,v in files.items()})
    if base_path.read_bytes()!=base_raw or report_path.read_bytes()!=raw:
        raise ValueError('Inputs changed during candidate layer compilation')
    files['index.json']=index
    return dataset_id,files


def compare(folder,files):
    actual={str(p.relative_to(folder)).replace('\\','/') for p in folder.rglob('*') if p.is_file()}
    if actual!=files.keys():
        raise ValueError('Layer file set differs')
    for name,value in files.items():
        if (folder/name).read_bytes()!=encoded(value):
            raise ValueError('Layer file differs: '+name)


def verify(root,folder):
    index=json.loads((folder/'index.json').read_bytes());inputs=index['inputs']
    dataset_id,files=materialize(root,Path(inputs['base']['path']),Path(inputs['reconciliation']['path']),inputs['reconciliation']['sha256'])
    if dataset_id!=index['dataset_id']:
        raise ValueError('Layer identity differs')
    compare(folder,files)
    return dict(state='passed',dataset_id=dataset_id,**index['statistics'])


def build(root,base,report,report_sha,output):
    dataset_id,files=materialize(root,base,report,report_sha)
    destination=output/dataset_id
    if destination.exists():
        compare(destination,files)
        reused=True
    else:
        destination.mkdir(parents=True)
        for name,value in files.items():
            path=destination/name;path.parent.mkdir(exist_ok=True,parents=True)
            with path.open('xb') as stream:stream.write(encoded(value))
        compare(destination,files);reused=False
    return dict(output=str(destination),dataset_id=dataset_id,reused=reused,**files['index.json']['statistics'])


def checklist(index):
    lines=['# Кандидатные свойства UI: отдельные проверки','',
        'Набор: `'+index['dataset_id']+'`.','',
        'Это дополнение к базовой матрице сканера. Все пункты первоначально открыты.',
        'Готовность каждого свойства: источник и чтение → наследование / defaults →',
        'применение через общий сборщик → проверка результата и актуальности версии.',
        'Кандидатные вложенные значения не считаются независимо подтверждёнными полями.',
        'Проверка переноса матрицы не закрывает эти пункты. ID не зависят от значения.','']
    for pid,p in sorted(index['properties'].items(),key=lambda item:item[1]['key']):
        lines.append('- [ ] '+pid+'. `'+p['key']+'` · наблюдений: '+str(p['observations'])+
            ' · пропусков: '+str(p['omitted_observations'])+' · типы: '+(', '.join(p['types']) or 'не наблюдались')+'.')
    return '\n'.join(lines)+'\n'


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=Path('F:/PhoneExit Resources/Vampir'))
    sub=p.add_subparsers(dest='operation',required=True)
    b=sub.add_parser('build');b.add_argument('--base',type=Path,required=True);b.add_argument('--reconciliation',type=Path,required=True)
    b.add_argument('--reconciliation-sha256',required=True);b.add_argument('--output',type=Path)
    b.add_argument('--tasks',type=Path)
    v=sub.add_parser('verify');v.add_argument('folder',type=Path)
    args=p.parse_args();root=args.root.resolve()
    if args.operation=='verify':result=verify(root,args.folder)
    else:
        if args.tasks and args.tasks.exists():
            p.error('Do not overwrite checklist statuses; use a new task path')
        output=(args.output or root/'ui-property-scans/candidate-layers').resolve()
        if any(output.is_relative_to(target.resolve()) for target in [HERE.parents[3],args.base,root/'ui-catalog',root/'ui-layout-study',root/'maps/ui-prototype']):
            p.error('Candidate layer must be outside source/base/repository/snapshot directories')
        result=build(root,args.base,args.reconciliation,args.reconciliation_sha256,output)
        if args.tasks:
            index=json.loads((Path(result['output'])/'index.json').read_bytes())
            with args.tasks.open('x',encoding='utf8') as stream:stream.write(checklist(index))
    print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':main()
