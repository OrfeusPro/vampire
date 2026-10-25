"""Build reusable component priority and consumer indices from verified source-root partitions."""
import argparse
from pathlib import Path
import importlib.util
import hashlib
import json

HERE=Path(__file__).resolve().parent


def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


scope_tool=load('consumer_scope_tool','scan-ui-outer-scopes.py')
composition=load('consumer_composition','ui_composition_graph.py')
consumers=load('consumer_indices','ui_component_consumers.py')


def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode('utf8')


def build(root,scope_folder,output):
    scope_tool.verify(root,scope_folder)
    raw=(scope_folder/'index.json').read_bytes();scope=json.loads(raw)
    inputs=scope['inputs'];audit=json.loads(scope_tool.audit_tool.checked(Path(inputs['audit_path']),inputs['audit_sha256']))
    snapshot=Path(audit['snapshot']['path'])
    manifest=json.loads(scope_tool.audit_tool.checked(snapshot/'manifest.json',audit['snapshot']['manifest_sha256']))
    rows=json.loads(scope_tool.audit_tool.checked(snapshot/'registry-index.json',manifest['generated_files']['registry-index.json']))
    records=[];quarantine={}
    for row in rows:
        relative='windows/'+row['id']+'.json'
        record=json.loads(scope_tool.audit_tool.checked(snapshot/relative,manifest['generated_files'][relative]))
        projected=[]
        for variant in record['variants']:
            entry=scope['variants'][variant['file']]
            view=json.loads(scope_tool.audit_tool.checked(scope_folder/entry['ref'],scope['files'][entry['ref']]))
            value,diagnostics=scope_tool.outer.project_variant(variant,view)
            projected.append(value)
            if diagnostics['requires_review']:quarantine[record['path']+'|'+variant['file']]=diagnostics
        record['variants']=projected;records.append(record)
    graph=composition.compile_graph(records)
    result=consumers.compile_consumers(graph)
    result.update(inputs=dict(scope_layer=str(scope_folder.resolve()),scope_index_sha256=sha(raw),snapshot=audit['snapshot']),
        tools={p.name:sha(p.read_bytes()) for p in [Path(__file__),HERE/'ui_component_consumers.py',HERE/'ui_composition_graph.py',HERE/'scan-ui-outer-scopes.py',HERE/'ui_outer_scope.py']},
        quarantine=quarantine,source_root_not_runtime_root=True)
    identity=sha(encoded(result));destination=output/identity
    result['dataset_id']=identity
    files={'index.json':result,'composition-graph.json':graph}
    if not destination.exists():
        destination.mkdir(parents=True)
        for name,value in files.items():
            with (destination/name).open('xb') as stream:stream.write(encoded(value))
    for name,value in files.items():
        if (destination/name).read_bytes()!=encoded(value):raise ValueError('Published consumer layer differs: '+name)
    if {p.name for p in destination.iterdir()}!=files.keys():raise ValueError('Unexpected consumer layer files')
    return dict(output=str(destination),dataset_id=identity,**result['statistics'],
        top=[dict(class_name=k,resources=result['classes'][k]['consumer_resource_count']) for k in result['priority'][:12]])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,default=Path('F:/PhoneExit Resources/Vampir'))
    p.add_argument('--scopes',type=Path,required=True);p.add_argument('--output',type=Path)
    a=p.parse_args();out=(a.output or a.root/'ui-property-scans/component-consumers').resolve()
    if any(out.is_relative_to(t.resolve()) for t in [HERE.parents[3],a.scopes,a.root/'ui-catalog',a.root/'ui-layout-study',a.root/'maps/ui-prototype']):p.error('Use an external analysis directory')
    print(json.dumps(build(a.root,a.scopes,out),ensure_ascii=False))
