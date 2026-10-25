"""Build immutable source-Outer partitions for all catalog variants, never runtime selection."""
import argparse
from collections import Counter, defaultdict
import hashlib
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent


def load(name,file):
    s=importlib.util.spec_from_file_location(name,HERE/file)
    m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m


audit_tool=load('outer_scope_audit','audit-ui-sources.py')
outer=load('outer_scope_compiler','ui_outer_scope.py')


def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode('utf8')


def derive(root,audit_path,audit_sha):
    raw=audit_tool.checked(audit_path,audit_sha);audit=json.loads(raw)
    if audit.get('schema')!=1 or audit.get('kind')!='automated_ui_source_audit' or audit['selection'].get('scope')!='all':
        raise ValueError('Expected full catalog source audit')
    for name,expected in audit['tools'].items():
        audit_tool.checked(audit_tool.inventory.child(HERE,name),expected)
    snapshot=Path(audit['snapshot']['path'])
    manifest=json.loads(audit_tool.checked(snapshot/'manifest.json',audit['snapshot']['manifest_sha256']))
    inventory=audit_tool.inventory.build(root,snapshot)
    expected={row['task_id']:row for row in inventory['records']}
    if len(audit['records'])!=len(expected) or {row['task_id'] for row in audit['records']}!=expected.keys():
        raise ValueError('Source audit does not cover inventory')
    files,packages,variants,physical,consumers={}, {}, {}, {}, defaultdict(list)
    totals=Counter()
    for row in audit['records']:
        source_row=expected[row['task_id']]
        if row['path']!=source_row['path'] or row['name']!=source_row['name'] or sorted(v['file'] for v in row['variants'])!=sorted(source_row['source_variant_files']):
            raise ValueError('Audit identity/variants differ from inventory')
        record_id=row['task_id'].removeprefix('UI-');relative='windows/'+record_id+'.json'
        published=json.loads(audit_tool.checked(snapshot/relative,manifest['generated_files'][relative]))
        if published['path']!=row['path'] or published['name']!=row['name']:
            raise ValueError('Published resource differs from inventory')
        published_variants={v['file']:v for v in published['variants']}
        for variant in row['variants']:
            if 'error' in variant:raise ValueError('Source audit contains unverified errors')
            file=variant['file']
            if Path(file).name!=file or file in variants:raise ValueError('Unsafe/duplicate catalog variant')
            p=audit_tool.inventory.child(root/'ui-catalog',file)
            catalog=json.loads(audit_tool.checked(p,variant['source']['catalog_sha256']))
            for field in ('asset_sha256','body_sha256'):
                if catalog[field]!=variant['source'][field]:raise ValueError('Source hashes differ')
            if sha(p.read_bytes())!=inventory['sources']['catalog_files'][file]['sha256']:
                raise ValueError('Catalog differs from inventory')
            source_file=catalog.get('source_file',catalog['file'])
            if Path(source_file).name!=source_file:raise ValueError('Unsafe physical source name')
            key=source_file+'|'+catalog['asset_sha256']+'|'+catalog['body_sha256']
            pid=sha(key.encode())
            if pid not in packages:
                stem=audit_tool.inventory.child(root/'ui-layout-study',Path(source_file).stem)
                asset=audit_tool.checked(stem.with_suffix('.uasset'),catalog['asset_sha256'])
                body=audit_tool.checked(stem.with_suffix('.uexp'),catalog['body_sha256'])
                exports=audit_tool.inspector.exports(asset,body)['exports']
                ownership=outer.compile_ownership(exports)
                packages[pid]=dict(source_file=source_file,asset_sha256=catalog['asset_sha256'],body_sha256=catalog['body_sha256'],
                    ref='packages/'+pid+'.json',roots=len(ownership['roots']))
                physical[pid]=ownership;files[packages[pid]['ref']]=ownership
                totals.update(packages=1,source_exports=len(exports),source_roots=len(ownership['roots']),outer_issues=len(ownership['issues']))
            ownership=physical[pid]
            view=outer.partition(catalog,ownership)
            view.update(source=dict(catalog_file=file,catalog_sha256=variant['source']['catalog_sha256'],package=pid),
                task_id=row['task_id'],resource_path=row['path'])
            published_variant=published_variants[file]
            if published_variant['sha256']!=variant['source']['catalog_sha256']:
                raise ValueError('Published variant differs from source')
            projected,scope=outer.project_variant(published_variant,view)
            schema=audit_tool.ui_layout_schema.compile_schema(published,projected)
            schema['source_scope']=scope
            schema['unresolved'].append('source_root_does_not_select_runtime_visible_root')
            files['schemas/'+file]=schema
            ref='variants/'+file;files[ref]=view
            variants[file]=dict(ref=ref,package=pid,source_root=view['selected_source_root'],
                catalog_sha256=variant['source']['catalog_sha256'],resource_path=row['path'],task_id=row['task_id'])
            consumers[pid+'#'+str(view['selected_source_root'])].append(file)
            totals.update(variants=1,multi_root_variants=int(len(ownership['roots'])>1),cross_scope_relations=len(view['cross_scope_relations']))
            for category,groups in view['groups'].items():
                for state,values in groups.items():totals[category+'_'+state]+=len(values)
    tools={p.name:sha(p.read_bytes()) for p in [Path(__file__),HERE/'ui_outer_scope.py',HERE/'ui_layout_schema.py',HERE/'inspect-ui.py',HERE/'audit-ui-sources.py',HERE/'inventory-ui-names.py']}
    dataset_id=sha(encoded(dict(audit_sha256=audit_sha,index_sha256=inventory['sources']['catalog_index']['sha256'],tools=tools)))
    index=dict(schema=1,kind='ui_source_outer_scope_layer',dataset_id=dataset_id,
        inputs=dict(audit_path=str(audit_path.resolve()),audit_sha256=audit_sha,snapshot=audit['snapshot']),
        tools=tools,packages=packages,variants=variants,root_consumers=dict(consumers),statistics=dict(totals),
        runtime_visible_root=None,geometry_verified=False,implementation_verified=False,
        files={name:sha(encoded(value)) for name,value in files.items()},
        limits=['Source Outer branches only; no runtime root, widget parent, slot order, visibility or layout inferred.',
            'Catalogs and prior snapshots are unchanged; foreign/unowned/unresolved exports remain explicit.'])
    files['index.json']=index
    return dataset_id,files


def compare(folder,files):
    actual={str(p.relative_to(folder)).replace('\\','/') for p in folder.rglob('*') if p.is_file()}
    if actual!=files.keys():raise ValueError('Outer layer file set differs')
    for name,value in files.items():
        if (folder/name).read_bytes()!=encoded(value):raise ValueError('Outer layer file differs: '+name)


def build(root,audit_path,audit_sha,output):
    identity,files=derive(root,audit_path,audit_sha);destination=output/identity
    reused=destination.exists()
    if not reused:
        destination.mkdir(parents=True)
        for name,value in files.items():
            target=destination/name;target.parent.mkdir(exist_ok=True,parents=True)
            with target.open('xb') as stream:stream.write(encoded(value))
    compare(destination,files)
    return dict(output=str(destination),dataset_id=identity,reused=reused,**files['index.json']['statistics'])


def verify(root,folder):
    index=json.loads((folder/'index.json').read_bytes())
    if index.get('schema')!=1 or index.get('kind')!='ui_source_outer_scope_layer':raise ValueError('Unsupported Outer layer')
    identity,files=derive(root,Path(index['inputs']['audit_path']),index['inputs']['audit_sha256'])
    if identity!=index['dataset_id']:raise ValueError('Outer layer identity differs')
    compare(folder,files)
    return dict(state='passed',dataset_id=identity,**index['statistics'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=Path('F:/PhoneExit Resources/Vampir'))
    sub=p.add_subparsers(dest='operation',required=True)
    b=sub.add_parser('build');b.add_argument('--audit',type=Path,required=True);b.add_argument('--audit-sha256',required=True);b.add_argument('--output',type=Path)
    v=sub.add_parser('verify');v.add_argument('folder',type=Path)
    args=p.parse_args();root=args.root.resolve()
    if args.operation=='verify':result=verify(root,args.folder)
    else:
        output=(args.output or root/'ui-property-scans/outer-scopes').resolve()
        if any(output.is_relative_to(t.resolve()) for t in [HERE.parents[3],root/'ui-catalog',root/'ui-layout-study',root/'maps/ui-prototype']):
            p.error('Keep Outer layers outside source/repository/snapshot directories')
        result=build(root,args.audit,args.audit_sha256,output)
    print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':main()
