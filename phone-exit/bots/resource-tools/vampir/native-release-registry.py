"""Explicit native source history and typed executable projections.

The registry declares provenance and role identity; it never admits runtime.
"""
import hashlib
import json
from pathlib import Path
import re
import importlib.util

HERE = Path(__file__).resolve().parent
SHA = re.compile(r'[0-9a-f]{64}')
IDENTIFIER = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}')
ADDRESS = re.compile(r'0x[0-9a-f]+')


def read(knowledge=None, *, fallback=None):
    path = Path(knowledge or HERE/'knowledge')/'native-release-registry.json'
    if path.is_file():
        value = json.loads(path.read_text('utf-8'))
    elif fallback is not None:
        value = dict(schema=1, releases=[dict(id=key, order=int(key), source_sha256=sha)
            for key, sha in fallback.items()], family_aliases={}, projections=[], suite_adapters=[])
    else:
        raise ValueError('Native release registry is missing')
    validate(value)
    return value


def validate(value):
    if value.get('schema') != 1 or not isinstance(value.get('releases'), list):
        raise ValueError('Invalid native release registry schema')
    ids, hashes, orders = set(), set(), set()
    for item in value['releases']:
        if (set(item) != {'id','order','source_sha256'}
                or not isinstance(item['id'], str) or not IDENTIFIER.fullmatch(item['id'])
                or type(item['order']) is not int or item['order'] < 0
                or not isinstance(item['source_sha256'], str) or not SHA.fullmatch(item['source_sha256'])
                or item['id'] in ids or item['source_sha256'] in hashes or item['order'] in orders):
            raise ValueError('Invalid or duplicate native release declaration')
        ids.add(item['id']); hashes.add(item['source_sha256']); orders.add(item['order'])
    aliases=value.get('family_aliases', {})
    if not isinstance(aliases,dict) or any(version not in ids or not isinstance(items,dict)
            or any(not IDENTIFIER.fullmatch(a) or not isinstance(b,str) or not IDENTIFIER.fullmatch(b)
                   for a,b in items.items()) for version,items in aliases.items()):
        raise ValueError('Invalid native family aliases')
    for projection in value.get('projections', []):
        if (set(projection) != {'adapter','contract','release','keys','exports'}
                or projection['adapter'] != 'contract-functions-v1'
                or not isinstance(projection['contract'],str) or not IDENTIFIER.fullmatch(projection['contract'])
                or projection['release'] not in ids
                or not isinstance(projection['keys'],list) or not projection['keys']
                or len(projection['keys']) != len(set(projection['keys']))
                or any(not isinstance(key,str) or not IDENTIFIER.fullmatch(key) for key in projection['keys'])):
            raise ValueError('Invalid typed native projection')
        validate_exports(projection['exports'])
    for adapter in value.get('suite_adapters', []):
        if (not isinstance(adapter,dict) or set(adapter) - {'id','family','adapter','reason','context'}
                or not isinstance(adapter.get('id'),str) or not IDENTIFIER.fullmatch(adapter['id'])
                or adapter.get('adapter') not in ('utf8-v1','unsupported')
                or not isinstance(adapter.get('family'),str) or not IDENTIFIER.fullmatch(adapter['family'])
                or (adapter['adapter']=='unsupported' and not adapter.get('reason'))):
            raise ValueError('Invalid reviewed native suite adapter')
    return value


def validate_exports(exports):
    if not isinstance(exports,dict) or not exports or any(not isinstance(run,str)
            or Path(run).name != run or not run.startswith('run-') or not isinstance(sha,str)
            or not SHA.fullmatch(sha) for run,sha in exports.items()):
        raise ValueError('Invalid native projection exports')


def sources(knowledge=None, *, fallback=None):
    return {item['id']:item['source_sha256'] for item in sorted(read(knowledge,fallback=fallback)['releases'],key=lambda x:x['order'])}


def source_order(knowledge=None, *, fallback=None):
    return {item['source_sha256']:item['order'] for item in read(knowledge,fallback=fallback)['releases']}


def context_identity(path,context,registry):
    """Prefer explicit release/family metadata; suffixes remain legacy import only."""
    by_source={row['source_sha256']:row for row in registry['releases']}
    declared=context.get('release_id')
    family=context.get('family')
    if declared is not None or family is not None:
        if declared is None and context.get('source_sha256') in by_source:
            declared=by_source[context['source_sha256']]['id']
        if declared not in {row['id'] for row in registry['releases']} or not isinstance(family,str) or not IDENTIFIER.fullmatch(family):
            raise ValueError('Invalid explicit native context identity')
        return declared,family
    stem=Path(path).stem
    matches=[row for row in registry['releases'] if stem.endswith('-'+row['id'])]
    if len(matches)==1:return matches[0]['id'],stem[:-(len(matches[0]['id'])+1)]
    if context.get('source_sha256') in by_source:
        # New source-bound contexts need no numeric filename suffix.
        return by_source[context['source_sha256']]['id'],stem
    return None


def projected_contexts(knowledge,registry):
    """Only reviewed contract keys are executable; globals/fixtures are excluded."""
    path=Path(knowledge)/'update-contracts.json'
    if not registry.get('projections'):return []
    raw=path.read_bytes();model=json.loads(raw)
    contracts={item['id']:item for item in model['contracts']}
    releases={row['id']:row for row in registry['releases']}
    result=[]
    for spec in registry['projections']:
        contract=contracts.get(spec['contract'])
        source=releases[spec['release']]['source_sha256']
        bindings=(contract or {}).get('bindings',{}).get(source,{})
        recipes={row['key'] for row in (contract or {}).get('recipes',[])}
        if any(key not in recipes or not ADDRESS.fullmatch(bindings.get(key,'')) for key in spec['keys']):
            raise ValueError('Typed native projection differs from reviewed graph')
        identity=dict(graph_sha256=hashlib.sha256(raw).hexdigest(),projection=spec)
        result.append((str(path)+'#'+spec['contract']+'@'+spec['release'],dict(
            schema=1,source_sha256=source,release_id=spec['release'],family='contract:'+spec['contract'],
            functions={key:bindings[key] for key in spec['keys']},exports=spec['exports']),
            hashlib.sha256(json.dumps(identity,sort_keys=True).encode()).hexdigest()))
    return result


def generated_contexts(root,registry):
    """Import only content-addressed contexts with successful native receipts.

    The mutable file is merely an index. Its entries cannot elevate an adapter,
    a suite scope or an unverified source to a runtime capability.
    """
    root=Path(root).resolve();index=root/'knowledge/generated-native/index.json'
    if not index.is_file():return []
    value=json.loads(index.read_text('utf-8'))
    if value.get('schema')!=1 or not isinstance(value.get('contexts'),list) or len(value['contexts'])>4096:
        raise ValueError('Invalid generated native context index')
    result=[];seen=set()
    known={row['source_sha256']:row['order'] for row in registry['releases']}
    for item in value['contexts']:
        if set(item)!={'context','check','order'} or type(item['order']) is not int or item['order']<0:
            raise ValueError('Invalid generated native declaration')
        documents=[]
        for field,category in (('context','generated-native-contexts'),('check','native-adapter-checks')):
            declaration=item[field];path=Path(declaration['path']).resolve()
            if (not path.is_relative_to(root/'knowledge'/category) or path.name!='manifest.json'
                    or path.parent.name!=declaration['sha256']
                    or hashlib.sha256(path.read_bytes()).hexdigest()!=declaration['sha256']):
                raise ValueError('Generated native context receipt changed')
            documents.append(json.loads(path.read_text('utf-8')))
        context,check=documents;sha=context.get('source_sha256')
        if (not isinstance(sha,str) or not SHA.fullmatch(sha) or context.get('family')!='utf8'
                or check.get('source_sha256')!=sha or check.get('scope')!='bounded_native_utf8'
                or check.get('method')!='bounded_native' or check.get('runtime_activated') is not False
                or check.get('network_used') is not False or check.get('profile_activated') is not False
                or check.get('proof')!=context.get('native_admission')
                or len(check.get('cases',[]))!=142 or len(check.get('scalar_cases',[]))!=80
                or not all(row.get('guards') is True for row in check.get('cases',[])+check.get('scalar_cases',[]))):
            raise ValueError('Generated native context lacks its reviewed semantic proof')
        identity=(sha,context['family'])
        if identity in seen:raise ValueError('Duplicate generated native source/family')
        seen.add(identity)
        result.append((Path(item['context']['path']),context,known.get(sha,item['order'])))
    return result


def publish_generated(root,context,context_receipt,check_receipt):
    """Single-coordinator publication, only after execute() passed real vectors."""
    root=Path(root);path=root/'knowledge/generated-native/index.json'
    registry=read();old=json.loads(path.read_text('utf-8')) if path.is_file() else dict(schema=1,contexts=[])
    # Validate the previous index before retaining entries.
    generated_contexts(root,registry)
    known={row['source_sha256']:row['order'] for row in registry['releases']}
    existing=[]
    for item in old['contexts']:
        payload=json.loads(Path(item['context']['path']).read_text('utf-8'))
        if (payload.get('source_sha256'),payload.get('family'))!=(context['source_sha256'],context['family']):existing.append(item)
    rank=known.get(context['source_sha256'],max([row['order'] for row in registry['releases']]+[x['order'] for x in existing])+1)
    existing.append(dict(context=context_receipt,check=check_receipt,order=rank))
    value=dict(schema=1,contexts=sorted(existing,key=lambda item:(item['order'],item['context']['path'])))
    spec=importlib.util.spec_from_file_location('generated_native_workflow',HERE/'research-workflow.py')
    workflow=importlib.util.module_from_spec(spec);spec.loader.exec_module(workflow)
    workflow.atomic(path,workflow.canonical(value))
    generated_contexts(root,registry)
    return dict(path=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest())
