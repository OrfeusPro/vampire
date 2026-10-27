"""Declarative update dependencies; recipes name data, never executable commands."""
import fnmatch
import re

SHA = re.compile(r'[0-9a-f]{64}')
ID = re.compile(r'[a-z][a-z0-9_-]*')
METHODS = {'anchor', 'prefix', 'direct_call', 'vtable', 'reviewed'}


def load(index, knowledge):
    data = index.read_json(knowledge/'update-contracts.json')
    if data.get('schema') != 1 or not isinstance(data.get('contracts'), list):
        raise ValueError('Unsupported update contracts')
    checks = index.read_json(knowledge/'research-checks.json')['checks']
    check_ids = [c['id'] for c in checks]
    scopes = {c['id']: index.extension('research-workflow').source_scope(c) for c in checks}
    plans = [knowledge/'release-update-targets.json']
    primary = index.read_json(plans[0])
    for name in primary.get('additional_target_plans', []):
        plans.append(index.child(knowledge, name))
    anchors = {a['id'] for p in plans for a in index.read_json(p).get('anchors', [])}
    targets={t['id'] for p in plans for t in index.read_json(p).get('manual_port_targets',[])}
    ids = [c['id'] for c in data['contracts']]
    if len(ids) != len(set(ids)) or any(not ID.fullmatch(v) for v in ids):
        raise ValueError('Duplicate or invalid contract ID')
    if len(check_ids) != len(set(check_ids)):
        raise ValueError('Duplicate check ID')
    capabilities = data.get('capabilities', {})
    for name, capability in capabilities.items():
        if not ID.fullmatch(name) or not capability.get('requires') or any(x not in ids for x in capability['requires']):
            raise ValueError('Invalid capability requirements')
    for c in data['contracts']:
        for field in ('purpose', 'limits', 'next_check'):
            if not c.get(field): raise ValueError('Missing contract field: '+field)
        if any(x not in ids or x == c['id'] for x in c['depends_on']):
            raise ValueError('Unknown contract dependency')
        if any(x not in check_ids for x in c['checks']):
            raise ValueError('Unknown contract check')
        if any(scopes[x] == 'tooling' for x in c['checks']):
            raise ValueError('Tooling check cannot establish a client contract')
        if any(t not in targets for t in c.get('targets',[])):
            raise ValueError('Unknown reviewed target reference')
        for recipe in c['recipes']:
            if recipe.get('method') not in METHODS or not ID.fullmatch(recipe.get('key', '')):
                raise ValueError('Unknown binding recipe')
            if recipe['method'] == 'anchor' and recipe.get('anchor') not in anchors:
                raise ValueError('Unknown anchor reference')
        keys = [r['key'] for r in c['recipes']]
        if len(keys) != len(set(keys)): raise ValueError('Duplicate binding key')
        for sha, bindings in c['bindings'].items():
            if not SHA.fullmatch(sha): raise ValueError('Contract needs full source SHA')
            if any(k not in keys or index.address(v) != v for k, v in bindings.items()):
                raise ValueError('Invalid reviewed binding')
        for sha, dependencies in c.get('data_dependencies',{}).items():
            if not SHA.fullmatch(sha):raise ValueError('Data dependency needs full source SHA')
            for key,spec in dependencies.items():
                if not ID.fullmatch(key) or not spec.get('kind') or index.address(spec.get('address'))!=spec['address']:
                    raise ValueError('Invalid data dependency')
        if c.get('builder') not in (None, 'sdk-launcher'):
            raise ValueError('Unreviewed profile builder')
        if c.get('builder')=='sdk-launcher':
            reports=c.get('profile_reports',{})
            if set(reports)!={'defaults','override','platform','start','url','headers','nid_base','nid_helpers','geo'}:
                raise ValueError('Missing or unknown profile report role')
            for spec in reports.values():
                pattern=spec.get('pattern','')
                if (not isinstance(pattern,str) or not pattern.startswith('code-clues/') or '..' in pattern or
                    not pattern.endswith('/*/manifest.json') or type(spec.get('min_cases')) is not int or spec['min_cases']<1):
                    raise ValueError('Invalid profile report selector')
        if any(x not in ('version-login-tag','packet-writer-projection') for x in c.get('context_checks',[])):
            raise ValueError('Unreviewed context check')
        for resource in c.get('resources', []):
            if not isinstance(resource.get('archive'), str) or not isinstance(resource.get('path'), str):
                raise ValueError('Resource needs archive and logical path patterns')
    ordered = []
    pending = dict(zip(ids, data['contracts']))
    while pending:
        ready = sorted(k for k, c in pending.items() if all(d in ordered for d in c['depends_on']))
        if not ready: raise ValueError('Contract dependency cycle')
        for k in ready: ordered.append(k); del pending[k]
    data['order'] = ordered
    return data


def affected(data, *, exe_changed, changes):
    """Unknown archive contents conservatively affect its declared consumers."""
    dirty = set()
    for c in data['contracts']:
        if exe_changed and c['recipes']: dirty.add(c['id'])
        for dep in c.get('resources', []):
            for change in changes:
                if not fnmatch.fnmatchcase(change['archive'].replace('\\', '/'), dep['archive']): continue
                paths = change.get('paths')
                if paths is None or any(fnmatch.fnmatchcase(p, dep['path']) for p in paths):
                    dirty.add(c['id'])
    for name in data['order']:
        c = next(c for c in data['contracts'] if c['id'] == name)
        if any(d in dirty for d in c['depends_on']): dirty.add(name)
    return [name for name in data['order'] if name in dirty]


def readiness(data, outcomes):
    return {name: dict(state='prepared_offline' if all(outcomes.get(c, {}).get('state') == 'passed'
        for c in cap['requires']) else 'incomplete',
        missing=[c for c in cap['requires'] if outcomes.get(c, {}).get('state') != 'passed'],
        live_verified=False) for name, cap in data['capabilities'].items()}
