"""Revalidate the selected immutable Version flow dependencies on cache hits."""
import copy
import hashlib
from pathlib import Path


CHECK = 'native-version-result-handler-context'


def run(index, workflow, args, sha, definition):
    if definition['id'] != CHECK or workflow.source_scope(definition) != 'client':
        raise ValueError('Version flow requires its source-bound handler check')
    path = index.child(Path(args.knowledge), definition['version_flow_contexts'][sha])
    effective = workflow.source_definition(definition, sha)
    if path.relative_to(index.HERE.parents[3].resolve()).as_posix() not in effective['dependencies']:
        raise ValueError('Version flow context is not a check dependency')
    files = {str(path): index.digest(path)}
    context = index.read_json(path)
    if context.get('source_sha256') != sha or context.get('recipe') != 'version-result-flow-v1':
        raise ValueError('Version flow context source differs')
    pointers = [context['baseline']]
    for role in ('input', 'gate'):
        pointers += [context[role]['context'], context[role]['check']]
    for pointer in pointers:
        selected = Path(pointer['path']).resolve()
        if not (selected.is_relative_to(args.root.resolve() / 'knowledge')
                or selected.is_relative_to(args.knowledge.resolve() / 'native-contexts')):
            raise ValueError('Version flow proof outside research directories')
        if index.digest(selected) != pointer['sha256']:
            raise ValueError('Version flow proof SHA changed')
        files[str(selected)] = pointer['sha256']
    # The native adapters validate their own closure and tool identities.
    # Retain their immutable proof manifests so a cached parent cannot hide corruption.
    for role in ('input', 'gate'):
        parent = index.read_json(context[role]['context']['path'])
        pointer = parent['transfer_proof']
        selected = Path(pointer['path']).resolve()
        if not selected.is_relative_to(args.root.resolve() / 'knowledge') or index.digest(selected) != pointer['sha256']:
            raise ValueError('Version flow transfer proof changed')
        files[str(selected)] = pointer['sha256']
    outcomes = workflow.run_checks(index, args, sha, None, check_ids=[CHECK])
    if any(index.digest(Path(name)) != expected for name, expected in files.items()):
        raise ValueError('Version flow material changed during check')
    results = []
    for outcome in outcomes:
        if 'report' not in outcome:
            results.append(outcome)
            continue
        original = workflow.checked_manifest(index, Path(outcome['report']))
        if index.digest(Path(outcome['report'])) != outcome['sha256']:
            raise ValueError('Version flow parent check changed')
        report = copy.deepcopy(original)
        artifacts = report['definition']['artifacts']
        if any(name in artifacts and artifacts[name] != expected for name, expected in files.items()):
            raise ValueError('Version flow artifact declarations conflict')
        artifacts.update(files)
        report['version_flow_guard'] = dict(recipe='version-result-flow-v1', context_sha256=files[str(path)])
        saved = workflow.snapshot(args.root, 'check-results', report)
        results.append(dict(outcome, report=str(saved), sha256=index.digest(saved),
            cache_key=hashlib.sha256(workflow.canonical(report['definition'])).hexdigest()))
    return results
