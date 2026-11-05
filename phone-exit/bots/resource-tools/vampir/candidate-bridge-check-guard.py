"""Retain complete source-proof bridge inputs around a cached scoped check."""
import copy
import hashlib
from pathlib import Path


CHECK = 'candidate-proof-bridges-current'


def runtime_inputs(index, root, report, identifier):
    if identifier != CHECK or report['definition']['check']['id'] != CHECK:
        raise ValueError('Candidate bridge runtime requires its registered check')
    tool = index.extension('candidate-proof-bridges')
    proof = tool.checked(root, report['candidate_bridge_guard']['proof'], 'candidate-proof-bridges-v1')
    files = proof['files']
    result = {}
    for path in index.extension('native-publication-v2').runtime_files():
        name = str(path.resolve())
        expected = files.get(name)
        if (expected is None or report['definition']['artifacts'].get(name) != expected
                or index.digest(path) != expected):
            raise ValueError('Candidate bridge runtime identity differs')
        result[name] = expected
    return result


def run(index, workflow, args, sha, definition):
    if definition['id'] != CHECK or workflow.source_scope(definition) != 'client':
        raise ValueError('Candidate bridge guard requires its registered check')
    selection = index.child(args.knowledge, definition['candidate_bridge_profiles'][sha])
    selected_sha = index.digest(selection)
    selected = index.read_json(selection)
    effective = workflow.source_definition(definition, sha)
    if (set(selected) != {'schema', 'source_sha256', 'context', 'proof'} or selected['schema'] != 1
            or selected['source_sha256'] != sha
            or selection.relative_to(index.HERE.parents[3].resolve()).as_posix() not in effective['dependencies']):
        raise ValueError('Candidate bridge selection source or dependencies differ')
    context_path = Path(selected['context']['path']).resolve()
    if not context_path.is_relative_to(args.knowledge.resolve() / 'native-contexts'):
        raise ValueError('Candidate bridge context path differs')
    if index.digest(context_path) != selected['context']['sha256']:
        raise ValueError('Candidate bridge context SHA changed')
    context = index.read_json(context_path)
    tool = index.extension('candidate-proof-bridges')
    report = tool.checked(args.root, selected['proof'], 'candidate-proof-bridges-v1')
    if report.get('context_sha256') != selected['context']['sha256']:
        raise ValueError('Candidate bridge proof context differs')
    tool.validate_saved(context, report)
    retained = {**report['files'], str(context_path): selected['context']['sha256'],
        selected['proof']['path']: selected['proof']['sha256'], str(selection): selected_sha}
    outcomes = workflow.run_checks(index, args, sha, None, check_ids=[CHECK])
    tool.validate_saved(context, report)
    if any(index.digest(Path(name)) != expected for name, expected in retained.items()):
        raise ValueError('Candidate bridge inputs changed during check')
    results = []
    for outcome in outcomes:
        if 'report' not in outcome:
            results.append(outcome)
            continue
        original = workflow.checked_manifest(index, Path(outcome['report']))
        if index.digest(Path(outcome['report'])) != outcome['sha256']:
            raise ValueError('Candidate bridge parent report changed')
        guarded = copy.deepcopy(original)
        artifacts = guarded['definition']['artifacts']
        if any(name in artifacts and artifacts[name] != expected for name, expected in retained.items()):
            raise ValueError('Candidate bridge artifacts conflict')
        artifacts.update(retained)
        guarded['candidate_bridge_guard'] = dict(recipe=tool.RECIPE, proof=selected['proof'])
        path = workflow.snapshot(args.root, 'check-results', guarded)
        results.append(dict(outcome, report=str(path), sha256=index.digest(path),
            cache_key=hashlib.sha256(workflow.canonical(guarded['definition'])).hexdigest()))
    return results
