"""Check immutable SDK Launcher profile inputs even on source-check cache hits."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import sys


CHECK = 'sdk-runtime-launcher-11316'


def runtime_inputs(index, root, report, identifier):
    if identifier != CHECK or report['definition']['check']['id'] != CHECK:
        raise ValueError('SDK Launcher runtime requires its registered check')
    pointer = report['sdk_launcher_guard']['profile']
    api = loader(index)
    sha = report['definition']['source_sha256']
    expected_path = Path(root).resolve() / 'sdk-launcher-profiles' / pointer['sha256'] / 'manifest.json'
    if Path(pointer['path']).resolve() != expected_path:
        raise ValueError('SDK Launcher runtime profile path differs')
    profile = api.load_manifest(profile_sha256=pointer['sha256'], source_sha256=sha,
        root=root, workspace=index.HERE.parents[3].resolve())
    paths = (Path(sys.executable).resolve(), api.INSTALLED.resolve())
    result = {}
    for path in paths:
        expected = profile['inputs'].get(str(path))
        if (expected is None or report['definition']['artifacts'].get(str(path)) != expected
                or index.digest(path) != expected):
            raise ValueError('SDK Launcher runtime identity differs')
        result[str(path)] = expected
    if result[str(api.INSTALLED.resolve())] != sha:
        raise ValueError('SDK Launcher runtime installed SHA differs')
    return result


def loader(index):
    path = index.HERE.parents[1] / 'vampir-headless/sdk-launcher-profile.py'
    spec = importlib.util.spec_from_file_location('guard_sdk_launcher_profile', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(index, workflow, args, sha, definition):
    if definition['id'] != CHECK or workflow.source_scope(definition) != 'client':
        raise ValueError('SDK Launcher guard requires its source-bound check')
    path = index.child(Path(args.knowledge), definition['sdk_launcher_profiles'][sha])
    effective = workflow.source_definition(definition, sha)
    workspace = index.HERE.parents[3].resolve()
    if path.relative_to(workspace).as_posix() not in effective['dependencies']:
        raise ValueError('SDK Launcher selection is not a check dependency')
    raw = path.read_bytes()
    selected = index.read_json(path)
    if (set(selected) != {'schema', 'source_sha256', 'profile'}
            or selected['schema'] != 1 or selected['source_sha256'] != sha
            or set(selected['profile']) != {'path', 'sha256'}):
        raise ValueError('SDK Launcher selection source or schema differs')
    pointer = selected['profile']
    manifest = args.root.resolve() / 'sdk-launcher-profiles' / pointer['sha256'] / 'manifest.json'
    if Path(pointer['path']).resolve() != manifest:
        raise ValueError('SDK Launcher selected profile path differs')
    api = loader(index)
    options = dict(profile_sha256=pointer['sha256'], source_sha256=sha,
        root=args.root, workspace=workspace)
    profile = api.load_manifest(**options)
    retained = {**profile['inputs'], str(path): hashlib.sha256(raw).hexdigest(),
        str(manifest): pointer['sha256']}
    outcomes = workflow.run_checks(index, args, sha, None, check_ids=[CHECK])
    if (api.load_manifest(**options) != profile or path.read_bytes() != raw
            or any(index.digest(Path(name)) != expected for name, expected in retained.items())):
        raise ValueError('SDK Launcher inputs changed during source check')
    results = []
    for outcome in outcomes:
        if 'report' not in outcome:
            results.append(outcome)
            continue
        original = workflow.checked_manifest(index, Path(outcome['report']))
        if index.digest(Path(outcome['report'])) != outcome['sha256']:
            raise ValueError('SDK Launcher parent check report changed')
        report = copy.deepcopy(original)
        artifacts = report['definition']['artifacts']
        if any(name in artifacts and artifacts[name] != expected for name, expected in retained.items()):
            raise ValueError('SDK Launcher artifact declarations conflict')
        artifacts.update(retained)
        report['sdk_launcher_guard'] = dict(recipe='sdk-launcher-runtime-v1', profile=pointer)
        saved = workflow.snapshot(args.root, 'check-results', report)
        results.append(dict(outcome, report=str(saved), sha256=index.digest(saved),
            cache_key=hashlib.sha256(workflow.canonical(report['definition'])).hexdigest()))
    return results
