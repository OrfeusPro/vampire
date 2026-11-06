"""Retain current entry native proofs on cold and cached source checks."""
import copy
import hashlib
import json
from pathlib import Path
import sys

IDS = {'character-list-current', 'clock-world-current', 'viper-class-current', 'lobby-metadata-current'}
EXTRA_IDS = {'create-packets-current', 'viper-cdo-current', 'lobby-wire-current'}
CANDIDATE = 'game-candidate-current'
CHECKS = IDS | EXTRA_IDS | {CANDIDATE}
RECIPE = 'entry-current-check-guard-v1'


def runtime_alias(current, retained):
    if current == retained:
        return current
    before, after = dict(retained), dict(current)
    old, new = before.pop('executable', None), after.pop('executable', None)
    if (before != after or not isinstance(old,str) or not isinstance(new,str)
            or not Path(old).is_file() or not Path(new).is_file() or not Path(old).samefile(new)):
        raise ValueError('Current proof runtime changed')
    return retained


def character_report(api, path, root):
    """Retain the historical producer, allowing only the same interpreter file."""
    report = api.checked(dict(path=str(path),sha256=api.digest(path)),root,'character-list-current-bounded')
    if (report.get('recipe')!=api.RECIPE or report.get('source_sha256')!=api.SOURCE
            or report.get('method')!='bounded_native' or report.get('semantic_verification') is not True
            or any(report.get(key) is not False for key in ('network_used','runtime_admitted','profile_activated','live_verified'))
            or set(report.get('reports',{}))!=set(api.NAMES) or not report.get('limits')):
        raise ValueError('Current CharacterList report boundary differs')
    _, expected = api.materials(report['definition']['generated']['path'],root)
    runtime_alias(expected,report['definition'])
    for name, component in report['reports'].items():
        api.validate_report(name,component)
    return report


def candidate_material(proof, pointer, installed):
    # The scoped receipt has a smaller per-file budget than the installed PAK.
    # The candidate verifier streams the PAK hash and retains it in its manifest.
    archive = Path(installed).resolve().parents[3] / 'ProjectRED/Content/Paks/ProjectRED-Windows.pak'
    return {**{name: sha for name, sha in proof['inputs'].items() if Path(name).resolve() != archive},
            pointer['path']: pointer['sha256']}


def retained(index, root, knowledge, definition, sha):
    identifier = definition['id']
    if identifier not in CHECKS:
        raise ValueError('Unknown current entry source check')
    workspace = index.HERE.parents[3].resolve()
    selector = index.child(knowledge, definition['entry_current_contexts'][sha])
    effective = index.extension('research-workflow').source_definition(definition, sha)
    if selector.relative_to(workspace).as_posix() not in effective['dependencies']:
        raise ValueError('Current entry selector is not a dependency')
    if identifier == CANDIDATE:
        api = index.extension('build-game-candidate-current')
        path, expected, proof = api.publish(selector, root=root)
        if proof['source_sha256'] != sha or proof['inputs'].get(str(selector.resolve())) != index.digest(selector):
            raise ValueError('Current game candidate source or selector changed')
        pointer = dict(path=str(path.resolve()), sha256=expected)
        return candidate_material(proof, pointer, index.INSTALL), pointer
    raw = selector.read_bytes()
    selected = index.read_json(selector)
    if (selected.get('schema') != 1 or selected.get('source_sha256') != sha
            or set(selected.get('proofs', {})) != (IDS if identifier in IDS else EXTRA_IDS)):
        raise ValueError('Current entry selector scope differs')
    pointer = selected['proofs'][definition['id']]
    path = Path(pointer['path']).resolve()
    if set(pointer) != {'path', 'sha256'} or index.digest(path) != pointer['sha256']:
        raise ValueError('Current entry proof changed')
    material = {}

    def merge(values):
        for name, value in values.items():
            if name in material and material[name] != value:
                raise ValueError('Current entry retained inputs conflict')
            material[name] = value

    if definition['id'] == 'character-list-current':
        api = index.extension('verify-character-list-current')
        proof = character_report(api, path, root)
        native_definition = proof['definition']
        merge(native_definition['inputs'])
        merge(native_definition['files'])
        generated_pointer = native_definition['generated']
        generated = api.checked(generated_pointer, root, 'character-list-current-generated')
        merge({generated_pointer['path']: generated_pointer['sha256']})
        merge({generated['scope']['path']: generated['scope']['sha256']})
    elif definition['id'] == 'clock-world-current':
        api = index.extension('run-clock-world-current')
        _, native_definition = api.inputs(root)
        native_definition = runtime_alias(native_definition,json.loads(path.read_bytes())['definition'])
        proof = api.verify_report(path, pointer['sha256'], native_definition, root)
        merge(native_definition['files'])
        merge(native_definition['exports'])
        source = Path(root).resolve() / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'
        merge({str(source): sha})
        merge({row['path']: row['sha256'] for row in proof['components'].values()})
    elif identifier in EXTRA_IDS:
        category = identifier + '-v1'
        if path != Path(root).resolve() / 'code-clues' / category / pointer['sha256'] / 'manifest.json':
            raise ValueError('Current extension proof path differs')
        proof = index.read_json(path)
        if (proof.get('recipe') != category or proof.get('native_execution') is not True
                or proof.get('runtime_admitted') is not False or proof.get('network_used') is not False):
            raise ValueError('Current extension proof scope differs')
        if identifier == 'create-packets-current':
            api = index.extension('verify-create-packets-current')
            api.verify_report(path, root=root)
            merge(proof['definition']['inputs'])
        elif identifier == 'lobby-wire-current':
            api = index.extension('verify-lobby-wire-current')
            context, native_definition = api.definition(api.CONTEXT, root)
            api.validate(proof)
            if native_definition != proof['definition']:
                raise ValueError('Current lobby wire proof inputs differ')
            merge(native_definition['inputs'])
            char = index.extension('verify-character-list-current')
            previous = char.verify_report(context['reuse']['character_list']['path'], root=root, workspace=workspace)
            generated_pointer = previous['definition']['generated']
            generated = char.checked(generated_pointer, root, 'character-list-current-generated')
            merge({generated_pointer['path']: generated_pointer['sha256'],
                   generated['scope']['path']: generated['scope']['sha256']})
        else:
            if (len(proof.get('allocation_cases', [])) != 6 or len(proof.get('ordinary_cases', [])) != 18
                    or proof.get('source_CDO_is_fixture') is not True
                    or proof.get('loaded_preset_verified') is not False
                    or proof.get('complete_viper_payload_verified') is not False):
                raise ValueError('Current CDO proof coverage differs')
            merge(proof['inputs'])
    else:
        proof = index.read_json(path)
        identifier = definition['id']
        category = 'viper-class-current-v1' if identifier == 'viper-class-current' else 'lobby-metadata-current-v1'
        if (path.parent.parent != Path(root).resolve() / 'code-clues' / category
                or path.name != 'manifest.json' or path.parent.name != pointer['sha256']
                or proof.get('recipe') != category or proof.get('native_execution') is not True
                or proof.get('runtime_admitted') is not False or proof.get('network_used') is not False
                or not proof.get('limits')):
            raise ValueError('Current entry native proof scope differs')
        counts = ({'lookup_cases': 27, 'selection_cases': 16, 'type_cases': 6}
                  if identifier == 'viper-class-current' else {'validation_cases': 362, 'apply_cases': 48})
        if any(len(proof.get(key, [])) != expected for key, expected in counts.items()):
            raise ValueError('Current entry native proof coverage differs')
        if identifier == 'viper-class-current' and (proof.get('complete_viper_payload_verified') is not False
                or proof.get('loaded_class_table_verified') is not False):
            raise ValueError('Current Viper proof exceeded its declared boundary')
        merge(proof['inputs'])
    if proof.get('source_sha256') != sha or selector.read_bytes() != raw:
        raise ValueError('Current entry source or selector changed during validation')
    merge({str(path): pointer['sha256'], str(selector.resolve()): hashlib.sha256(raw).hexdigest(),
           str(Path(__file__).resolve()): index.digest(Path(__file__))})
    if any(index.digest(Path(name)) != expected for name, expected in material.items()):
        raise ValueError('Current entry retained input changed')
    return material, pointer


def runtime_inputs(index, root, report, identifier):
    definition = report['definition']['check']
    if identifier != definition['id'] or identifier not in CHECKS:
        raise ValueError('Current entry source check identity differs')
    pointer = report['entry_current_guard']['pointer']
    if identifier == CANDIDATE:
        api = index.extension('build-game-candidate-current')
        proof = api.verify_report(pointer['path'], pointer['sha256'], root=root, installed=index.INSTALL)
        if proof['source_sha256'] != report['definition']['source_sha256']:
            raise ValueError('Current candidate check source differs')
        material = candidate_material(proof, pointer, index.INSTALL)
    else:
        material, pointer = retained(index, root, index.KNOWLEDGE, definition,
                                     report['definition']['source_sha256'])
    if pointer != report['entry_current_guard']['pointer']:
        raise ValueError('Current entry proof selection changed')
    if any(report['definition']['artifacts'].get(name) != sha for name, sha in material.items()):
        raise ValueError('Current entry check lost retained inputs')
    if identifier == CANDIDATE:
        python = Path(sys.executable).resolve()
        runtime = {python, Path(index.INSTALL).resolve(),
                   python.with_name('python3.dll'),
                   python.with_name(f'python{sys.version_info.major}{sys.version_info.minor}.dll')}
        return {name: expected for name, expected in material.items() if Path(name).resolve() in runtime}
    return {}


def run(index, workflow, args, sha, definition):
    if sha in definition.get('bounded_entry_sources', []):
        return index.extension('entry-package-check-guard').run(index, workflow, args, sha, definition)
    if definition['id'] not in CHECKS or workflow.source_scope(definition) != 'client':
        raise ValueError('Current entry requires its registered client check')
    material, pointer = retained(index, args.root, args.knowledge, definition, sha)
    outcomes = workflow.run_checks(index, args, sha, None, check_ids=[definition['id']])
    if definition['id'] == CANDIDATE:
        api = index.extension('build-game-candidate-current')
        proof = api.verify_report(pointer['path'], pointer['sha256'], root=args.root, installed=index.INSTALL)
        fresh, second = candidate_material(proof, pointer, index.INSTALL), pointer
    else:
        fresh, second = retained(index, args.root, args.knowledge, definition, sha)
    if fresh != material or second != pointer:
        raise ValueError('Current entry materials changed during source check')
    results = []
    for outcome in outcomes:
        if 'report' not in outcome:
            results.append(outcome)
            continue
        if index.digest(Path(outcome['report'])) != outcome['sha256']:
            raise ValueError('Current entry parent source check changed')
        guarded = copy.deepcopy(workflow.checked_manifest(index, Path(outcome['report'])))
        artifacts = guarded['definition']['artifacts']
        if any(name in artifacts and artifacts[name] != expected for name, expected in material.items()):
            raise ValueError('Current entry source artifacts conflict')
        artifacts.update(material)
        guarded['entry_current_guard'] = dict(recipe=RECIPE, pointer=pointer)
        path = workflow.snapshot(args.root, 'check-results', guarded)
        results.append(dict(outcome, report=str(path), sha256=index.digest(path),
            cache_key=hashlib.sha256(workflow.canonical(guarded['definition'])).hexdigest()))
    return results
