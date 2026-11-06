"""Retain current entry native proofs on cold and cached source checks."""
import copy
import hashlib
from pathlib import Path

IDS = {'character-list-current', 'clock-world-current', 'viper-class-current', 'lobby-metadata-current'}
RECIPE = 'entry-current-check-guard-v1'


def retained(index, root, knowledge, definition, sha):
    if definition['id'] not in IDS:
        raise ValueError('Unknown current entry source check')
    workspace = index.HERE.parents[3].resolve()
    selector = index.child(knowledge, definition['entry_current_contexts'][sha])
    effective = index.extension('research-workflow').source_definition(definition, sha)
    if selector.relative_to(workspace).as_posix() not in effective['dependencies']:
        raise ValueError('Current entry selector is not a dependency')
    raw = selector.read_bytes()
    selected = index.read_json(selector)
    if (selected.get('schema') != 1 or selected.get('source_sha256') != sha
            or set(selected.get('proofs', {})) != IDS):
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
        proof = api.verify_report(path, root=root, workspace=workspace)
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
        proof = api.verify_report(path, pointer['sha256'], native_definition, root)
        merge(native_definition['files'])
        merge(native_definition['exports'])
        source = Path(root).resolve() / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'
        merge({str(source): sha})
        merge({row['path']: row['sha256'] for row in proof['components'].values()})
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
    if identifier != definition['id'] or identifier not in IDS:
        raise ValueError('Current entry source check identity differs')
    material, pointer = retained(index, root, index.KNOWLEDGE, definition,
                                 report['definition']['source_sha256'])
    if pointer != report['entry_current_guard']['pointer']:
        raise ValueError('Current entry proof selection changed')
    if any(report['definition']['artifacts'].get(name) != sha for name, sha in material.items()):
        raise ValueError('Current entry check lost retained inputs')
    # All materials are explicit workspace or resource-library inputs. No external
    # runtime path exception is needed for these offline packages.
    return {}


def run(index, workflow, args, sha, definition):
    if definition['id'] not in IDS or workflow.source_scope(definition) != 'client':
        raise ValueError('Current entry requires its registered client check')
    material, pointer = retained(index, args.root, args.knowledge, definition, sha)
    outcomes = workflow.run_checks(index, args, sha, None, check_ids=[definition['id']])
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
