"""Source-bound QuestUpdate wire and Tutorial dispatch contexts for update."""
import copy
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
RECIPE = 'quest-action-transfer-v1'
CATEGORY = 'quest-action-transfer-proofs-v1'
STAGE = 'quest-action-transfer-v1'
BASELINES = ('quest-update-wire', 'tutorial-dispatch', 'archive-wire')
LIMITS = [
    'Whole root instructions and declared leaves, tables, registration windows and fixture entries are checked statically.',
    'Tutorial storage providers, handler application and registration effects require separate native scenarios.',
    'Prepared static contexts do not activate a game profile or grant online action permission.'
]


def configuration(index, args):
    path = Path(args.knowledge) / 'quest-action-transfer.json'
    if not path.is_file():
        return None
    with path.open('rb') as stream:
        raw = stream.read(16385)
    value = json.loads(raw)
    if (len(raw) > 16384 or not isinstance(value, dict)
            or set(value) != {'schema', 'recipe', 'baselines'}
            or type(value['schema']) is not int or value['schema'] != 1 or value['recipe'] != RECIPE
            or set(value['baselines']) != set(BASELINES)):
        raise ValueError('Unknown quest action transfer rule')
    seed = index.extension('quest-input-seed-v2')
    folder = Path(index.HERE) / 'knowledge/native-contexts'
    for pointer in value['baselines'].values():
        if not seed.exact_pointer(pointer) or not Path(pointer['path']).resolve().is_relative_to(folder.resolve()):
            raise ValueError('Quest action baseline must be exact repository knowledge')
    return value


def unavailable(reason):
    return dict(state='requires_review', recipe=RECIPE, method='static', reason=reason,
                runtime_activated=False, profile_activated=False)


def runtime(index):
    return index.extension('quest-reader-transfer-v1').runtime(index)


def tools(index):
    return {**index.extension('quest-action-transfer-rules-v1').tools(),
            str(Path(__file__).resolve()): index.digest(Path(__file__))}


def validate_result(index, args, result, inputs):
    harness = index.extension('quest-packet-harness-v1')
    pointer = result.get('proof') if isinstance(result, dict) else None
    proof = harness.pointer_document(pointer, Path(args.root) / 'knowledge' / CATEGORY)
    expected = dict(schema=1, recipe=RECIPE, method='static', inputs=inputs,
                    native_consumer_verified=False, runtime_activated=False, profile_activated=False, limits=LIMITS)
    canonical = index.extension('research-workflow').canonical
    if (set(proof) != set(expected) | {'package'}
            or canonical({key: proof.get(key) for key in expected}) != canonical(expected)):
        raise ValueError('Quest action cached proof scope differs')
    index.extension('quest-action-transfer-rules-v1').validate_package(proof['package'], inputs)
    wanted = dict(state='prepared_static', recipe=RECIPE, method='static', report=pointer['path'],
        sha256=pointer['sha256'], proof=pointer, counts=proof['package']['counts'],
        native_consumer_verified=False, runtime_activated=False, profile_activated=False,
        final_validation_completed=False, final_validation_pending=True)
    if index.extension('research-workflow').canonical(result) != index.extension('research-workflow').canonical(wanted):
        raise ValueError('Quest action cached result differs')
    return proof


def run(index, args, sha, journal, seed_result, reader_result, native_contexts, native_checks):
    rule = configuration(index, args)
    if rule is None:
        return dict(state='disabled', recipe=RECIPE)
    store = getattr(args, 'source_store', None)
    seed_state = getattr(args, '_quest_input_seed_v2_state', None)
    reader_state = getattr(args, '_quest_reader_transfer_v1_state', None)
    for state, result in ((seed_state, seed_result), (reader_state, reader_result)):
        if (not isinstance(state, dict) or state.get('source_store') is not store
                or state.get('result') != result or result.get('state') != 'prepared_static'
                or state.get('root') != Path(args.root).resolve()
                or state.get('knowledge') != Path(args.knowledge).resolve()):
            return unavailable('quest_action_input_invocation_missing_or_changed')
    scoped = getattr(args, '_scope_v2_state', None)
    owner = scoped.get('owner') if isinstance(scoped, dict) else None
    if (owner is not seed_state.get('owner') or owner is not reader_state.get('owner')
            or (owner is not None and getattr(owner, 'closed', True))):
        return unavailable('quest_action_owner_differs_or_closed')
    declarations = [row for row in native_contexts.get('checks', []) if row.get('id') == 'native-auto-archive-wire']
    outcomes = [row for row in native_checks if row.get('id') == 'native-auto-archive-wire']
    if len(declarations) != 1 or len(outcomes) != 1 or outcomes[0].get('state') != 'passed':
        return unavailable('quest_action_output_proof_missing_or_ambiguous')
    workflow = index.extension('research-workflow')
    harness = index.extension('quest-packet-harness-v1')
    common = index.extension('portable-native-family')
    try:
        declaration, outcome = declarations[0], outcomes[0]
        output_pointer = declaration['context']
        output_check = dict(path=outcome['report'], sha256=outcome['sha256'])
        output = harness.pointer_document(output_pointer, Path(args.root) / 'knowledge/generated-native-contexts')
        output_report = harness.pointer_document(output_check, Path(args.root) / 'knowledge/native-adapter-checks')
        archive = index.extension('update-native-archive-wire')
        if (output['source_sha256'] != sha or output.get('family') != 'archive-wire'
                or declaration.get('adapter') != archive.ADAPTER or declaration.get('scope') != archive.SCOPE
                or declaration.get('proof') != output.get('transfer_proof') or declaration.get('dependencies') != archive.tools()
                or outcome.get('scope') != archive.SCOPE):
            raise ValueError('Quest action output source or declaration differs')
        archive.report_valid(output_report, output, output_pointer['sha256'])
        seed_proof = harness.pointer_document(seed_result['proof'], Path(args.root) / 'knowledge/quest-input-seed-proofs-v2')
        reader_proof = harness.pointer_document(reader_result['proof'], Path(args.root) / 'knowledge/quest-reader-transfer-proofs-v1')
        if (seed_proof['inputs']['target']['source_sha256'] != sha
                or reader_proof['inputs']['target_source_sha256'] != sha
                or reader_proof['inputs']['seed'] != seed_result['proof']):
            raise ValueError('Quest action INPUT dependency source differs')
        dependencies = dict(input_seed=seed_result['proof'], reader_transfer=reader_result['proof'],
                            output_context=output_pointer, output_check=output_check, baselines=rule['baselines'])
        files = {}
        for pointer in (seed_result['proof'], reader_result['proof'], output_pointer, output_check, *rule['baselines'].values()):
            files.update(common.lineage_inputs(args, Path(pointer['path'])))
        selected_tools = tools(index)
        selected_runtime = runtime(index)
        selector = Path(args.knowledge) / 'quest-action-transfer.json'
        files.update(selected_tools)
        files[str(selector.resolve())] = index.digest(selector)
        files.update(selected_runtime['files'])
        files.update(selected_runtime['portable'].get('files', {}))
        aliases = {str(Path(pointer['path']).absolute()): str(Path(pointer['path']).resolve())
                   for pointer in (seed_result['proof'], reader_result['proof'], output_pointer, output_check, *rule['baselines'].values())}
        original = store.index
        harness.verify_files(files, aliases)
        for path, expected in files.items():
            if store.digest(path) != expected:
                raise ValueError('Quest action retained file changed')
        oldsha = seed_proof['inputs']['baseline']['source_sha256']
        store.source(oldsha)
        store.source(sha)
        inputs = dict(recipe=RECIPE, dependencies=dependencies, baseline_source_sha256=oldsha,
                      target_source_sha256=sha, files=files, aliases=aliases, tools=selected_tools, runtime=selected_runtime)

        def transfer():
            package = index.extension('quest-action-transfer-rules-v1').transfer(index, args, dependencies)
            index.extension('quest-action-transfer-rules-v1').validate_package(package, inputs)
            proof = dict(schema=1, recipe=RECIPE, method='static', inputs=inputs, package=package,
                         native_consumer_verified=False, runtime_activated=False, profile_activated=False, limits=LIMITS)
            if len(workflow.canonical(proof)) > 32 * 1024 * 1024:
                raise ValueError('Quest action proof budget exceeded')
            path = workflow.snapshot(args.root, CATEGORY, proof)
            pointer = dict(path=str(path), sha256=index.digest(path))
            return dict(state='prepared_static', recipe=RECIPE, method='static', report=str(path),
                sha256=pointer['sha256'], proof=pointer, counts=package['counts'], native_consumer_verified=False,
                runtime_activated=False, profile_activated=False, final_validation_completed=False, final_validation_pending=True)

        result = journal.stage(STAGE, inputs, transfer)
        validate_result(original, args, result, inputs)
        harness.verify_files(files, aliases)
        if tools(original) != selected_tools or runtime(original) != selected_runtime or configuration(original, args) != rule:
            raise ValueError('Quest action tools or runtime changed')
        args._quest_action_transfer_v1_state = dict(source_store=store, root=Path(args.root).resolve(),
            knowledge=Path(args.knowledge).resolve(), owner=owner, inputs=copy.deepcopy(inputs),
            result=copy.deepcopy(result), rule=copy.deepcopy(rule))
        return result
    except (ValueError, OSError, KeyError, StopIteration) as error:
        return unavailable('quest_action_transfer_rejected: ' + str(error))


def finalize(index, args, result):
    if result.get('state') != 'prepared_static':
        return result
    state = getattr(args, '_quest_action_transfer_v1_state', None)
    scoped = getattr(args, '_scope_v2_state', None)
    owner = scoped.get('owner') if isinstance(scoped, dict) else None
    if (not isinstance(state, dict) or state.get('source_store') is not args.source_store
            or state.get('result') != result or state.get('root') != Path(args.root).resolve()
            or state.get('knowledge') != Path(args.knowledge).resolve() or owner is not state['owner']
            or (owner is not None and getattr(owner, 'finished', False) is not True)):
        raise ValueError('Quest action final invocation or owner differs')
    inputs = state['inputs']
    validate_result(index, args, result, inputs)
    index.extension('quest-packet-harness-v1').verify_files(inputs['files'], inputs['aliases'])
    if tools(index) != inputs['tools'] or runtime(index) != inputs['runtime'] or configuration(index, args) != state['rule']:
        raise ValueError('Quest action final code or runtime changed')
    return dict(result, final_validation_completed=True, final_validation_pending=False)
