"""Journaled existing-task QuestSync state and progress checks."""
import copy
from pathlib import Path

HERE = Path(__file__).resolve().parent
RECIPE = 'quest-matching-state-native-v1'
CATEGORY = 'quest-matching-state-checks-v1'
STATIC = 'quest-matching-state-proofs-v1'
FAMILIES = ('quest-matching-state',)
FIXTURE_CALLS = {'quest-matching-state': 324}
LIMITS = {
    'quest-matching-state': 'Existing matching task only. Native state/progress, 32-byte virtual copy and sender index getter execute. Start/update callbacks use exact return-PC fixtures. Factory, replacement and real callback effects remain open.',
}


def configuration(index, args):
    path = Path(args.knowledge) / 'quest-matching-state-native.json'
    if not path.is_file():
        return None
    rule = index.read_json(path)
    if (rule != dict(schema=1, recipe=RECIPE, families=list(FAMILIES))
            or type(rule['schema']) is not int):
        raise ValueError('Unknown Quest matching state native rule')
    return rule

def tools(index):
    names = (RECIPE, 'quest-tutorial-state-harness-v1', 'quest-matching-state-cases-v1',
             'quest-dispatch-native-v1', 'quest-wire-harness-v1', 'portable-native-family',
             'update-bindings', 'build-native-entry-code', 'login-input-transfer-rules',
             'quest-action-transfer-rules-v1', 'update-native-harness', 'native-publication-v2')
    selected = {str(HERE / (name + '.py')): index.digest(HERE / (name + '.py')) for name in names}
    return selected | index.extension('quest-matching-state-transfer-v1').tools()

def blocked(reason):
    return dict(state='requires_review', recipe=RECIPE, reason=reason,
                runtime_activated=False, profile_activated=False)

def validate_report(index, report, inputs):
    family = inputs['family']
    cases = index.extension('quest-matching-state-cases-v1')
    expected = dict(schema=1, recipe=RECIPE, family=family, method='bounded_native',
        source_sha256=inputs['context']['source_sha256'], cases=cases.expected_cases(family),
        inputs=inputs, limits=LIMITS[family], runtime_activated=False, profile_activated=False, network_used=False)
    canonical = index.extension('research-workflow').canonical
    if (set(report) != set(expected) | {'metrics'}
            or canonical({key: report[key] for key in expected}) != canonical(expected)):
        raise ValueError('Quest matching state exact report or case matrix differs')
    metrics = report['metrics']
    wanted_calls = cases.expected_calls(family)
    if (set(metrics) != {'call_counts', 'abi_checks', 'read_checks', 'write_checks', 'fixture_calls', 'entry_counts'}
            or any(type(metrics[key]) is not int or metrics[key] != wanted_calls for key in ('call_counts', 'abi_checks'))
            or any(type(metrics[key]) is not int or metrics[key] <= 0 for key in ('read_checks', 'write_checks'))
            or type(metrics['fixture_calls']) is not int or metrics['fixture_calls'] != FIXTURE_CALLS[family]):
        raise ValueError('Quest matching state ABI or memory metrics differ')
    entries = metrics['entry_counts']
    context = inputs['context']
    fixtures = set(context['fixtures'].values())
    if (not isinstance(entries, dict) or not set(context['functions'].values()) <= set(entries)
            or not set(entries) <= set(context['functions'].values()) | set(context['leaves']) | fixtures
            or any(type(n) is not int or n <= 0 for n in entries.values())
            or sum(entries.get(at, 0) for at in fixtures) != metrics['fixture_calls']):
        raise ValueError('Quest matching state native/fixture entry coverage differs')

def read_check(index, root, outcome, inputs):
    helper = index.extension('quest-wire-harness-v1')
    report = helper.pointer_document(dict(path=outcome['report'], sha256=outcome['sha256']),
                                    root / 'knowledge' / CATEGORY)
    validate_report(index, report, inputs)
    if (set(outcome) != {'state', 'report', 'sha256', 'cases'} or outcome['state'] != 'passed'
            or type(outcome['cases']) is not int or outcome['cases'] != len(report['cases'])):
        raise ValueError('Quest matching state journal outcome differs')
    return report

def run(index, args, sha, journal, reader_result, database):
    rule = configuration(index, args)
    if rule is None:
        return dict(state='disabled', recipe=RECIPE)
    workflow = index.extension('research-workflow')
    guard = index.extension('quest-dispatch-native-v1')
    helper = index.extension('quest-wire-harness-v1')
    transfer = index.extension('quest-matching-state-transfer-v1')
    original = args.source_store.index
    root = Path(args.root).resolve()
    selector = Path(args.knowledge).resolve() / 'quest-matching-state-native.json'
    result = dict(state='passed_bounded_native', recipe=RECIPE, checks={}, cases=0,
                  runtime_activated=False, profile_activated=False, final_validation_completed=False)
    owner = guard.owner_for(args)
    saved = {}
    selected_runtime = helper.runtime_inputs()
    try:
        state = guard.state_for(args, '_quest_reader_transfer_v1_state', reader_result)
        index.extension('quest-reader-transfer-v1').validate_result(original, args, reader_result, state['inputs'],
            index.extension('quest-reader-transfer-rules-v1'))
        pointer = reader_result['proof']
        dependencies = transfer.dependencies(original, args, pointer)
        files = dict(state['inputs']['files']) | dependencies
        aliases = dict(state['inputs']['aliases'])
        helper.verify_files(files, aliases)
        static_inputs = dict(source=sha, reader=pointer, files=dict(files), aliases=aliases)

        def resolve():
            package = transfer.transfer(index, args, pointer)
            transfer.validate_package(package, sha, pointer)
            path = workflow.snapshot(root, STATIC, package)
            return dict(path=str(path), sha256=original.digest(path))

        static = journal.stage('quest-matching-state-transfer-v1', static_inputs, resolve)
        package = helper.pointer_document(static, root / 'knowledge' / STATIC)
        transfer.validate_package(package, sha, pointer)
        args.source_store.source(package['baseline_source_sha256'])
        args.source_store.source(sha)
        files[static['path']] = static['sha256']
        contexts = package['contexts']
        if set(contexts) != set(FAMILIES):
            raise ValueError('Quest matching state context family scope differs')
        addresses = set(package['export_addresses'])
        request = dict(contracts={RECIPE: dict(bindings={str(n): at for n, at in enumerate(sorted(addresses))})})
        collected = index.extension('update-run-v2').collect_batches(index, workflow, journal, args, database, request, sha)
        if owner is not guard.owner_for(args):
            raise ValueError('Quest matching state source owner changed')
        exports = guard.export_inputs(original, args, sha, addresses, collected)
        selected_tools = tools(original)
        files.update(exports)
        files.update(selected_tools)
        files.update(selected_runtime['files'])
        files[str(selector)] = original.digest(selector)
        helper.verify_files(files, aliases)
    except (ValueError, OSError, KeyError, StopIteration) as error:
        for family in FAMILIES:
            result['checks'][family] = blocked(str(error))
        result['state'] = 'requires_review'
    else:
        for family in FAMILIES:
            try:
                context = contexts[family]
                tables = {row['target']: row['bytes'] for row in context['tables']}
                inputs = dict(recipe=RECIPE, family=family, context=context, tables=tables, exports=exports,
                              files=files, aliases=aliases, tools=selected_tools, runtime=selected_runtime)

                def execute():
                    machine = index.extension('quest-tutorial-state-harness-v1').make_harness(
                        index, args.source_store, context, [original.read_json(p) for p in exports], tables)
                    report = index.extension('quest-matching-state-cases-v1').verify(machine, context)
                    report.update(schema=1, recipe=RECIPE, family=family, method='bounded_native',
                                  source_sha256=sha, inputs=inputs, limits=LIMITS[family],
                                  runtime_activated=False, profile_activated=False, network_used=False)
                    validate_report(index, report, inputs)
                    path = workflow.snapshot(root, CATEGORY, report)
                    return dict(state='passed', report=str(path), sha256=original.digest(path), cases=len(report['cases']))

                outcome = journal.stage('quest-matching-state-native-' + family, inputs, execute)
                report = read_check(original, root, outcome, inputs)
                helper.verify_files(files, aliases)
                saved[family] = copy.deepcopy(inputs)
                result['checks'][family] = outcome
                result['cases'] += len(report['cases'])
            except (ValueError, OSError, KeyError, StopIteration) as error:
                result['state'] = 'requires_review'
                result['checks'][family] = blocked(str(error))
    args._quest_matching_state_native_v1_state = dict(result=copy.deepcopy(result), owner=owner,
        source_store=args.source_store, root=root, knowledge=Path(args.knowledge).resolve(), inputs=saved)
    return result

def finalize(index, args, result):
    state = args._quest_matching_state_native_v1_state
    owner = index.extension('quest-dispatch-native-v1').owner_for(args)
    if (state['result'] != result or state['source_store'] is not args.source_store or state['owner'] is not owner
            or (owner is not None and owner.finished is not True)
            or state['root'] != Path(args.root).resolve() or state['knowledge'] != Path(args.knowledge).resolve()):
        raise ValueError('Quest matching state final invocation/source owner differs')
    helper = index.extension('quest-wire-harness-v1')
    for family, inputs in state['inputs'].items():
        helper.verify_files(inputs['files'], inputs['aliases'])
        if tools(index) != inputs['tools'] or helper.runtime_inputs() != inputs['runtime']:
            raise ValueError('Quest matching state tools or runtime changed')
        read_check(index, state['root'], result['checks'][family], inputs)
    return dict(result, final_validation_completed=bool(state['inputs']))
