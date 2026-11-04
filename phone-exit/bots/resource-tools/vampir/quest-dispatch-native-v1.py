"""Journaled bounded Tutorial 9905 and QuestSync 1854 dispatch execution."""
import copy
from pathlib import Path

HERE = Path(__file__).resolve().parent
RECIPE = 'quest-dispatch-native-v1'
CATEGORY = 'quest-dispatch-native-checks-v1'
STATIC = 'quest-sync-dispatch-proofs-v1'
SPECS = {
    'tutorial-dispatch': ('quest-tutorial-dispatch-cases-v1', 9905, 384),
    'quest-sync-dispatch': ('quest-sync-dispatch-cases-v1', 1854, 140),
}
FIXTURE_CALLS = {'tutorial-dispatch': 432, 'quest-sync-dispatch': 5520}
LIMITS = {
    'tutorial-dispatch': 'Immediate apply, state provider and allocation use fixtures. Fresh deferred copies and a bounded prepared queue are verified. Real application, queue drain and growth are excluded.',
    'quest-sync-dispatch': 'Registered trampoline, wrapper, provider leaf and receiver execute. Reset, model application, progress construction and notifications are observed at fixture boundaries. Real model and server effects are excluded.',
}


def configuration(index, args):
    path = Path(args.knowledge) / 'quest-dispatch-native.json'
    if not path.is_file():
        return None
    rule = index.read_json(path)
    if rule != dict(schema=1, recipe=RECIPE, families=list(SPECS)) or type(rule['schema']) is not int:
        raise ValueError('Unknown Quest dispatch native rule')
    return rule


def tools(index, family):
    names = [RECIPE, 'quest-dispatch-harness-v1', SPECS[family][0], 'quest-wire-harness-v1',
             'update-bindings', 'build-native-entry-code', 'login-input-transfer-rules',
             'quest-action-transfer-rules-v1', 'portable-native-family', 'update-native-harness',
             'extract-native-enums', 'version-system-transfer-rules', 'native-publication-v2']
    return {str(HERE / (name + '.py')): index.digest(HERE / (name + '.py')) for name in names}


def blocked(reason):
    return dict(state='requires_review', recipe=RECIPE, reason=reason,
                runtime_activated=False, profile_activated=False)


def owner_for(args):
    state = getattr(args, '_scope_v2_state', None)
    return state.get('owner') if isinstance(state, dict) else None


def state_for(args, attr, result):
    state = getattr(args, attr, None)
    if (not isinstance(state, dict) or state['result'] != result
            or result.get('state') != 'prepared_static' or state['source_store'] is not args.source_store
            or state['root'] != Path(args.root).resolve() or state['knowledge'] != Path(args.knowledge).resolve()
            or state['owner'] is not owner_for(args) or getattr(state['owner'], 'closed', False)):
        raise ValueError('Quest dispatch upstream result is not from the active invocation')
    return state


def validate_report(index, report, inputs):
    family = inputs['family']
    module, packet_id, calls = SPECS[family]
    workflow = index.extension('research-workflow')
    expected = dict(schema=1, recipe=RECIPE, method='bounded_native', family=family,
                    source_sha256=inputs['context']['source_sha256'], packet_id=packet_id,
                    network_used=False, profile_activated=False, runtime_activated=False,
                    inputs=inputs, limits=LIMITS[family], cases=index.extension(module).expected_cases())
    if set(report) != set(expected) | {'metrics'} or workflow.canonical(
            {key: report[key] for key in expected}) != workflow.canonical(expected):
        raise ValueError('Quest dispatch report exact source or case matrix differs')
    metrics = report['metrics']
    if (set(metrics) != {'call_counts', 'abi_checks', 'read_checks', 'write_checks', 'fixture_calls', 'entry_counts'}
            or any(type(metrics[key]) is not int or metrics[key] != calls for key in ('call_counts', 'abi_checks'))
            or any(type(metrics[key]) is not int or metrics[key] <= 0 for key in ('read_checks', 'write_checks'))
            or type(metrics['fixture_calls']) is not int or metrics['fixture_calls'] != FIXTURE_CALLS[family]):
        raise ValueError('Quest dispatch execution/ABI metrics differ')
    context = inputs['context']
    entries = metrics['entry_counts']
    fixtures = set(context['fixtures'].values())
    if (not isinstance(entries, dict) or not set(context['functions'].values()) <= set(entries)
            or not set(entries) <= set(context['functions'].values()) | set(context['leaves']) | fixtures
            or any(type(n) is not int or n <= 0 for n in entries.values())
            or sum(entries.get(at, 0) for at in fixtures) != metrics['fixture_calls']):
        raise ValueError('Quest dispatch entry/fixture counts differ')


def export_inputs(index, args, sha, addresses, collected):
    ready = {row['address']: row for row in collected if row.get('address') in addresses}
    if set(ready) != addresses or any(row['state'] != 'ready' or not row['artifacts'] for row in ready.values()):
        raise ValueError('Quest dispatch target exports incomplete')
    folder = (Path(args.root) / 'ghidra/request-exports' / sha).resolve()
    files = {}
    for row in ready.values():
        for artifact in row['artifacts']:
            path = Path(artifact['path']).resolve()
            if path.parent.parent != folder or path.name != 'details.json' or index.digest(path) != artifact['sha256']:
                raise ValueError('Quest dispatch export source or SHA differs')
            files[str(path)] = artifact['sha256']
    return dict(sorted(files.items()))


def run(index, args, sha, journal, reader_result, action_result, database):
    rule = configuration(index, args)
    if rule is None:
        return dict(state='disabled', recipe=RECIPE)
    original = args.source_store.index
    workflow = index.extension('research-workflow')
    helper = index.extension('quest-wire-harness-v1')
    transfer = index.extension('quest-sync-dispatch-transfer-v1')
    parent = index.extension('portable-native-family')
    root = Path(args.root).resolve()
    selector = Path(args.knowledge).resolve() / 'quest-dispatch-native.json'
    result = dict(state='passed_bounded_native', recipe=RECIPE, checks={}, cases=0,
                  runtime_activated=False, profile_activated=False, final_validation_completed=False)
    saved = {}
    owner = owner_for(args)
    selected_runtime = helper.runtime_inputs()
    for family in SPECS:
        try:
            if family == 'tutorial-dispatch':
                state = state_for(args, '_quest_action_transfer_v1_state', action_result)
                proof = index.extension('quest-action-transfer-v1').validate_result(original, args, action_result, state['inputs'])
                pointer = action_result['proof']
                context = proof['package']['target_contexts'][family]
                tables = {row['target']: row['bytes'] for row in proof['package']['relation']['tables']
                          if row['kind'].startswith('tutorial-')}
                files = dict(state['inputs']['files'])
                aliases = dict(state['inputs']['aliases'])
                export_addresses = set(context['functions'].values()) | {context['fixtures']['tutorial_apply']}
            else:
                state = state_for(args, '_quest_reader_transfer_v1_state', reader_result)
                pointer = reader_result['proof']
                files = {**state['inputs']['files'], **transfer.dependencies(original, args, pointer)}
                aliases = dict(state['inputs']['aliases'])
                helper.verify_files(files, aliases)
                static_inputs = dict(source=sha, reader=pointer, files=dict(files), aliases=aliases)

                def resolve():
                    context = transfer.transfer(index, args, pointer)
                    path = workflow.snapshot(root, STATIC, context)
                    return dict(path=str(path), sha256=original.digest(path))

                static = journal.stage('quest-sync-dispatch-transfer-v1', static_inputs, resolve)
                context = helper.pointer_document(static, root / 'knowledge' / STATIC)
                transfer.validate_package(context, sha, pointer)
                args.source_store.source(context['baseline_source_sha256'])
                files[static['path']] = static['sha256']
                tables = {row['target']: row['bytes'] for row in context['tables']}
                export_addresses = set(context['functions'].values())
            if context['source_sha256'] != sha or context.get('runtime_activated', False) is not False:
                raise ValueError('Quest dispatch context source/admission differs')
            files.update(parent.lineage_inputs(args, Path(pointer['path'])))
            request = dict(contracts={family: dict(bindings={str(n): at for n, at in enumerate(sorted(export_addresses))})})
            collector = index.extension('update-run-v2')
            collected = collector.collect_batches(index, workflow, journal, args, database, request, sha)
            if owner is not owner_for(args):
                raise ValueError('Quest dispatch collector changed the SourceStore owner')
            exports = export_inputs(original, args, sha, export_addresses, collected)
            selected_tools = tools(original, family)
            files.update(exports)
            files.update(selected_tools)
            files.update(selected_runtime['files'])
            files[str(selector)] = original.digest(selector)
            helper.verify_files(files, aliases)
            inputs = dict(recipe=RECIPE, family=family, source_sha256=sha, context=context, tables=tables,
                          exports=exports, files=files, aliases=aliases, tools=selected_tools, runtime=selected_runtime)

            def execute():
                harness = index.extension('quest-dispatch-harness-v1').make_harness(index, args.source_store,
                    context, [original.read_json(path) for path in exports], tables)
                module, packet_id, _ = SPECS[family]
                report = index.extension(module).verify(harness, context)
                report.update(schema=1, recipe=RECIPE, method='bounded_native', family=family, packet_id=packet_id,
                              source_sha256=sha, inputs=inputs, limits=LIMITS[family], network_used=False,
                              runtime_activated=False, profile_activated=False)
                validate_report(index, report, inputs)
                path = workflow.snapshot(root, CATEGORY, report)
                return dict(state='passed', report=str(path), sha256=original.digest(path), cases=len(report['cases']))

            outcome = journal.stage('quest-dispatch-native-' + family, inputs, execute)
            report = read_check(original, root, outcome, inputs)
            helper.verify_files(files, aliases)
            saved[family] = copy.deepcopy(inputs)
            result['checks'][family] = outcome
            result['cases'] += len(report['cases'])
        except (ValueError, OSError, KeyError, StopIteration) as error:
            result['state'] = 'requires_review'
            result['checks'][family] = blocked(str(error))
    args._quest_dispatch_native_v1_state = dict(result=copy.deepcopy(result), owner=owner, source_store=args.source_store,
        root=root, knowledge=Path(args.knowledge).resolve(), inputs=saved)
    return result


def read_check(index, root, outcome, inputs):
    helper = index.extension('quest-wire-harness-v1')
    pointer = dict(path=outcome['report'], sha256=outcome['sha256'])
    report = helper.pointer_document(pointer, root / 'knowledge' / CATEGORY)
    validate_report(index, report, inputs)
    if (set(outcome) != {'state', 'report', 'sha256', 'cases'} or outcome['state'] != 'passed'
            or type(outcome['cases']) is not int or outcome['cases'] != len(report['cases'])):
        raise ValueError('Quest dispatch journal result differs')
    return report


def finalize(index, args, result):
    state = args._quest_dispatch_native_v1_state
    owner = owner_for(args)
    if (state['result'] != result or state['source_store'] is not args.source_store
            or state['owner'] is not owner or (owner is not None and owner.finished is not True)
            or state['root'] != Path(args.root).resolve() or state['knowledge'] != Path(args.knowledge).resolve()):
        raise ValueError('Quest dispatch final invocation/source owner differs')
    helper = index.extension('quest-wire-harness-v1')
    for family, inputs in state['inputs'].items():
        helper.verify_files(inputs['files'], inputs['aliases'])
        if helper.runtime_inputs() != inputs['runtime'] or tools(index, family) != inputs['tools']:
            raise ValueError('Quest dispatch tool or runtime changed')
        read_check(index, state['root'], result['checks'][family], inputs)
    return dict(result, final_validation_completed=bool(state['inputs']))
