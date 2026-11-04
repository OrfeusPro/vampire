"""Bounded QuestUpdate1810 writer/mirror checks through the normal update journal."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
RECIPE = 'quest-wire-native-v1'
CATEGORY = 'quest-wire-native-checks-v1'
FAMILIES = ('quest-update-wire',)
LIMITS = [
    'Fresh preallocated OUTPUT storage and unbuffered INPUT are bounded to the 29-byte QuestUpdate1810 body.',
    'Whole IO executes native raw writes; six separate failure cases replace only raw-write through caller-bound fixtures.',
    'Growth, endian conversion helpers, handlers, real storage providers and online action admission remain open.'
]


def configuration(args):
    path = Path(args.knowledge) / 'quest-wire-native.json'
    if not path.is_file():
        return None
    with path.open('rb') as stream:
        raw = stream.read(8193)
    value = json.loads(raw)
    expected = dict(schema=1, recipe=RECIPE, families=list(FAMILIES))
    if len(raw) > 8192 or value != expected or type(value.get('schema')) is not int:
        raise ValueError('Unknown quest packet native rule')
    return value


def tools(index):
    harness = index.extension('quest-wire-harness-v1')
    return {**harness.tools(), **{str(HERE / name): index.digest(HERE / name)
            for name in ('quest-wire-cases-v1.py', 'quest-wire-native-v1.py')}}


def validate_report(index, report, context, inputs):
    canonical = index.extension('research-workflow').canonical
    expected = index.extension('quest-wire-cases-v1').expected_cases()
    if (report.get('recipe') != RECIPE or report.get('method') != 'bounded_native'
            or report.get('family') != 'quest-update-wire' or report.get('source_sha256') != context['source_sha256']
            or type(report.get('packet_id')) is not int or report.get('packet_id') != 1810
            or report.get('inputs') != inputs or report.get('limits') != LIMITS
            or canonical(report.get('cases')) != canonical(expected)
            or any(report.get(key) is not False for key in ('network_used', 'runtime_activated', 'profile_activated'))):
        raise ValueError('Quest wire report scope or exact matrix differs')
    for scope, calls in (('whole_io', 768), ('raw_failure', 24)):
        metrics = report.get(scope, {})
        if (metrics.get('source_sha256') != context['source_sha256'] or metrics.get('execution_scope') != scope
                or any(metrics.get(key) is not True for key in ('target_exports_verified', 'native_execution'))
                or any(metrics.get(key) is not False for key in ('runtime_activated', 'profile_activated'))
                or any(type(metrics.get(key)) is not int or metrics[key] != calls for key in ('call_counts', 'abi_checks'))
                or any(type(metrics.get(key)) is not int or metrics[key] <= 0 for key in ('read_checks', 'write_checks', 'fixture_calls'))):
            raise ValueError('Quest wire execution, ABI or memory scope differs')
    expected_exports = [dict(path=str(Path(inputs['root']) / 'ghidra/request-exports' /
                        context['source_sha256'] / run / 'details.json'), sha256=sha)
                        for run, sha in context['exports'].items()]
    if report.get('exports') != expected_exports:
        raise ValueError('Quest wire export provenance differs')


def unavailable(reason):
    return dict(state='requires_review', recipe=RECIPE, reason=reason,
                runtime_activated=False, profile_activated=False)


def run(index, args, sha, journal, action_result, database):
    rule = configuration(args)
    if rule is None:
        return dict(state='disabled', recipe=RECIPE)
    state = getattr(args, '_quest_action_transfer_v1_state', None)
    if (not isinstance(state, dict) or state.get('result') != action_result
            or state.get('source_store') is not getattr(args, 'source_store', None)
            or state.get('root') != Path(args.root).resolve()
            or state.get('knowledge') != Path(args.knowledge).resolve()):
        return unavailable('quest_action_transfer_invocation_missing_or_changed')
    if action_result.get('state') != 'prepared_static':
        return unavailable('quest_action_transfer_not_prepared')
    harness = index.extension('quest-wire-harness-v1')
    workflow = index.extension('research-workflow')
    original = args.source_store.index
    try:
        pointer = action_result['proof']
        proof = harness.pointer_document(pointer, Path(args.root) / 'knowledge/quest-action-transfer-proofs-v1')
        inputs = proof['inputs']
        index.extension('quest-action-transfer-rules-v1').validate_package(proof['package'], inputs)
        if inputs['target_source_sha256'] != sha:
            raise ValueError('Quest wire native target source differs')
        scoped = getattr(args, '_scope_v2_state', None)
        owner = scoped.get('owner') if isinstance(scoped, dict) else None
        if owner is not state.get('owner') or (owner is not None and getattr(owner, 'closed', True)):
            raise ValueError('Quest wire native owner differs or is closed')
        contexts = {'quest-update-wire': proof['package']['target_contexts']['quest-update-wire']}
        addresses = sorted({at for context in contexts.values() for at in context['functions'].values()}, key=lambda at: int(at, 16))
        request = dict(source_sha256=sha, contracts={'quest-wire-native': dict(
                       bindings={str(number): at for number, at in enumerate(addresses)})})
        collector = index.extension('update-run-v2' if (Path(args.knowledge) / 'update-engine.json').is_file() else 'update-run')
        collected = collector.collect_batches(index, workflow, journal, args, database, request, sha)
        ready = {item['address']: item for item in collected if item.get('address') in addresses}
        if set(ready) != set(addresses) or any(item.get('state') != 'ready' for item in ready.values()):
            return unavailable('quest_wire_target_exports_incomplete')
        exports = {}
        for item in ready.values():
            for artifact in item.get('artifacts', []):
                path = Path(artifact['path']).resolve()
                if path.name != 'details.json' or not path.is_relative_to(Path(args.root) / 'ghidra/request-exports' / sha):
                    raise ValueError('Quest wire target export outside selected source')
                if index.digest(path) != artifact['sha256']:
                    raise ValueError('Quest wire target export changed')
                prior = exports.setdefault(path.parent.name, artifact['sha256'])
                if prior != artifact['sha256']:
                    raise ValueError('Quest wire target export declarations conflict')
        exports = dict(sorted(exports.items()))
        selected_tools = tools(index)
        selected_runtime = harness.runtime_inputs()
        selector = Path(args.knowledge) / 'quest-wire-native.json'
        files = {**inputs['files'], **selected_tools, pointer['path']: pointer['sha256'],
                 str(selector.resolve()): index.digest(selector), **selected_runtime['files']}
        for run_name, expected in exports.items():
            files[str(Path(args.root) / 'ghidra/request-exports' / sha / run_name / 'details.json')] = expected
        harness.verify_files(files, inputs['aliases'])
        outcomes = {}
        for family in FAMILIES:
            context = dict(copy.deepcopy(contexts[family]), schema=1, family=family, exports=exports,
                           transfer_proof=pointer, verify_whole_exports=True, execution_scope='whole_io')
            check_inputs = dict(recipe=RECIPE, root=str(Path(args.root).resolve()), context=context,
                                tools=selected_tools, runtime=selected_runtime, files=files,
                                aliases=inputs['aliases'])

            def execute(context=context, check_inputs=check_inputs):
                report = index.extension('quest-wire-cases-v1').verify(harness, context, args.root, args.source_store)
                report.update(recipe=RECIPE, method='bounded_native', inputs=check_inputs,
                              network_used=False, limits=LIMITS, family=context['family'],
                              exports=[dict(path=str(Path(args.root) / 'ghidra/request-exports' / sha / run / 'details.json'), sha256=value)
                                       for run,value in exports.items()])
                validate_report(index, report, context, check_inputs)
                path = workflow.snapshot(args.root, CATEGORY, report)
                return dict(state='passed', report=str(path), sha256=index.digest(path),
                            cases=117, family=context['family'])

            outcome = journal.stage('quest-wire-native-' + family, check_inputs, execute)
            report = harness.pointer_document(dict(path=outcome['report'], sha256=outcome['sha256']), Path(args.root) / 'knowledge' / CATEGORY)
            validate_report(index, report, context, check_inputs)
            expected = dict(state='passed', report=outcome['report'], sha256=outcome['sha256'], cases=117, family=family)
            if workflow.canonical(outcome) != workflow.canonical(expected):
                raise ValueError('Quest wire native cached outcome differs')
            outcomes[family] = outcome
        harness.verify_files(files, inputs['aliases'])
        if tools(index) != selected_tools or harness.runtime_inputs() != selected_runtime or configuration(args) != rule:
            raise ValueError('Quest wire native inputs changed during execution')
        result = dict(state='passed_bounded_native', recipe=RECIPE, checks=outcomes,
                      cases=sum(item['cases'] for item in outcomes.values()),
                      runtime_activated=False, profile_activated=False,
                      final_validation_completed=False, final_validation_pending=True)
        args._quest_wire_native_v1_state = dict(source_store=args.source_store, result=copy.deepcopy(result),
            root=Path(args.root).resolve(), knowledge=Path(args.knowledge).resolve(), owner=owner,
            files=files, aliases=copy.deepcopy(inputs['aliases']), tools=selected_tools, runtime=selected_runtime, rule=rule)
        return result
    except (ValueError, OSError, KeyError, StopIteration) as error:
        return unavailable('quest_wire_native_rejected: ' + str(error))


def finalize(index, args, result):
    if result.get('state') != 'passed_bounded_native':
        return result
    state = getattr(args, '_quest_wire_native_v1_state', None)
    if (not isinstance(state, dict) or state['result'] != result or state['source_store'] is not args.source_store
            or state['root'] != Path(args.root).resolve() or state['knowledge'] != Path(args.knowledge).resolve()):
        raise ValueError('Quest wire native final invocation differs')
    scoped = getattr(args, '_scope_v2_state', None)
    owner = scoped.get('owner') if isinstance(scoped, dict) else None
    if owner is not state['owner'] or (owner is not None and getattr(owner, 'finished', False) is not True):
        raise ValueError('Quest wire native final owner differs or is unvalidated')
    harness = index.extension('quest-wire-harness-v1')
    harness.verify_files(state['files'], state['aliases'])
    for outcome in result['checks'].values():
        pointer = dict(path=outcome['report'], sha256=outcome['sha256'])
        report = harness.pointer_document(pointer, Path(args.root) / 'knowledge' / CATEGORY)
        validate_report(index, report, report['inputs']['context'], report['inputs'])
    if tools(index) != state['tools'] or harness.runtime_inputs() != state['runtime'] or configuration(args) != state['rule']:
        raise ValueError('Quest wire native final code or runtime changed')
    return dict(result, final_validation_completed=True, final_validation_pending=False)
