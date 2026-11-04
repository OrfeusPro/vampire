"""Whole bounded quest/tutorial packet checks through the normal update journal."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
RECIPE = 'quest-packet-native-v1'
CATEGORY = 'quest-packet-native-checks-v1'
FAMILIES = ('quest-sync', 'tutorial-update')
LIMITS = [
    'Fresh zeroed storage is bounded to eight quest groups and eight quests per group, or 64 tutorial records.',
    'Allocation, cleanup and memcpy use explicit caller-bound fixtures, with temporary storage poisoned after free.',
    'Reuse, real storage providers, handlers, active quest selection, outgoing actions and online admission remain open.'
]


def configuration(args):
    path = Path(args.knowledge) / 'quest-packet-native.json'
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
    harness = index.extension('quest-packet-harness-v1')
    return {**harness.tools(), **{str(HERE / name): index.digest(HERE / name)
            for name in ('quest-packet-cases-v1.py', 'quest-packet-native-v1.py')}}


def validate_report(index, report, context, inputs):
    cases = index.extension('quest-packet-cases-v1')
    wanted = [spec for spec, body in cases.scenarios(context['family'])]
    canonical = index.extension('research-workflow').canonical
    if (report.get('recipe') != RECIPE or report.get('method') != 'bounded_native'
            or report.get('family') != context['family'] or report.get('source_sha256') != context['source_sha256']
            or report.get('packet_id') != cases.FAMILIES[context['family']]
            or report.get('inputs') != inputs or report.get('limits') != LIMITS
            or canonical(report.get('cases')) != canonical(wanted)
            or any(report.get(key) is not True for key in ('target_exports_verified', 'native_execution'))
            or any(report.get(key) is not False for key in ('network_used', 'runtime_activated', 'profile_activated'))):
        raise ValueError('Quest packet native report scope or exact case matrix differs')
    if (type(report.get('call_counts')) is not int or type(report.get('abi_checks')) is not int
            or report['call_counts'] != 4 * len(wanted) or report['abi_checks'] != report['call_counts']):
        raise ValueError('Quest packet native call/ABI coverage differs')
    for key in ('read_checks', 'write_checks', 'fixture_calls'):
        if type(report.get(key)) is not int or report[key] <= 0:
            raise ValueError('Quest packet native memory/fixture coverage differs')
    expected_exports = [dict(path=str(Path(inputs['root']) / 'ghidra/request-exports' /
                        context['source_sha256'] / run / 'details.json'), sha256=sha)
                        for run, sha in context['exports'].items()]
    if report.get('exports') != expected_exports:
        raise ValueError('Quest packet native report export provenance differs')


def unavailable(reason):
    return dict(state='requires_review', recipe=RECIPE, reason=reason,
                runtime_activated=False, profile_activated=False)


def run(index, args, sha, journal, reader_result, database):
    rule = configuration(args)
    if rule is None:
        return dict(state='disabled', recipe=RECIPE)
    state = getattr(args, '_quest_reader_transfer_v1_state', None)
    if (not isinstance(state, dict) or state.get('result') != reader_result
            or state.get('source_store') is not getattr(args, 'source_store', None)
            or state.get('root') != Path(args.root).resolve()
            or state.get('knowledge') != Path(args.knowledge).resolve()):
        return unavailable('quest_reader_transfer_invocation_missing_or_changed')
    if reader_result.get('state') != 'prepared_static':
        return unavailable('quest_reader_transfer_not_prepared')
    harness = index.extension('quest-packet-harness-v1')
    workflow = index.extension('research-workflow')
    original = args.source_store.index
    try:
        pointer = reader_result['proof']
        proof = harness.pointer_document(pointer, Path(args.root) / 'knowledge/quest-reader-transfer-proofs-v1')
        inputs = proof['inputs']
        index.extension('quest-reader-transfer-rules-v1').validate_package(proof['package'], inputs)
        if inputs['target_source_sha256'] != sha:
            raise ValueError('Quest packet native target source differs')
        scoped = getattr(args, '_scope_v2_state', None)
        owner = scoped.get('owner') if isinstance(scoped, dict) else None
        if owner is not state.get('owner') or (owner is not None and getattr(owner, 'closed', True)):
            raise ValueError('Quest packet native owner differs or is closed')
        contexts = proof['package']['target_contexts']
        addresses = sorted({at for context in contexts.values() for at in context['functions'].values()}, key=lambda at: int(at, 16))
        request = dict(source_sha256=sha, contracts={'quest-packet-native': dict(
                       bindings={str(number): at for number, at in enumerate(addresses)})})
        collector = index.extension('update-run-v2' if (Path(args.knowledge) / 'update-engine.json').is_file() else 'update-run')
        collected = collector.collect_batches(index, workflow, journal, args, database, request, sha)
        ready = {item['address']: item for item in collected if item.get('address') in addresses}
        if set(ready) != set(addresses) or any(item.get('state') != 'ready' for item in ready.values()):
            return unavailable('quest_packet_target_exports_incomplete')
        exports = {}
        for item in ready.values():
            for artifact in item.get('artifacts', []):
                path = Path(artifact['path']).resolve()
                if path.name != 'details.json' or not path.is_relative_to(Path(args.root) / 'ghidra/request-exports' / sha):
                    raise ValueError('Quest packet target export outside selected source')
                if index.digest(path) != artifact['sha256']:
                    raise ValueError('Quest packet target export changed')
                prior = exports.setdefault(path.parent.name, artifact['sha256'])
                if prior != artifact['sha256']:
                    raise ValueError('Quest packet target export declarations conflict')
        exports = dict(sorted(exports.items()))
        selected_tools = tools(index)
        selected_runtime = harness.runtime_inputs()
        selector = Path(args.knowledge) / 'quest-packet-native.json'
        files = {**inputs['files'], **selected_tools, pointer['path']: pointer['sha256'],
                 str(selector.resolve()): index.digest(selector), **selected_runtime['files']}
        for run_name, expected in exports.items():
            files[str(Path(args.root) / 'ghidra/request-exports' / sha / run_name / 'details.json')] = expected
        harness.verify_files(files, inputs['aliases'])
        outcomes = {}
        for family in FAMILIES:
            context = dict(copy.deepcopy(contexts[family]), schema=1, family=family, exports=exports,
                           transfer_proof=pointer, verify_whole_exports=True)
            check_inputs = dict(recipe=RECIPE, root=str(Path(args.root).resolve()), context=context,
                                tools=selected_tools, runtime=selected_runtime, files=files,
                                aliases=inputs['aliases'])

            def execute(context=context, check_inputs=check_inputs):
                report = index.extension('quest-packet-cases-v1').verify(harness, context, args.root, args.source_store)
                report.update(recipe=RECIPE, method='bounded_native', inputs=check_inputs,
                              network_used=False, limits=LIMITS)
                validate_report(index, report, context, check_inputs)
                path = workflow.snapshot(args.root, CATEGORY, report)
                return dict(state='passed', report=str(path), sha256=index.digest(path),
                            cases=len(report['cases']), family=context['family'])

            outcome = journal.stage('quest-packet-native-' + family, check_inputs, execute)
            report = harness.pointer_document(dict(path=outcome['report'], sha256=outcome['sha256']), Path(args.root) / 'knowledge' / CATEGORY)
            validate_report(index, report, context, check_inputs)
            expected = dict(state='passed', report=outcome['report'], sha256=outcome['sha256'], cases=len(report['cases']), family=family)
            if workflow.canonical(outcome) != workflow.canonical(expected):
                raise ValueError('Quest packet native cached outcome differs')
            outcomes[family] = outcome
        harness.verify_files(files, inputs['aliases'])
        if tools(index) != selected_tools or harness.runtime_inputs() != selected_runtime or configuration(args) != rule:
            raise ValueError('Quest packet native inputs changed during execution')
        result = dict(state='passed_bounded_native', recipe=RECIPE, checks=outcomes,
                      cases=sum(item['cases'] for item in outcomes.values()),
                      runtime_activated=False, profile_activated=False,
                      final_validation_completed=False, final_validation_pending=True)
        args._quest_packet_native_v1_state = dict(source_store=args.source_store, result=copy.deepcopy(result),
            root=Path(args.root).resolve(), knowledge=Path(args.knowledge).resolve(), owner=owner,
            files=files, aliases=copy.deepcopy(inputs['aliases']), tools=selected_tools, runtime=selected_runtime, rule=rule)
        return result
    except (ValueError, OSError, KeyError, StopIteration) as error:
        return unavailable('quest_packet_native_rejected: ' + str(error))


def finalize(index, args, result):
    if result.get('state') != 'passed_bounded_native':
        return result
    state = getattr(args, '_quest_packet_native_v1_state', None)
    if (not isinstance(state, dict) or state['result'] != result or state['source_store'] is not args.source_store
            or state['root'] != Path(args.root).resolve() or state['knowledge'] != Path(args.knowledge).resolve()):
        raise ValueError('Quest packet native final invocation differs')
    scoped = getattr(args, '_scope_v2_state', None)
    owner = scoped.get('owner') if isinstance(scoped, dict) else None
    if owner is not state['owner'] or (owner is not None and getattr(owner, 'finished', False) is not True):
        raise ValueError('Quest packet native final owner differs or is unvalidated')
    harness = index.extension('quest-packet-harness-v1')
    harness.verify_files(state['files'], state['aliases'])
    for outcome in result['checks'].values():
        pointer = dict(path=outcome['report'], sha256=outcome['sha256'])
        report = harness.pointer_document(pointer, Path(args.root) / 'knowledge' / CATEGORY)
        validate_report(index, report, report['inputs']['context'], report['inputs'])
    if tools(index) != state['tools'] or harness.runtime_inputs() != state['runtime'] or configuration(args) != state['rule']:
        raise ValueError('Quest packet native final code or runtime changed')
    return dict(result, final_validation_completed=True, final_validation_pending=False)
