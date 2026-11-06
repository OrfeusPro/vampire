"""Исследование выбранных материалов без повторного аудита всей истории."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
RECIPE = 'research-scoped-v2'
SCOPE = 'selected_materials_only'
REQUIRED = ('question', 'source_sha256', 'addresses', 'conclusion', 'method',
            'limits', 'unknown', 'next_check', 'evidence')
SHA = re.compile('[0-9a-f]{64}')


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('utf-8')


def fingerprint(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def tools():
    names = ('research-scoped-v2.py', 'knowledge-scope-v2.py', 'knowledge-index.py',
             'knowledge-context.py', 'research-workflow.py', 'update-bindings.py',
             'build-native-entry-code.py', 'extract-native-enums.py')
    return {str(HERE / name): hashlib.sha256((HERE / name).read_bytes()).hexdigest()
            for name in names}


def pointer(index, path):
    path = Path(path).resolve()
    return dict(path=str(path), sha256=index.digest(path))


def checked(index, item, root=None, category=None, *, parse=True):
    if (not isinstance(item, dict) or set(item) != {'path', 'sha256'}
            or not isinstance(item['path'], str) or not SHA.fullmatch(str(item['sha256']))):
        raise ValueError('Нужен точный pointer с полным SHA')
    path = Path(item['path']).resolve()
    if root is not None and not path.is_relative_to(Path(root).resolve() / 'knowledge' / category):
        raise ValueError('Scoped manifest находится вне разрешённого namespace')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != item['sha256']:
        raise ValueError('Scoped evidence SHA изменился: ' + str(path))
    if category is not None and (path.name != 'manifest.json' or path.parent.name != item['sha256']):
        raise ValueError('Scoped manifest не content-addressed')
    return json.loads(raw) if parse else raw


def source_sha(index, release):
    if release == 'installed':
        return index.digest(index.INSTALL)
    if not isinstance(release, str) or not SHA.fullmatch(release):
        raise ValueError('Scoped исследование требует installed или полный SHA')
    return release


def question(index, knowledge, identifier):
    value = index.read_json(Path(knowledge) / 'questions.json')
    rows = value.get('questions')
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError('Неверный реестр вопросов')
    ids = [row.get('id') for row in rows]
    if any(not isinstance(item, str) or not item for item in ids) or len(ids) != len(set(ids)):
        raise ValueError('Неоднозначный реестр вопросов')
    selected = [row for row in rows if row['id'] == identifier]
    if len(selected) != 1:
        raise ValueError('Неизвестный вопрос')
    return copy.deepcopy(selected[0])


def question_contract(value):
    # These four fields are research outputs, not permissions or decision rules.
    return {key: child for key, child in value.items()
            if key not in ('known', 'unknown', 'next_action', 'evidence')}


def pin_input(scope, path, expected=None, *, kind='context'):
    selected = Path(path).resolve()
    source_root = scope.root / 'client-code-snapshots'
    if selected.is_relative_to(source_root):
        relative = selected.relative_to(source_root)
        if len(relative.parts) != 2 or relative.name != 'ProjectRED-Win64-Shipping.exe':
            raise ValueError('Неизвестный source input')
        sha = relative.parts[0]
        if expected is not None and sha != expected:
            raise ValueError('Source pointer имеет другой SHA')
        scope.source_store.source(sha)
        return dict(path=str(selected), sha256=sha)
    return scope.pin(selected, expected, kind=kind)


def tools_runtime(record):
    return {row['path'] for row in record['admission'].get('consumed_materials', [])
            if row['kind'] == 'runtime'}


def open_scope(index, args, sha, addresses):
    return load('knowledge-scope-v2').Scope.open(args.root, args.knowledge, sha, addresses,
        tools(), question_id=getattr(args, 'question', None),
        source_store=getattr(args, 'source_store', None))


def verify_installed(index, required, sha):
    if required and index.digest(index.INSTALL) != sha:
        raise ValueError('Установленный клиент изменился; нужно новое задание')


def pin_checks(index, scope, checks):
    """The cached runner already validates definition inputs; pin them for the barrier."""
    for outcome in checks:
        if outcome.get('state') != 'passed':
            raise ValueError('Обязательная проверка не прошла: ' + str(outcome.get('id')))
        report_pointer = dict(path=outcome['report'], sha256=outcome['sha256'])
        report = checked(index, report_pointer)
        scope.pin(report_pointer['path'], report_pointer['sha256'], kind='check')
        if report.get('state') != 'passed':
            raise ValueError('Сохранённая проверка не прошла')
        definition = report.get('definition')
        if not isinstance(definition, dict):
            raise ValueError('Проверка не содержит входы')
        runtime_inputs = {}
        if (outcome.get('id') == 'automatic-update-tooling'
                and outcome.get('source_scope') == 'tooling'
                and report.get('grouped_tooling') is True):
            runtime_inputs = definition.get('runtime_inputs', {})
            if (not isinstance(runtime_inputs, dict)
                    or any(definition.get('artifacts', {}).get(name) != expected
                           for name, expected in runtime_inputs.items())):
                raise ValueError('Runtime групповой проверки не соответствует artifacts')
        elif report.get('sdk_generation_guard', {}).get('recipe') == 'sdk-check-guard-v1':
            runtime_inputs = index.extension('sdk-check-guard').runtime_inputs(
                index, index.extension('research-workflow'), scope.root, report, outcome['id'])
        elif report.get('sdk_launcher_guard', {}).get('recipe') == 'sdk-launcher-runtime-v1':
            runtime_inputs = index.extension('sdk-launcher-check-guard').runtime_inputs(
                index, scope.root, report, outcome['id'])
        elif report.get('sdk_fetch_guard', {}).get('recipe') == 'sdk-fetch-check-guard-v1':
            runtime_inputs = index.extension('sdk-fetch-check-guard').runtime_inputs(
                index, scope.root, report, outcome['id'])
        elif report.get('sdk_first_profile_guard', {}).get('recipe') == 'sdk-first-profile-check-guard-v1':
            runtime_inputs = index.extension('sdk-first-profile-check-guard').runtime_inputs(
                index, scope.root, report, outcome['id'])
        elif report.get('candidate_bridge_guard', {}).get('recipe') == 'candidate-proof-bridges-v1':
            runtime_inputs = index.extension('candidate-bridge-check-guard').runtime_inputs(
                index, scope.root, report, outcome['id'])
        elif report.get('entry_current_guard', {}).get('recipe') == 'entry-current-check-guard-v1':
            runtime_inputs = index.extension('entry-current-check-guard').runtime_inputs(
                index, scope.root, report, outcome['id'])
        elif report.get('entry_package_guard', {}).get('recipe') == 'entry-package-check-guard-v1':
            runtime_inputs = index.extension('entry-package-check-guard').runtime_inputs(
                index, scope.root, report, outcome['id'])
        for field in ('inputs', 'artifacts'):
            for path, expected in definition.get(field, {}).items():
                kind = ('runtime' if path in runtime_inputs or Path(path).parent ==
                        Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'System32' else 'check_input')
                pin_input(scope, path, expected, kind=kind)
    return checks


def run_checks(index, args, scope, sha, identifier):
    workflow = index.extension('research-workflow')
    registry_path = Path(args.knowledge) / 'research-checks.json'
    before = index.digest(registry_path)
    checks = (index.extension('tooling-check-dispatch-v1').run_checks(
        index, args, sha, identifier, workflow=workflow)
        if (Path(args.knowledge) / 'tooling-groups-v1.json').is_file()
        else workflow.run_checks(index, args, sha, identifier))
    if index.digest(registry_path) != before:
        raise ValueError('Реестр проверок изменился во время исполнения')
    scope.pin(registry_path, before, kind='check_registry')
    return pin_checks(index, scope, checks)


def explicit_hints(index, args):
    result = []
    for name in getattr(args, 'export', ()) or ():
        path = Path(name).resolve()
        result.append(dict(report=pointer(index, path), receipt=pointer(index, index.receipt_for(path))))
    return result


def prepare(index, args, database):
    workflow = index.extension('research-workflow')
    with workflow.locked(args.root, 'research'):
        sha = source_sha(index, args.release)
        addresses = [index.address(at) for at in args.function]
        if not 1 <= len(addresses) <= 32 or len(addresses) != len(set(addresses)):
            raise ValueError('Нужно от 1 до 32 различных явных адресов')
        selected = question(index, args.knowledge, args.question)
        selected_sha = fingerprint(question_contract(selected))
        invocation_question = fingerprint(selected)
        scope = open_scope(index, args, sha, addresses)
        hints = scope.discover_candidates(legacy_read_only_index=database,
            explicit_export_pointers=explicit_hints(index, args))
        functions = scope.select(hints)
        for path in getattr(args, 'context', ()) or ():
            scope.pin(path, kind='context')
        checks = run_checks(index, args, scope, sha, args.question)
        if fingerprint(question(index, args.knowledge, args.question)) != invocation_question:
            raise ValueError('Выбранный вопрос изменился во время подготовки')
        verify_installed(index, args.release == 'installed', sha)
        admission = scope.finish_barrier()
        metrics = admission.pop('metrics')
        request = dict(schema=2, recipe=RECIPE, validation_scope=SCOPE,
            global_history_verified=False, source_sha256=sha,
            source=str(Path(args.root) / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'),
            ordered_addresses=addresses, question=args.question, question_snapshot=selected,
            question_sha256=selected_sha, question_applicability='historical_context_not_release_proof',
            require_installed_match=args.release == 'installed',
            reason=getattr(args, 'reason', None) or selected.get('next_action', ''),
            functions=functions, export_hints=hints, checks=checks, admission=admission, tools=tools(),
            limits=['Проверены только выбранные материалы; полная история не проверялась.',
                    'Discovery index и Markdown не являются доказательством роли или допуска.'])
        path = workflow.snapshot(args.root, 'research-scoped-v2-requests', request)
        return dict(request=str(path), sha256=index.digest(path), source_sha256=sha,
            validation_scope=SCOPE, global_history_verified=False,
            functions=[dict(address=row['address'], state=row['state']) for row in functions],
            checks=checks, metrics=metrics)


def load_request(index, args):
    path = Path(args.request).resolve()
    request = checked(index, pointer(index, path), args.root, 'research-scoped-v2-requests')
    if (request.get('schema') != 2 or request.get('recipe') != RECIPE
            or request.get('validation_scope') != SCOPE or request.get('global_history_verified') is not False
            or not SHA.fullmatch(str(request.get('source_sha256')))
            or request.get('tools') != tools()):
        raise ValueError('Scoped request имеет другую версию или инструменты')
    selected = question(index, args.knowledge, request['question'])
    if (fingerprint(question_contract(selected)) != request['question_sha256']
            or question_contract(selected) != question_contract(request['question_snapshot'])):
        raise ValueError('Выбранный вопрос изменился; нужно новое задание')
    verify_installed(index, request['require_installed_match'], request['source_sha256'])
    admission = request['admission']
    if admission.get('validation_scope') != SCOPE or admission.get('global_history_verified') is not False:
        raise ValueError('Неверная область admission')
    for name, expected in admission['inputs'].items():
        if index.digest(name) != expected:
            raise ValueError('Выбранный материал изменился: ' + name)
    return request


def collect(index, args, database):
    workflow = index.extension('research-workflow')
    with workflow.locked(args.root, 'research'):
        request = load_request(index, args)
        sha, addresses = request['source_sha256'], request['ordered_addresses']
        scope = open_scope(index, args, sha, addresses)
        attempt = Path(args.root) / 'knowledge/research-scoped-v2-attempts' / (index.digest(args.request) + '.json')
        previous_attempt = index.read_json(attempt) if attempt.exists() else {}
        saved_hints = [*request['export_hints'], *previous_attempt.get('export_hints', [])]
        hints = scope.discover_candidates(legacy_read_only_index=database, explicit_export_pointers=saved_hints)
        functions = scope.select(hints)
        missing = [row['address'] for row in functions if row['state'] != 'ready']
        if not missing:
            outcome = dict(state='reused', addresses=[], new_jvm=0)
        elif attempt.exists():
            outcome = dict(state='queued', reason='Этот request уже запускался; сохранённый отказ не повторяется.',
                previous=index.read_json(attempt), addresses=missing)
        else:
            collector_tools = {str(HERE / name): index.digest(HERE / name) for name in (
                'collect-requested-functions.py', 'inspect-release-function-candidates.py',
                'InspectVampirSdkProfile.java', 'ghidra-tools.lock.json')}
            for path, expected in collector_tools.items():
                scope.pin(path, expected, kind='collector_tool')
            workflow.atomic(attempt, canonical(dict(state='started', addresses=missing)))
            try:
                # The reviewed collector owns and waits for its JVM. No legacy
                # collect/build or mutable discovery index admission is used.
                outcome = workflow.collector(index, args, request, missing)
                fresh_hints = ([dict(report=pointer(index, outcome['export']),
                        receipt=pointer(index, index.receipt_for(Path(outcome['export']))))]
                        if outcome.get('export') else [])
                new_hints = scope.discover_candidates(legacy_read_only_index=database,
                    explicit_export_pointers=[*hints, *fresh_hints])
                functions = scope.select(new_hints)
                remaining = [dict(address=row['address'], reason=row['state'])
                    for row in functions if row['state'] != 'ready']
                if outcome.get('state') == 'collected' and remaining:
                    outcome = dict(outcome, state='partial', queue=outcome.get('queue', []) + remaining)
                workflow.atomic(attempt, canonical(dict(outcome, export_hints=new_hints)))
            except BaseException as error:
                workflow.atomic(attempt, canonical(dict(state='failed', addresses=missing,
                    error_type=type(error).__name__, reason=str(error))))
                raise
        verify_installed(index, request['require_installed_match'], sha)
        admission = scope.finish_barrier()
        receipt = workflow.snapshot(args.root, 'research-scoped-v2-collections', dict(schema=2,
            recipe=RECIPE, request=pointer(index, args.request), source_sha256=sha,
            outcome=outcome, functions=functions, admission=admission,
            validation_scope=SCOPE, global_history_verified=False))
        return dict(report=str(receipt), **outcome, functions=functions,
            validation_scope=SCOPE, global_history_verified=False, metrics=admission.get('metrics', {}))


def validate_result(index, args, request, result):
    if not isinstance(result, dict) or any(not result.get(key) for key in REQUIRED):
        raise ValueError('Неполный результат исследования')
    result = copy.deepcopy(result)
    if result['question'] != request['question'] or result['source_sha256'] != request['source_sha256']:
        raise ValueError('Результат не относится к этому request/source')
    if result['method'] not in ('static', 'bounded_native'):
        raise ValueError('Неизвестный метод результата')
    addresses = result['addresses']
    if not isinstance(addresses, list) or not addresses:
        raise ValueError('Результат требует явные адреса')
    result['addresses'] = sorted({index.address(at) for at in addresses})
    if not set(result['addresses']) <= set(request['ordered_addresses']):
        raise ValueError('Результат расширяет адреса request')
    if not isinstance(result['evidence'], list) or not result['evidence']:
        raise ValueError('Нет evidence')
    allowed = (Path(args.knowledge).resolve(), (Path(args.root) / 'ghidra').resolve())
    for item in result['evidence']:
        if not isinstance(item, dict) or set(item) != {'path', 'sha256'}:
            raise ValueError('Evidence требует точные path/SHA')
        path = Path(item['path']).resolve()
        if not any(path.is_relative_to(folder) for folder in allowed):
            raise ValueError('Evidence находится вне knowledge/public Ghidra')
        item['path'] = str(path)
        checked(index, item, parse=False)
    return result


def fact_document(raw, sha):
    value = json.loads(raw) if raw is not None else dict(schema=1, source_sha256=sha, facts=[])
    if (value.get('schema') != 1 or value.get('source_sha256') != sha
            or not isinstance(value.get('facts'), list)
            or any(not isinstance(row, dict) or not SHA.fullmatch(str(row.get('id')))
                for row in value['facts'])
            or len({row['id'] for row in value['facts']}) != len(value['facts'])):
        raise ValueError('Неверная структура facts документа')
    return value


def finish(index, args, database):
    workflow = index.extension('research-workflow')
    with workflow.locked(args.root, 'research'):
        request = load_request(index, args)
        result_pointer = pointer(index, args.result)
        invocation_question = fingerprint(question(index, args.knowledge, request['question']))
        result = validate_result(index, args, request, checked(index, result_pointer))
        scope = open_scope(index, args, request['source_sha256'], request['ordered_addresses'])
        pin_input(scope, args.request, index.digest(args.request), kind='request')
        pin_input(scope, args.result, result_pointer['sha256'], kind='result')
        for name, expected in request['admission']['inputs'].items():
            pin_input(scope, name, expected, kind='runtime' if name in tools_runtime(request) else 'request_input')
        for item in result['evidence']:
            scope.pin(item['path'], item['sha256'], kind='evidence')
        checks = run_checks(index, args, scope, request['source_sha256'], request['question'])
        client_checks = [row for row in checks if row.get('source_scope', 'client') == 'client']
        if result['method'] == 'bounded_native' and not client_checks:
            raise ValueError('Native вывод требует source-bound client check')
        fact = {key: result[key] for key in REQUIRED}
        fact.update(checks=client_checks, validation_scope=SCOPE, global_history_verified=False)
        fact['id'] = fingerprint(fact)
        index.extension('knowledge-context').validate_fact(index, fact,
            request['source_sha256'], {request['question']})
        target = Path(args.knowledge) / 'releases' / request['source_sha256'] / 'facts.json'
        previous = target.read_bytes() if target.exists() else None
        existing = fact_document(previous, request['source_sha256'])
        previous_facts = copy.deepcopy(existing['facts'])
        matching = [row for row in existing['facts'] if row['id'] == fact['id']]
        if matching and matching != [fact]:
            raise ValueError('Существующий fact с этим ID имеет другое содержимое')
        if not matching:
            existing['facts'].append(fact)
        verify_installed(index, request['require_installed_match'], request['source_sha256'])
        if pointer(index, args.result) != result_pointer:
            raise ValueError('Result изменился до публикации')
        admission = scope.finish_barrier()
        if fingerprint(question(index, args.knowledge, request['question'])) != invocation_question:
            raise ValueError('Выбранный вопрос изменился во время finish')
        if (target.read_bytes() if target.exists() else None) != previous:
            raise ValueError('Facts изменились до атомарной записи')
        revised = canonical(existing)
        workflow.atomic(target, revised)
        try:
            if target.read_bytes() != revised or existing['facts'][:len(previous_facts)] != previous_facts:
                raise ValueError('Не сохранены прежние fact objects')
            verify_installed(index, request['require_installed_match'], request['source_sha256'])
            scope.finish_barrier()
            if fingerprint(question(index, args.knowledge, request['question'])) != invocation_question:
                raise ValueError('Выбранный вопрос изменился после записи fact')
            if pointer(index, args.result) != result_pointer:
                raise ValueError('Result изменился после публикации')
            receipt = workflow.snapshot(args.root, 'research-scoped-v2-completions', dict(schema=2,
                recipe=RECIPE, request=pointer(index, args.request), result=result_pointer,
                fact=fact, fact_id=fact['id'], facts=str(target), checks=checks,
                facts_before_sha256=hashlib.sha256(previous).hexdigest() if previous is not None else None,
                facts_after_sha256=hashlib.sha256(revised).hexdigest(),
                admission=admission, validation_scope=SCOPE, global_history_verified=False))
        except BaseException:
            # Never overwrite a third party's concurrent edit during rollback.
            if target.exists() and target.read_bytes() == revised:
                if previous is None:
                    target.unlink()
                else:
                    workflow.atomic(target, previous)
            raise
        return dict(state='recorded', fact_id=fact['id'], facts=str(target), report=str(receipt),
            checks=checks, validation_scope=SCOPE, global_history_verified=False,
            old_facts_preserved=len(previous_facts), metrics=admission.get('metrics', {}))


def check(index, args, database=None):
    """Revalidate one completion; this is never a full-history audit."""
    path = Path(args.completion).resolve()
    completion = checked(index, pointer(index, path), args.root, 'research-scoped-v2-completions')
    if (completion.get('schema') != 2 or completion.get('recipe') != RECIPE
            or completion.get('validation_scope') != SCOPE
            or completion.get('global_history_verified') is not False):
        raise ValueError('Неподходящий scope completion')
    selected_args = copy.copy(args)
    selected_args.request = Path(completion['request']['path'])
    if pointer(index, selected_args.request) != completion['request']:
        raise ValueError('Request pointer изменился')
    request = load_request(index, selected_args)
    scope = open_scope(index, args, request['source_sha256'], request['ordered_addresses'])
    for name, expected in completion['admission']['inputs'].items():
        pin_input(scope, name, expected, kind='runtime' if name in tools_runtime(completion) else 'completion_input')
    fact = completion['fact']
    fact_body = {key: value for key, value in fact.items() if key != 'id'}
    if fingerprint(fact_body) != fact['id'] or fact['id'] != completion['fact_id']:
        raise ValueError('Fact ID изменился')
    target = Path(completion['facts']).resolve()
    expected_target = (Path(args.knowledge) / 'releases' / request['source_sha256'] / 'facts.json').resolve()
    if target != expected_target:
        raise ValueError('Facts pointer вне выбранного knowledge/source')
    before = target.read_bytes()
    value = fact_document(before, request['source_sha256'])
    if [row for row in value['facts'] if row['id'] == fact['id']] != [fact]:
        raise ValueError('Выбранный fact отсутствует или изменился')
    index.extension('knowledge-context').validate_fact(index, fact,
        request['source_sha256'], {request['question']})
    current_checks = run_checks(index, args, scope, request['source_sha256'], request['question'])
    if current_checks != completion['checks']:
        raise ValueError('Обязательные проверки или runtime изменились')
    result = validate_result(index, args, request, checked(index, completion['result']))
    if any(result[key] != fact[key] for key in REQUIRED):
        raise ValueError('Fact не соответствует записанному result')
    if fact['checks'] != [row for row in current_checks if row.get('source_scope', 'client') == 'client']:
        raise ValueError('Fact содержит другой набор client checks')
    admission = scope.finish_barrier()
    if target.read_bytes() != before:
        raise ValueError('Facts изменились во время scoped check')
    verify_installed(index, request['require_installed_match'], request['source_sha256'])
    return dict(state='passed', validation_scope=SCOPE, global_history_verified=False,
        fact_id=fact['id'], metrics=admission.get('metrics', {}),
        limits='Полная история и неиспользованные facts/evidence не проверялись.')


def main():
    index = load('knowledge-index').api()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=index.ROOT)
    parser.add_argument('--knowledge', type=Path, default=index.KNOWLEDGE)
    parser.add_argument('--database', type=Path)
    sub = parser.add_subparsers(dest='operation', required=True)
    selected = sub.add_parser('prepare')
    selected.add_argument('--question', required=True)
    selected.add_argument('--function', action='append', required=True)
    selected.add_argument('--release', default='installed')
    selected.add_argument('--reason')
    selected.add_argument('--export', action='append', type=Path)
    selected.add_argument('--context', action='append', type=Path)
    for name in ('collect', 'finish'):
        selected = sub.add_parser(name)
        selected.add_argument('--request', type=Path, required=True)
        if name == 'finish':
            selected.add_argument('--result', type=Path, required=True)
    selected = sub.add_parser('check')
    selected.add_argument('--completion', type=Path, required=True)
    args = parser.parse_args()
    result = globals()[args.operation](index, args,
        args.database or args.root / 'knowledge/search.sqlite3')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
