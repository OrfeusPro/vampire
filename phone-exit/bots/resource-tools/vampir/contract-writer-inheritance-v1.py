"""Статический перенос прежних writer fixtures, без нового native исполнения.

Caller обязан принять source-bound archive / preparation publications, точные
baseline report и exports и обеспечить финальные SHA barriers. Этот pure rule
проверяет только заданную fixture-модель и полные пары декодированных writers;
он не превращает произвольный mapping или report в доказательство источника.
"""
import copy
import re
import struct

RECIPE = 'contract-writer-inheritance-v1'
SHA = re.compile(r'[0-9a-f]{64}')
POISONS = (0, 0x55, 0xaa, 0xff)
COUNTS = {'game-version': 13, 'game-login': 25}
WIDTHS = {'string': 16, 'u32': 4, 'u8': 1, 'u64': 8, 'bool': 1}
SLOTS = {'u32': 0xc8, 'u8': 0xe0, 'u64': 0xb8, 'bool': 0xf0}


def reject(reason):
    raise ValueError('Перенос writer: ' + reason)


def address(value):
    if (not isinstance(value, str) or not re.fullmatch(r'0x[0-9a-f]+', value)
            or not 0 < int(value, 16) < 2**64 or hex(int(value, 16)) != value):
        reject('нужен канонический адрес')
    return int(value, 16)


def integer(value, minimum, maximum, reason):
    if type(value) is not int or not minimum <= value <= maximum:
        reject(reason)
    return value


def source(context):
    if not isinstance(context, dict):
        reject('отсутствует context источника')
    value = context.get('source_sha256')
    if not isinstance(value, str) or not SHA.fullmatch(value):
        reject('нужен полный SHA источника')
    return value


def packet(context, contract):
    if not isinstance(context, dict) or not isinstance(context.get('packets'), dict):
        reject('отсутствует packet context')
    if contract not in context['packets']:
        reject('отсутствует выбранный packet')
    item = context['packets'][contract]
    if not isinstance(item, dict):
        reject('неверный packet layout')
    fields = item.get('fields')
    if not isinstance(fields, list) or len(fields) != COUNTS[contract]:
        reject('неверное число полей')
    size = integer(item.get('object_size'), 16, 512, 'неверный размер объекта')
    occupied = set()
    for field in fields:
        if (not isinstance(field, list) or len(field) != 2 or not isinstance(field[0], str)
                or field[0] not in WIDTHS):
            reject('неверное описание поля')
        kind, offset = field
        integer(offset, 8, size-WIDTHS[kind], 'поле выходит за объект')
        span = set(range(offset, offset+WIDTHS[kind]))
        if occupied & span:
            reject('поля перекрываются')
        occupied.update(span)
    writer, table = address(item.get('writer')), address(item.get('table'))
    bindings = context.get('bindings')
    if not isinstance(bindings, dict):
        reject('отсутствуют helper bindings')
    string = address(bindings.get('string-writer'))
    if len({writer, table, string}) != 3:
        reject('writer, table и helper перекрываются')
    return dict(fields=copy.deepcopy(fields), object_size=size, writer=writer,
        table=table, string=string)


def cases(report, model, sha):
    if (not isinstance(report, dict) or type(report.get('schema')) is not int
            or report['schema'] != 1 or report.get('source_sha256') != sha
            or report.get('method') != 'bounded_native'
            or report.get('network_used') is not False or report.get('profile_activated') is not False
            or ('runtime_activated' in report and report['runtime_activated'] is not False)):
        reject('неверная область прежнего native report')
    binding = report.get('binding')
    if not isinstance(binding, dict) or set(binding) != {'constructor', 'packet_table', 'string_helper', 'table_slot', 'writer'}:
        reject('неверные прежние writer bindings')
    address(binding['constructor'])  # Target constructor/table admission is separate.
    if (address(binding['writer']) != model['writer'] or address(binding['packet_table']) != model['table']
            or address(binding['string_helper']) != model['string']
            or type(binding['table_slot']) is not int or binding['table_slot'] != 16):
        reject('прежние bindings не совпали с archive context')
    if report.get('fields') != model['fields']:
        reject('порядок полей report не совпал с моделью')
    evidence = report.get('evidence')
    if (not isinstance(evidence, list) or not 1 <= len(evidence) <= 256
            or any(not isinstance(row, dict) or set(row) != {'path', 'sha256'}
                or not isinstance(row['path'], str) or not 1 <= len(row['path']) <= 4096
                or not isinstance(row['sha256'], str) or not SHA.fullmatch(row['sha256']) for row in evidence)):
        reject('нет точных exports прежнего report')
    count = len(model['fields'])
    wanted = {(poison, fail_at) for poison in POISONS for fail_at in range(-1, count)}
    found = set(); rows = report.get('cases')
    if not isinstance(rows, list) or len(rows) != len(wanted):
        reject('неполная матрица прежних случаев')
    for row in rows:
        if not isinstance(row, dict) or set(row) != {'poison', 'fail_at', 'calls', 'result', 'guards'}:
            reject('неверная строка прежнего случая')
        poison = integer(row['poison'], 0, 255, 'неверный poison')
        fail_at = integer(row['fail_at'], -1, count-1, 'неверная позиция отказа')
        key = (poison, fail_at)
        if key not in wanted or key in found:
            reject('лишний или повторный прежний случай')
        found.add(key)
        expected_calls = count if fail_at == -1 else fail_at+1
        if (type(row['calls']) is not int or row['calls'] != expected_calls
                or type(row['result']) is not int or row['result'] != int(fail_at == -1)
                or row['guards'] is not True):
            reject('прежний результат, guards или число вызовов изменились')
    if found != wanted:
        reject('матрица прежних случаев не замкнута')
    return len(rows)


def instruction_rows(rows, root):
    if not isinstance(rows, list) or not 1 <= len(rows) <= 4096:
        reject('неверный бюджет instruction rows')
    at = root; decoded = []
    for row in rows:
        if not isinstance(row, dict):
            reject('неверная instruction row')
        integer(row.get('address'), 1, 2**64-1, 'неверный адрес инструкции')
        if row['address'] != at:
            reject('writer rows не покрывают сплошное тело')
        raw = row.get('bytes')
        if (not isinstance(raw, str) or not re.fullmatch(r'(?:[0-9a-f]{2}){1,15}', raw)):
            reject('неверные bytes инструкции')
        data = bytes.fromhex(raw)
        if (type(row.get('call')) is not bool or type(row.get('branch')) is not bool
                or not isinstance(row.get('mnemonic'), str) or not row['mnemonic']
                or not isinstance(row.get('operands'), str) or len(row['operands']) > 256
                or row.get('rip_references') != []):
            reject('неизвестная инструкция или RIP/data зависимость')
        if row['call'] != (row['mnemonic'] == 'call') or row['call'] and row['branch']:
            reject('call flags не совпали с декодированной инструкцией')
        target = row.get('direct_target')
        if target is not None:
            integer(target, 1, 2**64-1, 'неверная цель инструкции')
            if not row['call'] and not row['branch']:
                reject('неописанная прямая цель')
        if row['branch'] and target is None:
            reject('неописанный косвенный branch')
        if not row['branch'] and row['mnemonic'].startswith(('j', 'loop')):
            reject('branch flags не совпали с инструкцией')
        decoded.append((row, data)); at += len(data)
    if at > 2**64 or at-root > 65536:
        reject('тело writer превышает бюджет')
    return decoded


def call_model(rows, model):
    calls = [(row, raw) for row, raw in rows if row['call']]
    if len(calls) != len(model['fields']):
        reject('число вызовов writer не совпало с полями')
    for (kind, _), (row, raw) in zip(model['fields'], calls):
        if kind == 'string':
            if (len(raw) != 5 or raw[0] != 0xe8 or row['direct_target'] != model['string']
                    or row['address']+5+struct.unpack('<i', raw[1:])[0] != model['string']
                    or row['operands'] != hex(model['string'])):
                reject('string call выходит за fixture helper')
        else:
            wanted = b'\xff\x90'+struct.pack('<i', SLOTS[kind])
            if (raw != wanted or row['direct_target'] is not None
                    or row['operands'] != 'qword ptr [rax + '+hex(SLOTS[kind])+']'):
                reject('scalar call выходит за fixture slot')
    return calls


def verify(baseline_report, baseline_context, target_context, contract, before_rows, after_rows, mapping):
    """Return only static fixture inheritance; caller supplies admitted actual rows."""
    if not isinstance(contract, str) or contract not in COUNTS:
        reject('неизвестный контракт')
    old_sha, new_sha = source(baseline_context), source(target_context)
    old, new = packet(baseline_context, contract), packet(target_context, contract)
    if old['fields'] != new['fields'] or old['object_size'] != new['object_size']:
        reject('target layout отличается от прежней fixture модели')
    inherited = cases(baseline_report, old, old_sha)
    if not isinstance(mapping, dict) or not 1 <= len(mapping) <= 65536:
        reject('неверный relocation mapping')
    relocated = {address(a): address(b) for a, b in mapping.items()}
    for role in ('writer', 'table', 'string'):
        if relocated.get(old[role]) != new[role]:
            reject('отсутствует точная relocation роли '+role)
    before = instruction_rows(before_rows, old['writer'])
    after = instruction_rows(after_rows, new['writer'])
    if len(before) != len(after):
        reject('изменилось число инструкций')
    call_model(before, old); call_model(after, new)
    old_locations = {row['address'] for row, _ in before}
    new_locations = {row['address'] for row, _ in after}
    if (old['string'] in old_locations or new['string'] in new_locations
            or old['table'] in old_locations or new['table'] in new_locations):
        reject('fixture helper или table перекрывает тело writer')
    for (a, raw_a), (b, raw_b) in zip(before, after):
        if (a['address']-old['writer'] != b['address']-new['writer'] or len(raw_a) != len(raw_b)
                or relocated.get(a['address']) != b['address']
                or a['mnemonic'] != b['mnemonic'] or a['call'] != b['call'] or a['branch'] != b['branch']):
            reject('геометрия или тип инструкции не совпали')
        if a['branch']:
            if (a['direct_target'] not in old_locations or b['direct_target'] not in new_locations
                    or a['direct_target']-old['writer'] != b['direct_target']-new['writer']
                    or relocated.get(a['direct_target']) != b['direct_target']):
                reject('внешний branch или изменилась внутренняя цель')
        if a['call'] and a['direct_target'] is not None:
            if relocated.get(a['direct_target']) != b['direct_target']:
                reject('изменилась relocation helper')
        elif raw_a != raw_b:
            reject('изменились bytes вне объявленных direct call relocations')
        if not a['branch'] and not a['call'] and a['operands'] != b['operands']:
            reject('изменились operands вне relocations')
    return dict(schema=1, recipe=RECIPE, method='static_inheritance', contract=contract,
        baseline_source_sha256=old_sha, source_sha256=new_sha,
        binding=dict(writer=hex(new['writer']), packet_table=hex(new['table']),
            string_helper=hex(new['string']), table_slot=16),
        fields=copy.deepcopy(new['fields']), object_size=new['object_size'],
        inherited_cases=inherited, inherited_failure_cases=4*len(new['fields']),
        inherited_success_controls=4, target_native_cases=0,
        instructions=len(after), writer_bytes=sum(len(raw) for _, raw in after),
        network_used=False, profile_activated=False, runtime_activated=False,
        limits=['Прежние native случаи перенесены статически; target native случаи не исполнялись.',
            'Архивные scalar методы и string helper остаются независимыми fixture-вызовами с произвольным отказом.',
            'Boolean inputs проверены как raw bytes; реальная wire-нормализация этим правилом не доказывается.',
            'Caller отдельно подтверждает source publications, constructor/table link и финальные SHA barriers.',
            'Не подтверждает реальные archive failures, packet name/ID, wrapper links, целый контракт или online admission.'])
