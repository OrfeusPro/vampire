"""Текущие CSV из точного PAK; исторические таблицы и совместимость не угадываются."""
import copy
import csv
import ctypes
import encodings.utf_8_sig
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import struct
import tempfile
import threading
from types import ModuleType
import _csv
import _hashlib
import _json
import _struct
import _ctypes


HERE = Path(__file__).resolve().parent
CATEGORY = 'resource-csv-v3'
RECIPE = 'current-resource-csv-v3'
LIMIT = 16 * 1024 * 1024
JSON_LIMIT = 32 * 1024 * 1024
FIELD_LIMIT = 1024 * 1024
MAX_ENTRIES = 500000
MAX_LEGACY_REPORTS = 64
LEGACY_SCOPE = 'Plain UTF-8 BOM CSV, stored and decoded sizes <=16 MiB; no directory names'
SHA = re.compile('[0-9a-f]{64}')
# Several independently loaded helper modules still share the stdlib csv module.
# setdefault installs one process-local lock, without races between helpers.
_CSV_LOCK = csv.__dict__.setdefault('_phone_exit_resource_csv_lock_v3', threading.RLock())


def _canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('utf-8')


def _full_sha(value):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise ValueError('Нужен полный SHA256 ресурса')
    return value


def _digest(index, args, path):
    owner = _owner(index, args)
    if owner is not None:
        return owner.digest(path)
    store = getattr(args, 'source_store', None)
    original = getattr(store, 'index', index)
    digest = original.digest
    if store is not None and getattr(digest, '__self__', None) is store:
        raise ValueError('CSV barrier требует исходный digest без memo')
    return _full_sha(digest(Path(path)))


def _owner(index, args):
    owner = getattr(args, 'resource_owner', None)
    if owner is not None:
        if getattr(owner, 'recipe', None) != 'resource-owner-sha-v4':
            raise ValueError('Неизвестный resource owner')
        owner.check(index, args)
    return owner


def _checked_pointer(index, args, pointer, *, category=None):
    if not isinstance(pointer, dict) or set(pointer) != {'path', 'sha256'}:
        raise ValueError('Нужен точный pointer ресурса')
    if not isinstance(pointer['path'], str) or not Path(pointer['path']).is_absolute():
        raise ValueError('Нужен абсолютный путь manifest')
    expected = _full_sha(pointer['sha256'])
    path = Path(pointer['path']).resolve()
    root = Path(args.root).resolve()
    allowed = root if category is None else root/'knowledge'/category
    if not path.is_relative_to(allowed) or path.name != 'manifest.json' or path.parent.name != expected:
        raise ValueError('Manifest вне content-addressed каталога ресурсов')
    with path.open('rb') as stream:
        raw = stream.read(JSON_LIMIT + 1)
    if len(raw) > JSON_LIMIT or hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('Manifest ресурса превышает бюджет или изменён')
    owner = _owner(index, args)
    if owner is not None:
        owner.bind_aliases({str(Path(pointer['path']).absolute()): path})
        owner.remember(pointer['path'], raw)
    return path, json.loads(raw.decode('utf-8-sig'))


def _load_checked_module(path, expected):
    raw = Path(path).read_bytes()
    if len(raw) > JSON_LIMIT or hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('Код инструмента изменился перед загрузкой')
    module = ModuleType('resource_csv_' + Path(path).stem.replace('-', '_'))
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def _load_reader(path, expected):
    """Production always loads the fixed, SHA-checked reader; unittest seam."""
    return _load_checked_module(path, expected)


def _runtime(index, args):
    paths = {Path(sys.executable).resolve(), Path(csv.__file__).resolve(),
        Path(encodings.utf_8_sig.__file__).resolve(), Path(ctypes.__file__).resolve(),
        Path(struct.__file__).resolve()}
    for name in ('_csv', '_hashlib', '_json', '_struct', '_ctypes'):
        filename = getattr(sys.modules.get(name), '__file__', None)
        if filename and Path(filename).is_file():
            paths.add(Path(filename).resolve())
    for parent in (Path(sys.base_prefix), Path(sys.base_prefix)/'DLLs'):
        for name in (f'python{sys.version_info.major}{sys.version_info.minor}.dll', 'python3.dll'):
            if (parent/name).is_file():
                paths.add((parent/name).resolve())
    return dict(python=sys.version, implementation=sys.implementation.name,
        files={str(path): _digest(index, args, path) for path in sorted(paths)})


def _prepare(index, args, record_pointer):
    path, record = _checked_pointer(index, args, record_pointer)
    if not isinstance(record, dict) or record.get('schema') != 1 or not isinstance(record.get('entries'), list) or len(record['entries']) > MAX_ENTRIES:
        raise ValueError('Неподдержанная структура индекса записей')
    source = record.get('source') or {}
    if not isinstance(source.get('path'), str) or not Path(source['path']).is_absolute():
        raise ValueError('Индекс не содержит абсолютный путь PAK')
    archive = Path(source['path']).resolve()
    expected = _full_sha(source.get('sha256'))
    if archive.suffix.lower() != '.pak' or not archive.is_file():
        raise ValueError('Источник не является доступным PAK')
    size = archive.stat().st_size
    if source.get('size', size) != size or _digest(index, args, archive) != expected:
        raise ValueError('SHA или размер исходного архива изменился')
    if type(record.get('index_offset')) is not int or not 0 <= record['index_offset'] <= size:
        raise ValueError('Индекс записей имеет неверную границу PAK')
    ids = set()
    for entry in record['entries']:
        _entry(entry, record['index_offset'])
        if entry['entry'] in ids:
            raise ValueError('Повторный ID записи PAK')
        ids.add(entry['entry'])
    dependencies = record.get('dependencies') or {}
    reader = (HERE.parent/'rfnext/scan-pak.py').resolve()
    decoder_root = Path(os.environ.get('PHONEEXIT_RF_RESOURCES', 'F:/PhoneExit Resources/RF Online Next')).resolve()
    oodle = (decoder_root/'tools/oodle-data-shared.dll').resolve()
    reader_sha, oodle_sha = _digest(index, args, reader), _digest(index, args, oodle)
    if (reader_sha != _full_sha(dependencies.get('reader_sha256'))
            or oodle_sha != _full_sha(dependencies.get('oodle_sha256'))):
        raise ValueError('Зависимости декодера индекса изменились')
    tools = {str(p.resolve()): _digest(index, args, p)
        for p in (Path(__file__), HERE/'extract-release-tables.py', HERE/'index-release-archives.py')}
    value = dict(schema=3, recipe=RECIPE,
        record_index=dict(path=str(path), sha256=record_pointer['sha256']),
        source=dict(path=str(archive), sha256=expected, size=size),
        decoder=dict(reader=dict(path=str(reader), sha256=reader_sha),
            oodle=dict(path=str(oodle), sha256=oodle_sha)),
        tools=tools, runtime=_runtime(index, args),
        budgets=dict(decoded_bytes=LIMIT, stored_bytes=LIMIT, csv_field_bytes=FIELD_LIMIT,
            record_index_json_bytes=JSON_LIMIT, record_entries=MAX_ENTRIES, legacy_reports=MAX_LEGACY_REPORTS),
        logical_paths_assumed=False, compatibility='not_established')
    aliases = {str(Path(record_pointer['path']).absolute()): path,
        str(Path(source['path']).absolute()): archive, str(decoder_root/'tools/oodle-data-shared.dll'): oodle}
    return value, record, aliases


def inputs(index, args, record_pointer):
    """Stable exact archive/record/decoder/runtime identity; no historical index."""
    value, _, aliases = _prepare(index, args, record_pointer)
    _barrier(index, args, value, aliases)
    return copy.deepcopy(value)


def _input_sha(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _barrier(index, args, value, aliases, extra_pins=None):
    owner = _owner(index, args)
    if owner is not None:
        owner.bind_aliases(aliases)
    for lexical, expected in aliases.items():
        if Path(lexical).resolve() != expected:
            raise ValueError('Путь ресурса перенаправлен во время извлечения')
    expected_files = dict(value['tools'])
    expected_files.update(value['runtime']['files'])
    expected_files.update(extra_pins or {})
    for item in (value['record_index'], value['source'], value['decoder']['reader'], value['decoder']['oodle']):
        expected_files[item['path']] = item['sha256']
    for filename, expected in expected_files.items():
        actual = owner.expect(filename, expected) if owner is not None else _digest(index, args, filename)
        if actual != expected:
            raise ValueError('Вход CSV изменился во время извлечения: ' + filename)
    if _runtime(index, args) != value['runtime']:
        raise ValueError('Runtime CSV изменился во время извлечения')
    for lexical, expected in aliases.items():
        if Path(lexical).resolve() != expected:
            raise ValueError('Путь ресурса перенаправлен после SHA-барьера')


def _entry(entry, index_offset):
    if not isinstance(entry, dict):
        raise ValueError('Неверная запись индекса PAK')
    for key in ('entry', 'offset', 'end', 'bytes', 'uncompressed', 'method'):
        if type(entry.get(key)) is not int:
            raise ValueError('Неверное целое поле записи PAK: ' + key)
    if (entry['entry'] < 0 or not 0 <= entry['offset'] < entry['end'] <= index_offset
            or entry['bytes'] <= 0 or entry['uncompressed'] <= 0 or entry['method'] not in (0, 1)
            or type(entry.get('encrypted')) is not bool):
        raise ValueError('Неверные границы или флаги записи PAK')
    if entry.get('decoded_sha256') is not None:
        _full_sha(entry['decoded_sha256'])


def _parse(parser, data):
    with _CSV_LOCK:
        previous = csv.field_size_limit()
        try:
            csv.field_size_limit(FIELD_LIMIT)
            return parser.parse_csv(data)
        finally:
            csv.field_size_limit(previous)


def _header(reader, stream, entry, index_offset):
    header = reader.header(stream, entry['offset'], index_offset)
    fields = {'pos': 'offset', 'end': 'end', 'size': 'bytes', 'usize': 'uncompressed',
        'method': 'method', 'encrypted': 'encrypted'}
    if not header or any(header.get(key) != entry[field] for key, field in fields.items()):
        raise ValueError('Fresh record header не совпал с SHA-bound индексом')
    if header['method']:
        blocks = header.get('blocks')
        if (not isinstance(blocks, list) or not 1 <= len(blocks) <= 32768
                or any(not isinstance(block, (list, tuple)) or len(block) != 2
                    or any(type(part) is not int for part in block)
                    or not 0 <= block[0] < block[1] <= entry['end']-entry['offset'] for block in blocks)
                or sum(block[1]-block[0] for block in blocks) > LIMIT):
            raise ValueError('Compressed record превышает бюджет чтения')
    return header


def _proven_uasset(value, record, entry):
    producer = str((HERE/'index-release-archives.py').resolve())
    return (record.get('dependencies', {}).get('tool_sha256') == value['tools'][producer]
        and type(record.get('decode_limit')) is int and record['decode_limit'] == 2*1024*1024
        and entry.get('decode_status') == 'decoded' and entry.get('uasset') is True
        and isinstance(entry.get('decoded_sha256'), str) and SHA.fullmatch(entry['decoded_sha256']) is not None)


def _legacy_bridge(index, args, value, record, parser, reader):
    """Reuse only the existing CURRENT CSV proof, never old comparison inputs."""
    folder = Path(value['record_index']['path']).parent/'table-snapshots'
    candidates = sorted(folder.glob('*/manifest.json'))
    if len(candidates) > MAX_LEGACY_REPORTS:
        raise ValueError('Слишком много legacy CSV reports для однозначного переноса')
    accepted, projection, pins = [], None, {}
    entries = {entry['entry']: entry for entry in record['entries']}
    root = Path(args.root).resolve()
    with Path(value['source']['path']).open('rb') as stream:
        for path in candidates:
            if not SHA.fullmatch(path.parent.name):
                continue
            pointer = dict(path=str(path.resolve()), sha256=path.parent.name)
            _, report = _checked_pointer(index, args, pointer)
            source = report.get('source') or {}
            dependencies = report.get('dependencies') or {}
            if (report.get('schema') != 1 or report.get('scope') != LEGACY_SCOPE
                    or report.get('record_index_sha256') != value['record_index']['sha256']
                    or report.get('tool_sha256') != value['tools'][str((HERE/'extract-release-tables.py').resolve())]
                    or source.get('sha256') != value['source']['sha256']
                    or not isinstance(source.get('path'), str)
                    or Path(source['path']).resolve() != Path(value['source']['path'])
                    or dependencies.get('reader_sha256') != value['decoder']['reader']['sha256']
                    or dependencies.get('oodle_sha256') != value['decoder']['oodle']['sha256']):
                continue
            if (not isinstance(report.get('tables'), list) or not isinstance(report.get('errors'), list)
                    or type(report.get('skipped')) is not int or report['skipped'] < 0):
                raise ValueError('Неверная структура подходящего legacy CSV report')
            tables, seen = [], set()
            for old in report['tables']:
                if not isinstance(old, dict) or type(old.get('entry')) is not int or old['entry'] in seen:
                    raise ValueError('Неоднозначная legacy CSV запись')
                seen.add(old['entry'])
                entry = entries.get(old['entry'])
                if entry is None:
                    raise ValueError('Legacy CSV отсутствует в текущем индексе')
                _entry(entry, record['index_offset'])
                digest = _full_sha(old.get('sha256'))
                current = Path(old.get('file', '')).resolve()
                expected = Path(value['record_index']['path']).parent/'csv-blobs'/(digest+'.csv')
                if current != expected or not current.is_relative_to(expected.parent):
                    raise ValueError('Legacy bridge пытается прочитать чужой CSV')
                with current.open('rb') as blob:
                    data = blob.read(LIMIT+1)
                parsed = _parse(parser, data) if len(data) <= LIMIT else None
                if (parsed is None or hashlib.sha256(data).hexdigest() != digest
                        or entry['encrypted'] or entry['bytes'] > LIMIT or entry['uncompressed'] > LIMIT
                        or len(data) != entry['uncompressed'] or old.get('bytes') != len(data)
                        or old.get('offset') != entry['offset'] or old.get('header') != parsed[0]
                        or old.get('rows') != parsed[1] or old.get('internal_path') is not None
                        or (entry.get('decoded_sha256') is not None and entry['decoded_sha256'] != digest)):
                    raise ValueError('Текущий legacy CSV не прошёл проверку')
                _header(reader, stream, entry, record['index_offset'])
                target = _blob(root, digest)
                _write_blob(target, data, digest)
                tables.append(dict(file=str(target), entry=entry['entry'], offset=entry['offset'],
                    sha256=digest, bytes=len(data), header=parsed[0], rows=parsed[1], internal_path=None))
                pins[str(current)] = digest
            errors, error_ids = [], set()
            for old in report['errors']:
                if (not isinstance(old, dict) or type(old.get('entry')) is not int or old['entry'] not in entries
                        or old['entry'] in seen or old['entry'] in error_ids):
                    raise ValueError('Ошибка legacy CSV не принадлежит текущему индексу')
                error_ids.add(old['entry'])
                errors.append(dict(entry=old['entry'], offset=entries[old['entry']]['offset'],
                    error_type=str(old.get('error_type', 'ValueError')), reason='legacy_decode_or_csv_error'))
            expected_skipped = sum(entry['encrypted'] or entry['bytes'] > LIMIT
                or entry['uncompressed'] > LIMIT for entry in record['entries'])
            if report['skipped'] != expected_skipped or len(tables)+len(errors)+report['skipped'] > len(entries):
                raise ValueError('Счётчики legacy CSV не совпали с текущим индексом')
            current_projection = dict(tables=sorted(tables, key=lambda item: item['entry']),
                errors=sorted(errors, key=lambda item: (item['entry'], item['error_type'])), skipped=report['skipped'])
            if projection is not None and projection != current_projection:
                raise ValueError('Подходящие legacy CSV reports противоречат друг другу')
            projection = current_projection
            accepted.append(pointer)
            pins[pointer['path']] = pointer['sha256']
    if projection is None:
        return None
    return dict(**projection, pins=pins, provenance=dict(method='checked_legacy_current_csv',
        reports=accepted, scope=LEGACY_SCOPE, previous_comparison_inputs_read=False))


def _blob(root, digest):
    return root/'knowledge/resource-csv-blobs-v3'/(digest+'.csv')


def _write_blob(path, data, digest):
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open('xb') as stream:
            stream.write(data)
    except FileExistsError:
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('Существующий CSV blob повреждён') from None


def _outputs(index, args, report, record, parser):
    root = Path(args.root).resolve()
    records = {entry['entry']: entry for entry in record['entries']}
    seen, checked = set(), {}
    for table in report['tables']:
        if not isinstance(table, dict) or type(table.get('entry')) is not int or table['entry'] in seen:
            raise ValueError('Неверная или повторная CSV-запись отчёта')
        seen.add(table['entry'])
        entry = records.get(table['entry'])
        if entry is None:
            raise ValueError('CSV не принадлежит выбранному индексу записей')
        _entry(entry, record['index_offset'])
        expected = _full_sha(table.get('sha256'))
        path = Path(table.get('file', '')).resolve()
        wanted = _blob(root, expected)
        if path != wanted or not path.is_relative_to(root/'knowledge/resource-csv-blobs-v3'):
            raise ValueError('CSV blob вне content-addressed каталога')
        if path not in checked:
            with path.open('rb') as stream:
                raw = stream.read(LIMIT + 1)
            if len(raw) > LIMIT or hashlib.sha256(raw).hexdigest() != expected:
                raise ValueError('SHA сохранённого CSV blob изменился')
            owner = _owner(index, args)
            if owner is not None:
                owner.bind_aliases({str(Path(table['file']).absolute()): path})
                owner.remember(path, raw)
            checked[path] = (len(raw), _parse(parser, raw))
        size, parsed = checked[path]
        if (parsed is None or table.get('bytes') != size or size != entry['uncompressed']
                or table.get('offset') != entry['offset'] or entry['encrypted']
                or entry['bytes'] > LIMIT or entry['uncompressed'] > LIMIT
                or table.get('header') != parsed[0] or table.get('rows') != parsed[1]
                or table.get('internal_path') is not None
                or (entry.get('decoded_sha256') is not None and entry['decoded_sha256'] != expected)):
            raise ValueError('Данные CSV не совпали с отчётом и индексом')


def _accounting(report, value, record):
    entries = {entry['entry']: entry for entry in record['entries']}
    skipped = {}
    for entry in record['entries']:
        reason = ('encrypted' if entry['encrypted'] else
            'size_budget' if entry['uncompressed'] > LIMIT or entry['bytes'] > LIMIT else
            'proven_uasset_magic' if _proven_uasset(value, record, entry) else None)
        if reason is not None:
            skipped[entry['entry']] = reason
    legacy = report.get('legacy_bridge')
    if legacy is not None:
        # The historical tool decoded UAssets again, so its counters have no
        # producer-classification shortcut. Its exact current CSV was checked
        # during migration and the copied outputs now stand independently.
        skipped = {key: reason for key, reason in skipped.items() if reason != 'proven_uasset_magic'}
        expected_reasons = {'legacy_encrypted_or_size_budget': len(skipped)} if skipped else {}
        if (not isinstance(legacy, dict) or legacy.get('method') != 'checked_legacy_current_csv'
                or legacy.get('previous_comparison_inputs_read') is not False
                or legacy.get('cold_migration_only') is not True):
            raise ValueError('Неверная граница legacy CSV bridge')
    else:
        expected_reasons = {reason: list(skipped.values()).count(reason) for reason in sorted(set(skipped.values()))}
    used = set()
    for table in report['tables']:
        entry = table.get('entry')
        if entry in skipped or entry in used:
            raise ValueError('CSV счётчики пересекаются со skipped records')
        used.add(entry)
    for error in report['errors']:
        if (not isinstance(error, dict) or type(error.get('entry')) is not int
                or error['entry'] not in entries or error['entry'] in skipped or error['entry'] in used
                or error.get('offset') != entries[error['entry']]['offset']
                or not isinstance(error.get('error_type'), str) or not error['error_type']):
            raise ValueError('Неверные ошибки в CSV-отчёте')
        used.add(error['entry'])
    non_csv = len(entries)-len(skipped)-len(used)
    expected_state = 'partial' if report['errors'] or record.get('reached_index') is not True else 'extracted'
    if (report['skipped'] != len(skipped) or report.get('skip_reasons') != expected_reasons
            or type(report.get('non_csv_records')) is not int or report['non_csv_records'] != non_csv
            or report.get('record_scan_complete') is not (record.get('reached_index') is True)
            or report['state'] != expected_state or report.get('logical_paths_assumed') is not False):
        raise ValueError('Счётчики CSV-отчёта не совпали с текущим индексом')


def load_checked(index, args, report_pointer, expected_inputs=None):
    """Fresh input and every output SHA; a report never grants compatibility."""
    _, report = _checked_pointer(index, args, report_pointer, category=CATEGORY)
    if not isinstance(report, dict) or not isinstance(report.get('record_index'), dict):
        raise ValueError('Неверный индекс CSV-отчёта')
    prepared = _prepare(index, args, report['record_index'])
    return _load_checked_prepared(index, args, report_pointer, prepared, expected_inputs)


def _load_checked_prepared(index, args, report_pointer, prepared, expected_inputs=None, extra_pins=None):
    """Reuse preparation only within the caller's still-open verification."""
    path, report = _checked_pointer(index, args, report_pointer, category=CATEGORY)
    if (not isinstance(report, dict) or report.get('schema') != 3 or report.get('recipe') != RECIPE
            or report.get('compatibility') != 'not_established' or report.get('state') not in ('extracted', 'partial')
            or not isinstance(report.get('tables'), list) or not isinstance(report.get('errors'), list)
            or type(report.get('skipped')) is not int or report['skipped'] < 0):
        raise ValueError('Неверный отчёт текущих CSV')
    value, record, aliases = prepared
    expected = value if expected_inputs is None else expected_inputs
    if (report.get('inputs') != expected or report.get('input_sha256') != _input_sha(expected)
            or report.get('source') != value['source'] or (expected_inputs is not None and value != expected_inputs)):
        raise ValueError('Входы CSV-отчёта изменились')
    if report.get('record_index') != value['record_index']:
        raise ValueError('Индекс CSV-отчёта изменился')
    parser_path = HERE/'extract-release-tables.py'
    parser = _load_checked_module(parser_path, value['tools'][str(parser_path.resolve())])
    _outputs(index, args, report, record, parser)
    _accounting(report, value, record)
    _barrier(index, args, value, aliases, extra_pins)
    if _digest(index, args, path) != report_pointer['sha256']:
        raise ValueError('CSV-отчёт изменился во время проверки')
    return copy.deepcopy(report)


def _reuse_producer(index, args, prepared, cache):
    knowledge = getattr(args, 'knowledge', None)
    if knowledge is None:
        return None
    registry = Path(knowledge)/'resource-csv-reuse.json'
    if not registry.is_file():
        return None
    raw = registry.read_bytes()
    if len(raw) > 4096:
        raise ValueError('CSV producer registry превышает бюджет')
    rule = json.loads(raw)
    if (not isinstance(rule, dict) or set(rule) != {'schema', 'recipe', 'previous_producer_sha256'}
            or type(rule['schema']) is not int or rule['schema'] != 1
            or rule['recipe'] != 'csv-prepared-inputs-reuse-v1'):
        raise ValueError('Неизвестное правило переноса CSV producer')
    previous = _full_sha(rule['previous_producer_sha256'])
    value, record, aliases = prepared
    old = copy.deepcopy(value)
    producer = str(Path(__file__).resolve())
    if previous == value['tools'][producer]:
        raise ValueError('CSV producer registry указывает текущий producer')
    old['tools'][producer] = previous
    old_cache = Path(args.root).resolve()/'knowledge/resource-csv-v3-cache'/(_input_sha(old)+'.json')
    if not old_cache.is_file():
        return None
    with old_cache.open('rb') as stream:
        cache_raw = stream.read(4097)
    if len(cache_raw) > 4096:
        raise ValueError('CSV producer cache превышает бюджет')
    pointer = json.loads(cache_raw)
    old_path, report = _checked_pointer(index, args, pointer, category=CATEGORY)
    # Only the registered producer SHA may differ. The current decoder,
    # runtime, source, record index and budgets retain exact equality.
    if (not isinstance(report, dict) or report.get('inputs') != old
            or report.get('input_sha256') != _input_sha(old)):
        raise ValueError('Прежние входы CSV отличаются от зарегистрированного переноса')
    report = dict(report, inputs=copy.deepcopy(value), input_sha256=_input_sha(value))
    pins = {str(registry): hashlib.sha256(raw).hexdigest(),
        str(old_cache): hashlib.sha256(cache_raw).hexdigest(), str(old_path): pointer['sha256']}
    aliases = dict(aliases)
    for path in (registry, old_cache, Path(pointer['path'])):
        aliases[str(path.absolute())] = path.resolve()
    # Revalidate the migrated body through the same current verifier, including
    # outputs/accounting and the final fresh SHA barrier, before cache assignment.
    provisional = _save(Path(args.root).resolve(), report)
    _load_checked_prepared(index, args, provisional, (value, record, aliases), extra_pins=pins)
    report['producer_reuse'] = dict(recipe=rule['recipe'], previous_report=pointer,
        previous_producer_sha256=previous, registry_sha256=pins[str(registry)],
        cold_migration_only=True)
    result = _save(Path(args.root).resolve(), report)
    _cache_write(cache, result, owner=_owner(index, args))
    return result


def _save(root, report):
    raw = _canonical(report)
    digest = hashlib.sha256(raw).hexdigest()
    path = root/'knowledge'/CATEGORY/digest/'manifest.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open('xb') as stream:
            stream.write(raw)
    except FileExistsError:
        if path.read_bytes() != raw:
            raise ValueError('Существующий CSV manifest повреждён') from None
    return dict(path=str(path), sha256=digest)


def _cache_write(path, pointer, *, owner=None):
    if owner is not None:
        owner.defer(path, pointer)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = _canonical(pointer)
    if path.exists():
        if path.read_bytes() != raw:
            raise ValueError('CSV cache key имеет другой неизменяемый результат')
        return
    handle, temporary = tempfile.mkstemp(prefix='.csv-v3-', dir=path.parent)
    try:
        with os.fdopen(handle, 'wb') as stream:
            stream.write(raw)
        os.replace(temporary, path)
    finally:
        if Path(temporary).exists():
            Path(temporary).unlink()


def extract(index, args, record_pointer, *, source_sha256=None):
    value, record, aliases = _prepare(index, args, record_pointer)
    if source_sha256 is not None and _full_sha(source_sha256) != value['source']['sha256']:
        raise ValueError('Запрошен другой SHA исходного архива')
    root = Path(args.root).resolve()
    cache = root/'knowledge/resource-csv-v3-cache'/(_input_sha(value)+'.json')
    owner = _owner(index, args)
    pending = owner.cached(cache) if owner is not None else None
    if pending is not None or cache.is_file():
        raw = cache.read_bytes() if cache.is_file() else None
        pointer = pending if pending is not None else json.loads(raw)
        _load_checked_prepared(index, args, pointer, (value, record, aliases), expected_inputs=value)
        if raw is not None and cache.read_bytes() != raw:
            raise ValueError('CSV cache pointer изменился во время проверки')
        return copy.deepcopy(pointer)
    reused = _reuse_producer(index, args, (value, record, aliases), cache)
    if reused is not None:
        return reused
    reader_pointer = value['decoder']['reader']
    reader = _load_reader(Path(reader_pointer['path']), reader_pointer['sha256'])
    if (Path(reader.ROOT)/'tools/oodle-data-shared.dll').resolve() != Path(value['decoder']['oodle']['path']):
        raise ValueError('Reader загрузил другой Oodle')
    parser_path = HERE/'extract-release-tables.py'
    parser = _load_checked_module(parser_path, value['tools'][str(parser_path.resolve())])
    bridge = _legacy_bridge(index, args, value, record, parser, reader)
    if bridge is not None:
        tables, errors = bridge['tables'], bridge['errors']
        skipped = bridge['skipped']
        skip_reasons = {'legacy_encrypted_or_size_budget': skipped} if skipped else {}
        non_csv = max(0, len(record['entries'])-len(tables)-len(errors)-skipped)
        return _finish(index, args, value, record, aliases, parser, tables, errors, skip_reasons,
            non_csv, cache, bridge=bridge)
    tables, errors, skip_reasons = [], [], {}
    non_csv = 0
    with Path(value['source']['path']).open('rb') as stream:
        for entry in record['entries']:
            reason = ('encrypted' if entry['encrypted'] else
                'size_budget' if entry['uncompressed'] > LIMIT or entry['bytes'] > LIMIT else
                'proven_uasset_magic' if _proven_uasset(value, record, entry) else None)
            if reason is not None:
                skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
                continue
            header = _header(reader, stream, entry, record['index_offset'])
            try:
                data = reader.decode(stream, header)
                if not isinstance(data, bytes) or len(data) != entry['uncompressed'] or len(data) > LIMIT:
                    raise ValueError('decoded_size_mismatch')
                digest = hashlib.sha256(data).hexdigest()
                if entry.get('decoded_sha256') is not None and digest != entry['decoded_sha256']:
                    raise ValueError('decoded_sha256_mismatch')
                parsed = _parse(parser, data)
            except (ValueError, OSError, UnicodeError, csv.Error) as error:
                errors.append(dict(entry=entry['entry'], offset=entry['offset'], error_type=type(error).__name__,
                    reason=str(error) if str(error) in ('decoded_size_mismatch', 'decoded_sha256_mismatch') else 'decode_or_csv_error'))
                continue
            if parsed is None:
                non_csv += 1
                continue
            target = _blob(root, digest)
            _write_blob(target, data, digest)
            tables.append(dict(file=str(target), entry=entry['entry'], offset=entry['offset'],
                sha256=digest, bytes=len(data), header=parsed[0], rows=parsed[1], internal_path=None))
    return _finish(index, args, value, record, aliases, parser, tables, errors, skip_reasons, non_csv, cache)


def _finish(index, args, value, record, aliases, parser, tables, errors, skip_reasons, non_csv, cache, bridge=None):
    pins = {} if bridge is None else bridge['pins']
    _barrier(index, args, value, aliases, pins)
    report = dict(schema=3, recipe=RECIPE, state='partial' if errors or record.get('reached_index') is not True else 'extracted',
        inputs=value, input_sha256=_input_sha(value), source=value['source'], record_index=value['record_index'],
        tables=tables, errors=errors, skipped=sum(skip_reasons.values()), skip_reasons=skip_reasons,
        non_csv_records=non_csv, record_scan_complete=record.get('reached_index') is True,
        scope='Plain UTF-8 BOM CSV; stored and decoded sizes <=16 MiB; prior source-bound UAsset magic may be reused; directory names unknown',
        compatibility='not_established', logical_paths_assumed=False)
    if bridge is not None:
        report['legacy_bridge'] = dict(bridge['provenance'], consumed_files=pins,
            cold_migration_only=True)
    _outputs(index, args, report, record, parser)
    _accounting(report, value, record)
    _barrier(index, args, value, aliases, pins)
    pointer = _save(Path(args.root).resolve(), report)
    _cache_write(cache, pointer, owner=_owner(index, args))
    return pointer
