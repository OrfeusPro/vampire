"""Whole current QuestTask loading with a CSV-backed service policy fixture."""
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
RECIPE = 'quest-mixed-current-v1'
TASK_IDS = ['110120005', '110120010', '110120020', '110120030', '110120040', '110120070',
            '200110010', '200110020', '200110030', '200110050', '200110060', '200110070']
COUNTERS = (0x1234567800000001, 0x8765432100000002)
SERVICE_MANAGER = 0x14b1ca960
SERVER_MANAGER = 0x14b1ca720
POLICY_ROOTS = ('0x145a4d700', '0x145bff820', '0x145c03670', '0x145bff6a0', '0x145bfefd0')
TASK_KIND = dict(zip(TASK_IDS, (6, 5, 6, 5, 6, 6, 6, 5, 6, 5, 6, 6)))
TASK_ROWS_SHA256 = '2958fd28288c363ff38000ef4658661220d5474e7622778d7fd783d7c3dc8fb3'
DATASET_SHA256 = 'cb711287de0a107f38a04a3dbffe11744a70cc4d198c801d0a9602ca24dacb69'
NATIVE_ENTRIES = {
    '0x145b736a0': 32, '0x145b73280': 16, '0x1416169f0': 32,
    '0x141437580': 16, '0x141436d70': 48, '0x14142e750': 220,
    '0x145b4afa0': 156, '0x145b4b110': 156, '0x145b4a830': 156,
    '0x145b48f60': 26, '0x145b48c70': 156, '0x145b4c130': 156,
    '0x145b5f680': 16, '0x1445f6680': 208, '0x145a4d700': 192,
    '0x1445f5fc0': 624, '0x1445f1650': 624, '0x145de7870': 156,
    '0x145b4c280': 156, '0x145c03670': 96, '0x145bff820': 96,
    '0x145bff6a0': 96, '0x145bfefd0': 96, '0x141491e00': 48,
    '0x141403bd0': 2496, '0x140bb4a10': 16, '0x1445f6030': 468,
    '0x1445f61a0': 312, '0x1445f6070': 624, '0x1445f1610': 468,
    '0x1445f1cd0': 312, '0x1445f6010': 660, '0x1445f1630': 1284,
    '0x1445e4d90': 2556, '0x1487f8de3': 624, '0x141500740': 468,
    '0x145b55eb0': 156,
}


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require(condition, message):
    if not condition:
        raise ValueError('Current mixed loader: ' + message)


def fingerprint(value):
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


def selected_rows(payload):
    physical = payload.splitlines(keepends=True)
    reader = csv.reader(io.StringIO(payload.decode('utf-8-sig'), newline=''))
    columns = next(reader)
    previous = reader.line_num
    rows = []
    for row in reader:
        end = reader.line_num
        if row[0] in TASK_IDS:
            rows.append((dict(zip(columns, row)), b''.join(physical[previous:end])))
        previous = end
    require(len(columns) == 17 and [row['Id'] for row, _ in rows] == TASK_IDS,
            'source task selection or schema changed')
    require(all(row['QuestInfoId'] == ('110120' if i < 6 else '200110')
                and row['ServerServiceGroupId'] == ('' if i < 6 else '10000')
                for i, (row, _) in enumerate(rows)), 'source groups changed')
    require(fingerprint([row for row, _ in rows]) == TASK_ROWS_SHA256, 'source task fields changed')
    return columns, rows


def retained_rows(rows, region, reverse):
    ordered = list(reversed(rows)) if reverse else rows
    return [(row, raw) for row, raw in ordered
            if not row['ServerServiceGroupId'] or region < 5]


def expected_projection(task_id, kind, index):
    result = bytearray(b'\xcc' * 32)
    struct.pack_into('<QBB', result, 0, int(task_id), kind, index)
    struct.pack_into('<II', result, 12, COUNTERS[0] & 0xffffffff, COUNTERS[1] & 0xffffffff)
    struct.pack_into('<Q', result, 24, 0)
    return result.hex()


def validate(report, context=None):
    flags = dict(source_sha256=SOURCE, native_execution=True, network_used=False,
                 runtime_admitted=False, active_region_verified=False, active_task_verified=False,
                 ordered_catalog_verified=False, action_admitted=False, order_admitted=False,
                 table_loaders_executed=False, native_russian_override=False)
    require(isinstance(report, dict) and all(report.get(key) == value
            and (type(value) is not bool or type(report.get(key)) is bool)
            for key, value in flags.items()), 'report scope differs')
    cases = report.get('cases', [])
    require([(row.get('region'), row.get('reverse')) for row in cases]
            == [(region, reverse) for region in range(8) for reverse in (False, True)],
            'region/order matrix differs')
    projections = 0
    for case in cases:
        expected_ids = TASK_IDS if case['region'] < 5 else TASK_IDS[:6]
        if case['reverse']:
            expected_ids = list(reversed(expected_ids))
        skipped = TASK_IDS[6:] if case['region'] >= 5 else []
        expected_groups = list(dict.fromkeys(identifier[:6] for identifier in expected_ids))
        require(case.get('task_ids') == expected_ids and case.get('skipped_ids') == skipped
                and case.get('records') == len(expected_ids)
                and case.get('group_ids') == expected_groups
                and case.get('groups_match_native_records') is True
                and case.get('missing_group_verified') is (case['region'] >= 5)
                and case.get('inputs_unchanged') is True
                and case.get('heap_guards_verified') is True
                and case.get('policy_temporaries_released') is True,
                'retained records/group coverage differs')
        rows = case.get('projections', [])
        require(len(rows) == len(expected_ids) and [row['task_id'] for row in rows] == expected_ids,
                'projection count or order differs')
        group_indexes = {}
        for row in rows:
            group = row['task_id'][:6]
            index = group_indexes.get(group, 0)
            group_indexes[group] = index + 1
            require(row['quest_id'] == group and row['index'] == index
                    and row['kind'] == TASK_KIND[row['task_id']]
                    and row['progress_hex'] == expected_projection(row['task_id'], row['kind'], index),
                    'group-local index or output differs')
        entries = case.get('policy_entries', {})
        require(entries == {name: (12 if name == '0x145a4d700' else 6) for name in POLICY_ROOTS},
                'policy execution coverage differs')
        require(case.get('russian_override_calls') == 1, 'explicit no-op override coverage differs')
        callbacks = case.get('callbacks', {})
        require(callbacks == dict(column=16, file_load=1, group_array_resize=4 if case['region'] < 5 else 2,
                                 node_resize=3, override_fixture=1), 'storage provider coverage differs')
        projections += len(rows)
    metrics = report.get('metrics', {})
    require(projections == 156 and metrics.get('abi_checks') == 172
            and metrics.get('call_counts') == 172 and metrics.get('fixture_calls') == 49220
            and all(metrics.get('entry_counts', {}).get(address) == count
                    for address, count in NATIVE_ENTRIES.items()), 'ABI/native/projection coverage differs')
    require(report.get('dataset', {}).get('maps_built_by') == 'bounded_fixture_from_source_csv'
            and len(report['dataset'].get('service_rows', [])) == 8
            and report['dataset'].get('server_row', {}).get('row', {}).get('Id') == '387',
            'source policy dataset differs')
    require(fingerprint(report['dataset'].get('task_rows')) == TASK_ROWS_SHA256,
            'source task evidence differs')
    require(fingerprint(report['dataset']) == DATASET_SHA256, 'source policy evidence differs')
    source = report.get('source_markers')
    require(source == dict(original_table='0x1499f9508', cloned_table='0x28002500',
        replaced_slot=64, original_override='0x145b6a0b0', fixture_override='0x28002600',
        dispatch={'0x145b5fab7': 'e844dceeff', '0x145b5fabc': '84c0',
                  '0x145b5fabe': '0f8558040000', '0x145b5ff2d': 'e8fee0eeff',
                  '0x145b5ff32': '4d8b0424', '0x145b5ff36': '488bd0',
                  '0x145b5ff39': '498bcc', '0x145b5ff3c': '41ff5040'}),
        'bounded source dispatch or no-RU override scope differs')
    if context is not None:
        require(context.get('source_sha256') == SOURCE and context.get('task_ids') == TASK_IDS
                and report.get('tables') == context['tables']
                and report.get('limits') == context['limits'], 'context/input binding differs')
        require(all(metrics.get('entry_counts', {}).get(address, 0) > 0
                    for address in context['functions']), 'whole native root was not executed')
        require(set(context['functions']) | set(context['leaves']) == set(NATIVE_ENTRIES),
                'declared native source scope differs')


def run(context_path=None, *, root=None):
    common = load('replay-quest-loader-current-v1')
    audit = load('audit-client-release')
    path = Path(context_path) if context_path else HERE / 'knowledge/native-contexts/quest-mixed-current.json'
    context_raw = path.read_bytes()
    context = json.loads(context_raw)
    require(context.get('schema') == 1 and context.get('recipe') == RECIPE
            and context.get('source_sha256') == SOURCE and context.get('task_ids') == TASK_IDS,
            'context scope differs')
    addresses = context['addresses']
    address = lambda old: int(addresses[hex(old)], 16)
    h = load('native-request-harness-11316').make_harness(context['exports'],
        {int(value, 16) for value in context['functions']},
        leaves={int(key, 16): value for key, value in context['leaves'].items()},
        root=root, source_sha256=SOURCE, copy_thunk=address(0x1487f5ab9))
    metrics = common.install_guards(h, context)
    dataset, inputs = load('replay-quest-service-current-v1').parse_tables(common, h.root, context)
    services = [item for item in dataset['service_rows'] if item['row']['GroupId'] == '10000']
    servers = [item for item in dataset['server_rows'] if item['row']['Id'] == '387']
    require(len(services) == 8 and len(servers) == 1
            and all(not item['row']['ExcludeServerId'] and not item['row']['IncludeServerId']
                    for item in services), 'bounded policy source selection changed')
    payload = common.checked_blob(h.root, context['tables']['quest_task'])
    columns, rows = selected_rows(payload)
    inputs[path.resolve()] = hashlib.sha256(context_raw).hexdigest()
    inputs[h.source] = SOURCE
    for name in ('replay-quest-mixed-current-v1', 'quest-loader-fixtures-current-v1',
                 'replay-quest-loader-current-v1', 'replay-quest-service-current-v1'):
        tool = HERE / (name + '.py')
        inputs[tool.resolve()] = audit.sha256(tool)
    for item in h.evidence:
        inputs[Path(item['path']).resolve()] = item['sha256']
    fixture = load('quest-loader-fixtures-current-v1').create_fixture_state(h, addresses, columns)
    uc, x, base = h.uc, h.x, h.scratch
    get, put = fixture.get, fixture.put
    manager, primary, group = base + 0x1000, base + 0x1018, base + 0x1068
    service_nodes, service_slots, service_records = base + 0x4000, base + 0x4100, base + 0x4200
    server_nodes, server_record = base + 0x5000, base + 0x5100
    current = {}
    policy_allocations = set()

    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_' + name))

    def identifier_string(machine):
        require(reg('RDX') == 387, 'policy identifier input differs')
        data = b'3\x008\x007\x00\0\0'
        target = fixture.allocate(len(data))
        policy_allocations.add(target)
        uc.mem_write(target, data)
        put(reg('RCX'), target)
        put(reg('RCX') + 8, len(data) // 2, 4)
        put(reg('RCX') + 12, len(data) // 2, 4)
        h.finish(reg('RCX'))

    def split_empty(machine):
        require(reg('RCX') in current['empty_lists'] and reg('R8') == 0x1489f4900
                and reg('R9') == 1, 'policy empty-list input differs')
        uc.mem_write(reg('RDX'), bytes(16))
        h.finish(reg('RDX'))

    def destroy_empty(machine):
        require(reg('RCX') == 0 and reg('RDX') == 0, 'policy cleanup is not empty')
        h.finish()

    h.add_fixture(0x141429f90, identifier_string)
    h.add_fixture(0x141432370, split_empty)
    h.add_fixture(0x141404b20, destroy_empty)
    runtime = common.install_runtime(h, fixture.numeric_input, fixture.address, base + 0x7000)
    tls = 0x29000000
    uc.mem_map(tls, 0x110000)
    uc.reg_write(x.UC_X86_REG_GS_BASE, tls)
    put(tls + 0x58, tls + 0x1000)
    put(tls + 0x1000, tls + 0x2000)
    put(tls + 0x2000 + 0x101184, 0, 4)
    for at in (0x14b6a7d00, 0x14b5f37c8, 0x14b5f3784, 0x14b5f3790):
        put(at, 0, 4)
    put(0x14b5f3788, 0)

    def seed_policy(region):
        uc.mem_write(SERVICE_MANAGER, bytes(0x88))
        uc.mem_write(SERVER_MANAGER, bytes(0x110))
        put(SERVICE_MANAGER + 0x28, service_nodes)
        put(SERVICE_MANAGER + 0x30, 1, 4)
        put(SERVICE_MANAGER + 0x60, 0, 4)
        put(SERVICE_MANAGER + 0x64, -1, 4)
        put(SERVICE_MANAGER + 0x70, 2, 4)
        put(SERVICE_MANAGER + 0x78, region, 4)
        put(SERVICE_MANAGER + 0x7c, 387, 4)
        put(service_nodes, 10000, 4)
        put(service_nodes + 8, service_slots)
        put(service_nodes + 16, 8, 4)
        put(service_nodes + 24, -1, 4)
        current['empty_lists'] = set()
        for i, item in enumerate(services):
            record = service_records + i * 64
            put(service_slots + i * 8, record)
            for column, offset in (('GroupId', 8), ('RegionType', 12),
                                   ('MinServicePhase', 16), ('MaxServicePhase', 20)):
                put(record + offset, int(item['row'][column]), 4)
            current['empty_lists'].update((record + 24, record + 40))
        put(SERVER_MANAGER + 0xc0, server_nodes)
        put(SERVER_MANAGER + 0xc8, 1, 4)
        put(SERVER_MANAGER + 0xf8, -1, 4)
        put(SERVER_MANAGER + 0xfc, 0, 4)
        put(SERVER_MANAGER + 0x108, 2, 4)
        put(server_nodes, 387, 4)
        put(server_nodes + 8, server_record)
        put(server_nodes + 16, -1, 4)
        put(server_record + 0x28, int(servers[0]['row']['ServicePhase']), 4)

    cases = []
    for region in range(8):
        for reverse in (False, True):
            ordered = list(reversed(rows)) if reverse else rows
            expected = retained_rows(rows, region, reverse)
            fixture.reset([raw for _, raw in ordered])
            runtime['calls'].clear()
            policy_allocations.clear()
            seed_policy(region)
            immutable_policy = [(at, bytes(uc.mem_read(at, size))) for at, size in
                ((SERVICE_MANAGER, 0x88), (SERVER_MANAGER, 0x110), (base + 0x4000, 0x1200),
                 (tls, 0x110000), (0x14b5f3784, 16), (0x14b5f37c8, 4))]
            before = dict(metrics['entry_counts'])
            h.call(address(0x145b5f270), manager + 8, budget=2000000)
            require(all(pointer not in fixture.blocks for pointer in policy_allocations),
                    'policy temporary leaked into loaded records')
            require(all(bytes(uc.mem_read(at, len(raw))) == raw for at, raw in immutable_policy),
                    'service input changed during loading')
            require(get(primary + 8, 4) == len(expected), 'primary retained count differs')
            group_ids = list(dict.fromkeys(row['QuestInfoId'] for row, _ in expected))
            require(get(group + 8, 4) == len(group_ids), 'retained group count differs')
            records = []
            for slot, (row, _) in enumerate(expected):
                at = get(primary) + slot * 200 + 8
                require(get(at) == address(0x1499f67f8) and get(at + 0x40) == int(row['Id'])
                        and get(at + 0x48) == int(row['QuestInfoId']), 'retained record key differs')
                require(get(at + 8) == 0 and get(at + 0x10, 4) == 0 and get(at + 0x14, 4) == 0
                        and get(at + 0x78) == 0 and get(at + 0x80) == 0,
                        'record constructor or unlocalized TaskName differs')
                for field, offset, size in (('TargetSpotInfoId', 0x58, 4), ('AreaInfoId', 0x68, 4),
                        ('AutoQuest', 0x88, 1), ('RunInInstance', 0x89, 1),
                        ('RemainInstanceWorldEndTask', 0x8a, 1), ('ShowInstanceEffect', 0x8b, 1),
                        ('Type', 0x8c, 1), ('MapIconGroupId', 0xa0, 4), ('TaskProgressType', 0xa4, 1)):
                    require(get(at + offset, size) == int(row[field] or '0'), 'retained scalar differs')
                require(fixture.wide_read(get(at + 0x90)).decode('utf-16le')
                        == row['Param'].replace('\r', ''), 'retained Param differs')
                for field, offset in (('QuestActionPosX', 0xa8), ('QuestActionPosY', 0xac),
                                       ('QuestActionPosZ', 0xb0), ('QuestActionRadius', 0xb4)):
                    require(bytes(uc.mem_read(at + offset, 4)) == struct.pack('<f', float(row[field] or '0')),
                            'retained coordinates differ')
                records.append((at, row))
            native_ids = [str(get(at + 0x40)) for at, _ in records]
            require(not set(native_ids) & set(TASK_IDS[6:] if region >= 5 else []), 'skipped ID was loaded')
            for slot, identifier in enumerate(group_ids):
                node = get(group) + slot * 32
                expected_records = [at for at, row in records if row['QuestInfoId'] == identifier]
                require(get(node) == int(identifier) and get(node + 16, 4) == len(expected_records)
                        and [get(get(node + 8) + i * 8) for i in range(len(expected_records))] == expected_records,
                        'native group-local pointer order differs')
            fixture.check_guards()
            immutable = [(manager, bytes(uc.mem_read(manager, 256)))]
            immutable.extend((at, bytes(uc.mem_read(at, size))) for at, size in fixture.blocks.items())
            projections = []
            indexes = {}
            for at, row in records:
                identifier = row['QuestInfoId']
                index = indexes.get(identifier, 0)
                indexes[identifier] = index + 1
                result, progress = base + 0x6000, base + 0x6100
                uc.mem_write(result - 16, b'A' * 16 + b'\xcc' * 32 + b'B' * 16)
                uc.mem_write(progress - 16, b'C' * 16 + bytes(32) + b'D' * 16)
                put(progress + 8, index, 1)
                put(progress + 0x10, COUNTERS[0])
                put(progress + 0x18, COUNTERS[1])
                before_progress = bytes(uc.mem_read(progress - 16, 64))
                uc.reg_write(x.UC_X86_REG_RDX, int(identifier))
                uc.reg_write(x.UC_X86_REG_R8, progress)
                require(h.call(address(0x145de4610), result) == result, 'projection return differs')
                output = bytes(uc.mem_read(result, 32)).hex()
                require(output == expected_projection(row['Id'], int(row['Type']), index)
                        and bytes(uc.mem_read(progress - 16, 64)) == before_progress
                        and bytes(uc.mem_read(result - 16, 16)) == b'A' * 16
                        and bytes(uc.mem_read(result + 32, 16)) == b'B' * 16,
                        'projection output, input or guard differs')
                require(all(bytes(uc.mem_read(pointer, len(data))) == data for pointer, data in immutable),
                        'projection mutated loaded records')
                projections.append(dict(task_id=row['Id'], quest_id=identifier, kind=int(row['Type']),
                                        index=index, progress_hex=output))
            require(all(bytes(uc.mem_read(at, len(raw))) == raw for at, raw in immutable_policy),
                    'service input changed during projection')
            fixture.check_guards()
            entries = {name: metrics['entry_counts'].get(name, 0) - before.get(name, 0) for name in POLICY_ROOTS}
            cases.append(dict(region=region, reverse=reverse, records=len(records), task_ids=native_ids,
                skipped_ids=TASK_IDS[6:] if region >= 5 else [], group_ids=group_ids,
                groups_match_native_records=True, missing_group_verified=region >= 5,
                inputs_unchanged=True, heap_guards_verified=True, policy_temporaries_released=True,
                policy_entries=entries, russian_override_calls=fixture.counts.get('override_fixture', 0),
                projections=projections, callbacks=dict(fixture.counts)))
    runtime['verify']()
    require(all(audit.sha256(pointer) == sha for pointer, sha in inputs.items()), 'input SHA changed')
    report = dict(source_sha256=SOURCE, tool_sha256=inputs[Path(__file__).resolve()],
        context_sha256=inputs[path.resolve()], exports=h.evidence, tables=context['tables'],
        dataset=dict(service_rows=services, server_row=servers[0], task_rows=[row for row, _ in rows],
                     maps_built_by='bounded_fixture_from_source_csv'),
        source_markers=fixture.source, cases=cases, metrics=metrics, system_runtime=runtime['system_runtime'],
        scalar_imports=runtime['imported'], native_execution=True, network_used=False, runtime_admitted=False,
        active_region_verified=False, active_task_verified=False, ordered_catalog_verified=False,
        action_admitted=False, order_admitted=False, table_loaders_executed=False,
        native_russian_override=False, limits=context['limits'])
    validate(report, context)
    artifact = audit.save_snapshot(h.root / 'code-clues/quest-mixed-current-native-v1', report)
    return artifact, report


if __name__ == '__main__':
    target, report = run()
    print(json.dumps(dict(artifact=str(target), cases=len(report['cases']),
                         abi_checks=report['metrics']['abi_checks']), ensure_ascii=False))
