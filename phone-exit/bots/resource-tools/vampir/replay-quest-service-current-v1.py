"""Current service policy over fixture maps populated from SHA-bound CSV rows."""
import csv
import ctypes
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
ROOTS = ['0x145a4d700', '0x145bff820', '0x145c03670', '0x145bff6a0', '0x145bfefd0']
DATASET_SHA256 = 'f0e8624ddf49ff90e9f4aaad10c33fd133046bc094ca53d78a94da0277f2af72'
ENTRIES = {'0x141404b20': 46, '0x141429f90': 24, '0x141432370': 46,
    '0x141436f30': 88, '0x14145f240': 88, '0x1414830e0': 120,
    '0x1445f1630': 24, '0x1445f6010': 24, '0x145a4d700': 24,
    '0x145bfefd0': 20, '0x145bff6a0': 20, '0x145bff820': 24,
    '0x145c03670': 24, '0x1487f8c99': 88, '0x28007000': 24}
SERVICE_MANAGER = 0x14b1ca960
SERVER_MANAGER = 0x14b1ca720
BRANCHES = (0x145c03778, 0x145c038bb, 0x145c0395e, 0x145c0394b,
            0x145bff050, 0x145bff08e)
SOURCE_BYTES = {
    '0x145b5fab7': 'e844dceeff',
    '0x145b5fabc': '84c0',
    '0x145b5fabe': '0f8558040000',
    '0x145c08305': '894608',
    '0x145c08321': '89460c',
    '0x145c0833d': '894610',
    '0x145c08359': '894614',
    '0x145c08440': '488d5e18',
    '0x145c08582': '488d5e28',
    '0x145c0698c': '894328',
    '0x145c08087': '488d052a389103',
    '0x145c08098': '488d0559ccdf03',
    '0x145c080a6': '488d05fbc8e003',
    '0x145c080b4': '488d054536dd03',
    '0x145c080c2': '488d05efc8e003',
    '0x145c080d0': '488d05f1c8e003',
    '0x145c066e7': '488d05b2d4e003',
}
STATIC_PADDING = {'0x145c08278': '0f1f840000000000'}
COLUMNS = {
    '0x14951b8b8': 'GroupId',
    '0x149a04cf8': 'RegionType',
    '0x149a149a8': 'MinServicePhase',
    '0x1499db700': 'MaxServicePhase',
    '0x149a149b8': 'ExcludeServerId',
    '0x149a149c8': 'IncludeServerId',
    '0x149a13ba0': 'ServicePhase',
}


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def scenarios():
    rows = [dict(name='group10000-region'+str(region), group=10000, region=region,
                 server=387, expected_skip=int(region >= 5), decision='phase')
            for region in range(8)]
    rows.extend([
        dict(name='include-listed', group=7000, region=1, server=140,
             expected_skip=0, decision='include'),
        dict(name='exclude-listed', group=8000, region=1, server=140,
             expected_skip=1, decision='exclude'),
        dict(name='include-nonmatching-phase', group=7000, region=1, server=387,
             expected_skip=1, decision='phase'),
        dict(name='exclude-nonmatching-phase', group=8000, region=1, server=387,
             expected_skip=0, decision='phase'),
    ])
    return [dict(row, external_buckets=external) for external in (False, True) for row in rows]


def source_markers(h):
    native, bindings = load('build-native-entry-code'), load('update-bindings')
    static_roots = {'0x145b5f680', '0x145c07f00', '0x145c06500'}
    exported_instructions = {}
    selected = set()
    for pointer in h.evidence:
        raw = Path(pointer['path']).read_bytes()
        if hashlib.sha256(raw).hexdigest() != pointer['sha256']:
            raise ValueError('Current service static export SHA changed')
        report = json.loads(raw)
        for function in report['functions']:
            if function['address'] not in static_roots:
                continue
            if (function['address'] in selected or function.get('decompilation_completed') is not True
                    or function.get('block_coverage_complete') is not True
                    or function.get('direct_flow_coverage_complete') is not True):
                raise ValueError('Current service static loader coverage differs')
            whole = bindings.rows(native, h.image, int(function['address'], 16))
            actual = [(int(row['address'], 16), row['bytes']) for row in function['instructions']]
            expected_rows = [(row['address'], row['bytes']) for row in whole
                             if hex(row['address']) not in STATIC_PADDING]
            omitted = {hex(row['address']): row['bytes'] for row in whole
                       if hex(row['address']) in STATIC_PADDING}
            if (actual != expected_rows or any(STATIC_PADDING[address] != value
                                              for address, value in omitted.items())):
                raise ValueError('Current service static loader is not whole source code')
            for row in whole:
                if hex(row['address']) in omitted and (row['mnemonic'] != 'nop' or any(
                        item['direct_target'] == row['address'] for item in whole)):
                    raise ValueError('Current service omitted static row is not alignment padding')
            selected.add(function['address'])
            exported_instructions.update({row['address']: row['bytes'] for row in function['instructions']})
    if selected != static_roots:
        raise ValueError('Current service static loader export missing')
    for address, expected in SOURCE_BYTES.items():
        offset = h.image.offset(int(address, 16)-h.image.pe.base)
        if (h.raw[offset:offset+len(bytes.fromhex(expected))].hex() != expected
                or exported_instructions.get(address) != expected):
            raise ValueError('Service loader/source marker changed '+address)
    for address, text in COLUMNS.items():
        offset = h.image.offset(int(address, 16)-h.image.pe.base)
        if h.raw[offset:offset+len(text)+1] != (text+'\0').encode('ascii'):
            raise ValueError('Service column literal changed '+address)
    return dict(instructions=SOURCE_BYTES, columns=COLUMNS, static_padding=STATIC_PADDING,
                quest_gate='0x145a4d700', skip_destination='0x145b5ff1c',
                service_record_layout=dict(GroupId=8, RegionType=12, MinServicePhase=16,
                    MaxServicePhase=20, ExcludeServerId=24, IncludeServerId=40),
                server_phase_offset=40, table_loaders_executed=False)


def parse_tables(common, root, context):
    tables = {}
    payloads = {}
    for name, pointer in context['tables'].items():
        raw = common.checked_blob(root, pointer)
        reader = csv.DictReader(io.StringIO(raw.decode('utf-8-sig'), newline=''))
        tables[name] = list(reader)
        payloads[Path(pointer['path']).resolve()] = hashlib.sha256(raw).hexdigest()
    tasks, servers, services = [tables[name] for name in
                                ('quest_task', 'server_group', 'server_service_group')]
    groups = {row['ServerServiceGroupId'] for row in tasks if row['ServerServiceGroupId']}
    if len(tasks) != 5944 or groups != {'10000'}:
        raise ValueError('Current QuestTask service coverage changed')
    nonempty = sum(bool(row['ServerServiceGroupId']) for row in tasks)
    if nonempty != 1627:
        raise ValueError('Current nonempty QuestTask rows changed')
    selected_services = [dict(csv_record=i, row=row) for i, row in enumerate(services, 2)
                         if row['GroupId'] in ('7000', '8000', '10000')]
    if len(selected_services) != 24 or any(
            {int(item['row']['RegionType']) for item in selected_services
             if int(item['row']['GroupId']) == group} != set(range(8))
            for group in (7000, 8000, 10000)):
        raise ValueError('Selected service groups changed')
    selected_servers = []
    for identifier in (391, 387, 140):
        matches = [dict(csv_record=i, row=row) for i, row in enumerate(servers, 2)
                   if int(row['Id']) == identifier]
        if len(matches) != 1 or matches[0]['row']['ServicePhase'] != '10000':
            raise ValueError('Selected server must have one source row and phase10000')
        selected_servers.extend(matches)
    source_cell = next(row for row in tasks if row['Id'] == '200110010')
    if source_cell['ServerServiceGroupId'] != '10000':
        raise ValueError('Nonempty source QuestTask cell changed')
    dataset = dict(table_rows={name: len(rows) for name, rows in tables.items()},
        nonempty_quest_tasks=nonempty, empty_quest_tasks=len(tasks)-nonempty,
        nonempty_groups=[10000], source_quest_cell=dict(task_id=source_cell['Id'],
            value=source_cell['ServerServiceGroupId']), service_rows=selected_services,
        server_rows=selected_servers, maps_built_by='bounded_fixture_from_source_csv')
    return dataset, payloads


def validate(report, context=None):
    flags = dict(source_sha256=SOURCE, native_execution=True, network_used=False,
                 runtime_admitted=False, active_region_verified=False,
                 active_task_verified=False, ordered_catalog_verified=False,
                 action_admitted=False, order_admitted=False, table_loaders_executed=False)
    if not isinstance(report, dict) or any(report.get(key) != value
            or (type(value) is bool and type(report.get(key)) is not bool) for key, value in flags.items()):
        raise ValueError('Current service proof scope differs')
    cases = report.get('cases', [])
    expected = scenarios()
    if len(cases) != len(expected):
        raise ValueError('Current service case matrix differs')
    for case, scenario in zip(cases, expected):
        if (case.get('scenario') != scenario or case.get('skip') != scenario['expected_skip']
                or type(case.get('skip')) is not int
                or type(case.get('scenario', {}).get('external_buckets')) is not bool):
            raise ValueError('Current service case/outcome differs')
        phase = int(scenario['decision'] == 'phase')
        roots = {key: 1 for key in ('0x145a4d700', '0x145bff820', '0x145c03670',
                                  '0x1445f6010', '0x1445f1630')}
        roots.update({'0x145bff6a0': phase, '0x145bfefd0': phase})
        if case.get('native_entries') != roots or case.get('crt_calls') != ['atoi']:
            raise ValueError('Current service native entry coverage differs')
        branches = {hex(address): 0 for address in BRANCHES}
        branches['0x145c03778'] = 1
        branches['0x145c038bb'] = int(scenario['decision'] == 'exclude')
        branches['0x145c0395e'] = int(scenario['decision'] == 'include')
        branches['0x145c0394b'] = phase
        branches['0x145bff050'] = 2*phase
        branches['0x145bff08e'] = phase
        if case.get('branches') != branches or case.get('allocations_remaining') != 0:
            raise ValueError('Current service branch/ownership coverage differs')
        callbacks = dict(destroy_array=2, free=1, identifier_string=1, split=2)
        if scenario['group'] in (7000, 8000):
            iterations = 10 if scenario['server'] == 140 else 12
            callbacks.update(compare=iterations, copy=iterations, resize=iterations, free=iterations+2)
        if scenario['decision'] == 'exclude':
            callbacks.update(destroy_array=1, split=1)
        if case.get('callbacks') != callbacks:
            raise ValueError('Current service fixture callback coverage differs')
        if case.get('service_phase') != 10000 or case.get('source_service_region') != scenario['region']:
            raise ValueError('Current service source row binding differs')
    dataset = report.get('dataset', {})
    dataset_hash = hashlib.sha256(json.dumps(dataset, sort_keys=True, separators=(',', ':'),
                                            ensure_ascii=False).encode('utf-8')).hexdigest()
    if (dataset.get('table_rows') != dict(quest_task=5944, server_group=425, server_service_group=128)
            or dataset.get('nonempty_quest_tasks') != 1627 or dataset.get('empty_quest_tasks') != 4317
            or dataset.get('nonempty_groups') != [10000]
            or dataset.get('source_quest_cell') != dict(task_id='200110010', value='10000')
            or len(dataset.get('service_rows', [])) != 24 or len(dataset.get('server_rows', [])) != 3
            or dataset.get('maps_built_by') != 'bounded_fixture_from_source_csv'
            or dataset_hash != DATASET_SHA256):
        raise ValueError('Current service source dataset coverage differs')
    markers = report.get('source_markers', {})
    if (markers.get('instructions') != SOURCE_BYTES or markers.get('columns') != COLUMNS
            or markers.get('static_padding') != STATIC_PADDING
            or markers.get('quest_gate') != '0x145a4d700'
            or markers.get('skip_destination') != '0x145b5ff1c'
            or markers.get('service_record_layout') != dict(GroupId=8, RegionType=12,
                MinServicePhase=16, MaxServicePhase=20, ExcludeServerId=24, IncludeServerId=40)
            or markers.get('server_phase_offset') != 40
            or markers.get('table_loaders_executed') is not False):
        raise ValueError('Current service loader edge/layout markers differ')
    metrics = report.get('metrics', {})
    if (metrics.get('abi_checks') != 24 or metrics.get('call_counts') != 24
            or metrics.get('entry_counts') != ENTRIES or metrics.get('fixture_calls') != 524):
        raise ValueError('Current service ABI coverage differs')
    for root in ROOTS:
        wanted = 20 if root in ('0x145bff6a0', '0x145bfefd0') else 24
        if metrics.get('entry_counts', {}).get(root) != wanted:
            raise ValueError('Current service whole function coverage differs')
    if context is not None and (context['source_sha256'] != SOURCE
            or context['functions'] != ROOTS or report.get('limits') != context['limits']
            or report.get('tables') != context['tables']):
        raise ValueError('Current service result/context binding differs')


def run(context_path=None, *, root=None):
    common = load('replay-quest-loader-current-v1')
    audit = load('audit-client-release')
    path = Path(context_path) if context_path else HERE/'knowledge/native-contexts/quest-service-current.json'
    context_raw = path.read_bytes()
    context = json.loads(context_raw)
    if (context.get('schema') != 1 or context.get('recipe') != 'quest-service-current-v1'
            or context.get('functions') != ROOTS):
        raise ValueError('Current service context differs')
    h = load('native-request-harness-11316').make_harness(context['exports'],
        {int(address, 16) for address in context['functions']},
        leaves={int(address, 16): value for address, value in context['leaves'].items()},
        root=root, source_sha256=context['source_sha256'], copy_thunk=None)
    metrics = common.install_guards(h, context)
    markers = source_markers(h)
    dataset, inputs = parse_tables(common, h.root, context)
    inputs[path.resolve()] = hashlib.sha256(context_raw).hexdigest()
    inputs[Path(__file__).resolve()] = audit.sha256(Path(__file__))
    inputs[h.source] = SOURCE
    for item in h.evidence:
        inputs[Path(item['path'])] = item['sha256']
    uc, x, base = h.uc, h.x, h.scratch
    current = {}
    blocks = {}
    cursor = [base+0x18000]
    branches = {}
    callbacks = {}
    row, cells, gate = [base+n for n in (0x1000, 0x2000, 0x3000)]
    service_nodes, service_slots, service_records = [base+n for n in (0x4000, 0x4100, 0x5000)]
    server_nodes, server_records = [base+n for n in (0x6000, 0x6100)]
    cell_atoi = base+0x7000

    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_'+name))

    def put(address, value, size=8):
        uc.mem_write(address, (int(value) % (1 << (size*8))).to_bytes(size, 'little'))

    def get(address, size=8):
        return int.from_bytes(uc.mem_read(address, size), 'little')

    def count(name):
        callbacks[name] = callbacks.get(name, 0)+1

    def allocate(data):
        address = cursor[0]+16
        cursor[0] = address+((len(data)+15)&~15)+16
        if not 0 < len(data) <= 1024 or cursor[0] >= base+0x32000:
            raise ValueError('Current service allocation budget')
        uc.mem_write(address-16, b'L'*16+data+b'R'*16)
        blocks[address] = len(data)
        return address

    def release(address):
        size = blocks.pop(address, None)
        if size is None or bytes(uc.mem_read(address-16, 16)) != b'L'*16 or bytes(uc.mem_read(address+size, 16)) != b'R'*16:
            raise ValueError('Current service ownership/heap guards differ')

    def wide(address):
        for size in range(64):
            if bytes(uc.mem_read(address+size*2, 2)) == b'\0\0':
                return bytes(uc.mem_read(address, size*2)).decode('utf-16le')
        raise ValueError('Current service string budget')

    def assign(address, text):
        data = text.encode('utf-16le')+b'\0\0'
        put(address, allocate(data))
        put(address+8, len(data)//2, 4)
        put(address+12, len(data)//2, 4)

    def identifier_string(machine):
        if reg('RDX') != current['server']:
            raise ValueError('Current service identifier conversion input differs')
        assign(reg('RCX'), str(current['server']))
        count('identifier_string')
        h.finish(reg('RCX'))

    def split(machine):
        address, destination = reg('RCX'), reg('RDX')
        if address not in current['list_fields'] or reg('R9') != 1 or reg('R8') != 0x1489f4900:
            raise ValueError('Current service list split source differs')
        values = current['list_fields'][address]
        if len(values) > 12:
            raise ValueError('Current service source list budget')
        uc.mem_write(destination, bytes(16))
        if values:
            array = allocate(bytes(16*len(values)))
            for index, text in enumerate(values):
                assign(array+index*16, text)
            put(destination, array)
            put(destination+8, len(values), 4)
            put(destination+12, len(values), 4)
        count('split')
        h.finish(destination)

    def resize(machine):
        address, length = reg('RCX'), reg('RDX')
        if not 0 < length <= 64 or reg('R8') != 0:
            raise ValueError('Current service temporary string length differs')
        put(address, allocate(bytes(length*2)))
        put(address+12, length, 4)
        count('resize')
        h.finish()

    def copy(machine):
        target, source, length = reg('RCX'), reg('RDX'), reg('R8')
        if length > 128 or target not in blocks or source not in blocks:
            raise ValueError('Current service string copy outside owned storage')
        if length > blocks[target] or length > blocks[source]:
            raise ValueError('Current service string copy length differs')
        uc.mem_write(target, bytes(uc.mem_read(source, length)))
        count('copy')
        h.finish(target)

    def compare(machine):
        count('compare')
        h.finish(0 if wide(reg('RCX')) == wide(reg('RDX')) else 1)

    def destroy_array(machine):
        address, length = reg('RCX'), reg('RDX')
        if length > 12 or (length and address not in blocks):
            raise ValueError('Current service array cleanup scope differs')
        for index in range(length):
            release(get(address+index*16))
        count('destroy_array')
        h.finish()

    def free(machine):
        release(reg('RCX'))
        count('free')
        h.finish()

    for address, callback in ((0x141429f90, identifier_string), (0x141432370, split),
            (0x141436f30, resize), (0x1487f8c99, copy), (0x14145f240, compare),
            (0x141404b20, destroy_array), (0x1414830e0, free)):
        h.add_fixture(address, callback)
    directory = ctypes.create_unicode_buffer(32768)
    if not 0 < ctypes.WinDLL('kernel32', use_last_error=True).GetSystemDirectoryW(directory, len(directory)) < len(directory):
        raise ValueError('Current service system CRT directory unavailable')
    crt_path = Path(directory.value)/'ucrtbase.dll'
    crt_sha = audit.sha256(crt_path)
    crt = ctypes.CDLL(str(crt_path))
    crt.atoi.argtypes, crt.atoi.restype = [ctypes.c_char_p], ctypes.c_int
    crt.setlocale.argtypes, crt.setlocale.restype = [ctypes.c_int, ctypes.c_char_p], ctypes.c_char_p
    locale = crt.setlocale(0, None)
    crt_calls = []
    imported = load('build-object-zero-init-code').import_at(h.raw, h.image, 0x14899ebf8)
    if (imported['dll'].lower(), imported['name']) != ('api-ms-win-crt-convert-l1-1-0.dll', 'atoi'):
        raise ValueError('Current service numeric import differs')

    def number(machine):
        if reg('RCX') != cells:
            raise ValueError('Current service numeric cell pointer differs')
        data = bytes(uc.mem_read(cells, 16)).split(b'\0', 1)[0]
        if data != str(current['group']).encode('ascii'):
            raise ValueError('Current service numeric cell data differs')
        crt_calls.append('atoi')
        h.finish(crt.atoi(data)&0xffffffff)

    h.add_fixture(cell_atoi, number)
    put(0x14899ebf8, cell_atoi)
    tls = 0x29000000
    uc.mem_map(tls, 0x110000)
    uc.reg_write(x.UC_X86_REG_GS_BASE, tls)
    put(tls+0x58, tls+0x1000)
    put(tls+0x1000, tls+0x2000)
    put(tls+0x2000+0x101184, 0, 4)
    for address in (0x14b6a7d00, 0x14b5f37c8, 0x14b5f3784, 0x14b5f3790):
        put(address, 0, 4)
    put(0x14b5f3788, 0)
    import unicorn

    def observe(machine, address, size, unused):
        if address in BRANCHES:
            branches[hex(address)] = branches.get(hex(address), 0)+1

    uc.hook_add(unicorn.UC_HOOK_CODE, observe)
    cases = []
    for scenario in scenarios():
        current.clear()
        current.update(scenario, list_fields={})
        blocks.clear()
        cursor[0] = base+0x18000
        branches.clear()
        callbacks.clear()
        crt_calls.clear()
        uc.mem_write(SERVICE_MANAGER, bytes(0x88))
        uc.mem_write(SERVER_MANAGER, bytes(0x110))
        uc.mem_write(base+0x1000, bytes(0xe000))
        put(SERVICE_MANAGER+0x28, service_nodes)
        put(SERVICE_MANAGER+0x30, 3, 4)
        put(SERVICE_MANAGER+0x70, 2, 4)
        put(SERVICE_MANAGER+0x60, 0, 4)
        put(SERVICE_MANAGER+0x64, -1, 4)
        put(SERVICE_MANAGER+0x78, scenario['region'], 4)
        put(SERVICE_MANAGER+0x7c, scenario['server'], 4)
        for index, group in enumerate((7000, 8000, 10000)):
            node = service_nodes+index*32
            put(node, group, 4)
            put(node+8, service_slots+index*64)
            put(node+16, 8, 4)
            put(node+24, index+1 if index < 2 else -1, 4)
            entries = [item for item in dataset['service_rows'] if int(item['row']['GroupId']) == group]
            for position, item in enumerate(entries):
                source = item['row']
                record = service_records+(index*8+position)*64
                put(service_slots+index*64+position*8, record)
                for column, offset in (('GroupId', 8), ('RegionType', 12), ('MinServicePhase', 16), ('MaxServicePhase', 20)):
                    put(record+offset, int(source[column]), 4)
                for column, offset in (('ExcludeServerId', 24), ('IncludeServerId', 40)):
                    current['list_fields'][record+offset] = source[column].split(',') if source[column] else []
        put(SERVER_MANAGER+0xc0, server_nodes)
        put(SERVER_MANAGER+0xc8, 3, 4)
        put(SERVER_MANAGER+0x108, 2, 4)
        put(SERVER_MANAGER+0xf8, 2, 4)
        put(SERVER_MANAGER+0xfc, 0, 4)
        for index, item in enumerate(dataset['server_rows']):
            source = item['row']
            node, record = server_nodes+index*24, server_records+index*48
            put(node, int(source['Id']), 4)
            put(node+8, record)
            put(node+16, 1 if index == 0 else -1, 4)
            put(record+0x28, int(source['ServicePhase']), 4)
        if scenario['external_buckets']:
            put(SERVICE_MANAGER+0x68, base+0xa000)
            put(base+0xa000, 0, 4)
            put(base+0xa004, -1, 4)
            put(SERVER_MANAGER+0x100, base+0xa010)
            put(base+0xa010, 2, 4)
            put(base+0xa014, 0, 4)
        put(row+0x20, 1, 4)
        put(row+0x28, cells)
        text = str(scenario['group']).encode('ascii')
        uc.mem_write(cells, text+b'\0')
        put(cells+16, len(text))
        put(cells+24, 15)
        put(gate+8, 0, 2)
        immutable = [(address, bytes(uc.mem_read(address, size))) for address, size in
            ((SERVICE_MANAGER, 0x88), (SERVER_MANAGER, 0x110), (base+0x1000, 0xe000),
             (tls, 0x110000), (0x14b5f3784, 16), (0x14b5f37c8, 4))]
        before = dict(metrics['entry_counts'])
        uc.reg_write(x.UC_X86_REG_RDX, row)
        skip = h.call(0x145a4d700, gate)&255
        if skip != scenario['expected_skip']:
            raise ValueError('Current service policy outcome differs '+str((scenario, skip)))
        if blocks or any(bytes(uc.mem_read(address, len(data))) != data for address, data in immutable):
            raise ValueError('Current service input changed or temporary allocation leaked')
        entries = {address: metrics['entry_counts'].get(address, 0)-before.get(address, 0)
                   for address in ROOTS+list(context['leaves'])}
        cases.append(dict(scenario=scenario, skip=skip, native_entries=entries,
            branches={hex(address): branches.get(hex(address), 0) for address in BRANCHES},
            crt_calls=crt_calls.copy(), callbacks=callbacks.copy(), allocations_remaining=len(blocks),
            source_service_region=scenario['region'], service_phase=10000))
    if audit.sha256(crt_path) != crt_sha or crt.setlocale(0, None) != locale:
        raise ValueError('Current service CRT changed during execution')
    if any(audit.sha256(name) != expected for name, expected in inputs.items()):
        raise ValueError('Current service input SHA changed during execution')
    report = dict(source_sha256=SOURCE, tool_sha256=inputs[Path(__file__).resolve()],
        context_sha256=inputs[path.resolve()], exports=h.evidence, tables=context['tables'],
        source_markers=markers, dataset=dataset, cases=cases, metrics=metrics, imported=imported,
        system_runtime=dict(path=str(crt_path), sha256=crt_sha, locale=locale.decode()),
        native_execution=True, network_used=False, runtime_admitted=False, active_region_verified=False,
        active_task_verified=False, ordered_catalog_verified=False, action_admitted=False,
        order_admitted=False, table_loaders_executed=False, limits=context['limits'])
    validate(report, context)
    target = audit.save_snapshot(h.root/'code-clues/quest-service-current-native-v1', report)
    return target, report


if __name__ == '__main__':
    target, report = run()
    print(json.dumps(dict(artifact=str(target), cases=len(report['cases']),
                          abi_checks=report['metrics']['abi_checks']), ensure_ascii=False))
