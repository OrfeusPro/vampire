"""Bind current dialogue NPC movement fields to exact native code and named CSV.

This is a static source proof. It never opens a game connection or admits an action.
"""
import argparse
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import struct

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE/'knowledge/native-contexts/dialogue-move-current.json'
RECIPE = 'dialogue-move-current-v1'
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
TABLE = 'ProjectRED/Content/RED/Data/CSV/DialogSequence.csv'
ROLES = dict(producer='0x145d04450', writer='0x145836220', reader='0x14582ab90',
             selected_actor='0x14566c1f0', sequence_parser='0x145589410',
             vector_writer='0x144aad370', vector_reader='0x144aad030')
FALSE_FIELDS = ('native_execution', 'runtime_admitted', 'network_used', 'live_step_verified',
                'historical_client_source_verified', 'current_actor_keys_verified',
                'sequence_order_verified', 'ui_lifecycle_verified')
LIMITS = [
    'Whole exports and selected instruction/data bindings are checked against the exact current EXE; no native execution is claimed.',
    'The two wire layouts describe native archive field order. Archive providers, transport and a live request are not executed.',
    'DialogSequence row 1101111002001 targets NPC spawn 10011001. Static data does not select the current actor or prove playback order.',
    'The caller key, current NPC instance key, clock value, source branch and UI lifecycle are not supplied by this proof.',
    'Historical capture comparison is separate, private and optional; it cannot establish the source version or current runtime admission.',
]

# These field meanings are intentionally narrower than a runnable packet contract.
FIELDS = [
    dict(offset='0x10', wire='Q', source='return of selected_actor; registry actor type 6'),
    dict(offset='0x18', wire='Q', source='producer input RDX; caller key semantics unresolved'),
    dict(offset='0x20', wire='fff', source='position property; three doubles converted to float32'),
    dict(offset='0x38', wire='Q', source='R8 subject actor +0x648 virtual +0x20'),
    dict(offset='0x40', wire='f', source='rotateYaw when onMoveFinished, otherwise subject component yaw'),
    dict(offset='0x48', wire='Q', source='clock provider +0x10 multiplied by 0.0001, truncated to int64'),
    dict(offset='0x50', wire='B', source='producer fifth argument: movement completion flag'),
]
NPC_PARAM = dict(objectType='NPC', spawnInfoId=10011001, moveSpeed=110,
                 pos=dict(X=130818, Y=82540, Z=-10412),
                 moveFinished=dict(yaw=-100, withAnim=1, duration=1))
SEQUENCE_ROW_SHA = '1418efc63403fbc6167f2b2a1b86725a01e23f377bb93f725395e9173313db43'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE/(name+'.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def require(ok, why):
    if not ok:
        raise ValueError('Dialogue move: '+why)


def resource_row(raw):
    require(len(raw) <= 8*1024*1024, 'table budget exceeded')
    selected = [r for r in csv.DictReader(io.StringIO(raw.decode('utf-8-sig'), newline=''))
                if r.get('GroupId') in ('11011110010', '11011110020', '11011110030')]
    require(len(selected) == 2 and len({r['Id'] for r in selected}) == 2,
            'dialogue sequence membership differs')
    rows = {r['Id']: r for r in selected}
    require(set(rows) == {'1101111001001', '1101111002001'}, 'dialogue sequence IDs differ')
    camera, move = rows['1101111001001'], rows['1101111002001']
    require(camera['GroupId'] == '11011110010' and camera['Type'] == '8'
            and move['GroupId'] == '11011110020' and move['Type'] == '5'
            and all(r['DialogSequenceTiming'] == '0' and r['Delay'] == '' for r in selected),
            'dialogue sequence type or timing differs')
    param = json.loads(move['Param'], object_pairs_hook=strict_object)
    require(param == NPC_PARAM and all(type(v) is int for v in param['pos'].values())
            and type(param['spawnInfoId']) is int and type(param['moveSpeed']) is int
            and all(type(v) is int for v in param['moveFinished'].values()),
            'NPC sequence parameters differ')
    row_sha = hashlib.sha256(json.dumps(move, sort_keys=True,
        ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()
    require(row_sha == SEQUENCE_ROW_SHA, 'selected row identity differs')
    return dict(id=move['Id'], group_id=move['GroupId'], type=5, timing=0,
                param=param, row_sha256=row_sha)


def strict_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'duplicate parameter key')
        value[key] = item
    return value


def at(image, raw, address, size):
    offset = image.offset(address-image.pe.base)
    require(offset is not None and offset >= 0 and offset+size <= len(raw), 'source address outside image')
    return raw[offset:offset+size]


def source_bindings(image, raw, context):
    for address, expected in context['guards'].items():
        value = bytes.fromhex(expected)
        require(1 <= len(value) <= 256 and at(image, raw, int(address, 16), len(value)) == value,
                'source instruction binding differs: '+address)
    for address, text in context['literals'].items():
        value = (text+'\0').encode('utf-16le')
        require(at(image, raw, int(address, 16), len(value)) == value, 'script literal differs')
    for key, table, ctor, writer, reader, ident, getter, literal, name in (
        (1852, 0x149966f38, 0x145827cc0, 0x145836220, 0x14582aae0,
         0x145834390, 0x145834aa0, 0x149963db0, 'PktDialogMove'),
        (1853, 0x149966fb0, 0x145827cf0, 0x1458362e0, 0x14582ab90,
         0x1458343a0, 0x145834ad0, 0x149963dc0, 'PktDialogMoveResult')):
        slots = struct.unpack('<8Q', at(image, raw, table, 64))
        require((slots[2], slots[4], slots[5], slots[7]) == (writer, reader, ident, getter),
                'packet table binding differs')
        require(at(image, raw, ident, 6) == b'\xb8'+struct.pack('<I', key)+b'\xc3',
                'packet ID getter differs')
        constructor = at(image, raw, ctor, 7)
        require(constructor[:3] == b'\x48\x8d\x05'
                and ctor+7+struct.unpack('<i', constructor[3:])[0] == table,
                'constructor table differs')
        # Slot +0x38 constructs an FString; it is not a short LEA/RET getter.
        code = at(image, raw, getter+9, 7)
        require(code[:3] == b'\x48\x8d\x15'
                and getter+16+struct.unpack('<i', code[3:])[0] == literal
                and at(image, raw, literal, len(name)+1) == name.encode()+b'\0',
                'packet name getter differs')
    require(struct.unpack('<d', at(image, raw, 0x148a0b858, 8))[0] == 0.0001,
            'clock conversion differs')
    return wire_contract()


def wire_contract():
    return dict(request=dict(packet_id=1852, format='<QQfffQfQB', bytes=struct.calcsize('<QQfffQfQB')),
                response=dict(packet_id=1853, format='<IQQfffQfQB', bytes=struct.calcsize('<IQQfffQfQB')),
                fields=FIELDS, result_prefix=dict(offset='0x10', wire='I'),
                selected_actor_type=6, subject_kind='script_selected_actor',
                producer_send_branch='subject +0x6a0 is false or completion flag is true')


def whole_exports(index, root, context, raw):
    native = index.extension('build-native-entry-code')
    image = native.Image(raw)
    needed = set(ROLES.values())
    found = {}
    for run in context['exports']:
        export = json.loads((root/'ghidra/request-exports'/SOURCE/run/'details.json').read_bytes())
        require(export.get('new_source_sha256') == SOURCE, 'export source differs')
        for function in export['functions']:
            address = function['address'].lower()
            if address not in needed:
                continue
            require(address not in found, 'duplicate selected export')
            actual = index.extension('update-bindings').rows(native, image, int(address, 16))
            require(function.get('decompilation_completed') is True
                    and function.get('block_coverage_complete') is True
                    and function.get('direct_flow_coverage_complete') is True
                    and [(int(r['address'], 16), r['bytes'].lower()) for r in function['instructions']]
                        == [(r['address'], r['bytes'].lower()) for r in actual],
                    'whole export differs: '+address)
            found[address] = function
    require(set(found) == needed, 'selected exports incomplete')
    return image


def definition(index, root, context_path):
    common = load('verify-quest-loader-current')
    context_path = Path(context_path).resolve()
    context_raw = common.read_bounded(context_path, 128*1024)
    context = json.loads(context_raw)
    require(context.get('schema') == 1 and context.get('recipe') == RECIPE
            and context.get('source_sha256') == SOURCE and context.get('roles') == ROLES
            and context.get('table', {}).get('canonical_path') == TABLE
            and 1 <= len(context.get('exports', {})) <= 4
            and 30 <= len(context.get('guards', {})) <= 128
            and 10 <= len(context.get('literals', {})) <= 30, 'context scope differs')
    source = root/'client-code-snapshots'/SOURCE/'ProjectRED-Win64-Shipping.exe'
    inputs = {str(source): SOURCE, str(context_path): hashlib.sha256(context_raw).hexdigest()}
    for name in ('verify-dialogue-move-current', 'verify-quest-loader-current', 'knowledge-index',
                 'build-native-entry-code', 'extract-native-enums', 'update-bindings',
                 'audit-client-release', 'research-workflow', 'native-publication-v2'):
        path = HERE/(name+'.py')
        inputs[str(path.resolve())] = common.digest(path)
    for run, expected in context['exports'].items():
        require(re.fullmatch('run-[0-9a-f]+', run) and common.SHA.fullmatch(str(expected)),
                'export pointer differs')
        inputs[str(root/'ghidra/request-exports'/SOURCE/run/'details.json')] = expected
    baseline = common.document(context['named_baseline'], root, 'knowledge/resource-named-baselines-v1')
    require(baseline.get('recipe') == 'named-table-baselines-v1'
            and baseline['source']['sha256'] == context['archive_sha256'], 'named archive differs')
    archive = (Path(index.INSTALL).resolve().parents[2]
               /'Saved/PersistentDownloadDir/Patch/Install/pakchunk1-Windows.pak').resolve()
    require(Path(baseline['source']['archive_key']).resolve() == archive, 'named archive path differs')
    pointer = context['table']
    blob = root/'knowledge/resource-csv-blobs-v3'/(pointer['sha256']+'.csv')
    matches = [r for r in baseline['tables'] if r.get('canonical_path') == TABLE]
    require(common.SHA.fullmatch(pointer['sha256']) and len(matches) == 1
            and matches[0]['state'] == 'verified_payload' and matches[0]['sha256'] == pointer['sha256']
            and Path(matches[0]['file']).resolve() == blob, 'named table identity differs')
    inputs.update({str(archive): context['archive_sha256'], str(blob): pointer['sha256'],
                   str(Path(context['named_baseline']['path']).resolve()): context['named_baseline']['sha256']})
    runtime = {str(path): common.digest(path)
               for path in index.extension('native-publication-v2').runtime_files()}
    require(bool(runtime), 'decoder runtime identity missing')
    inputs.update(runtime)
    return context, dict(source_sha256=SOURCE, inputs=inputs, runtime_inputs=runtime, source=dict(path=str(archive),
        sha256=context['archive_sha256']), table=dict(path=str(blob), sha256=pointer['sha256']))


def validate(report, selected):
    require(report.get('schema') == 1 and report.get('recipe') == RECIPE
            and report.get('source_sha256') == SOURCE and report.get('definition') == selected
            and report.get('limits') == LIMITS and report.get('whole_exports_verified') == len(ROLES)
            and all(report.get(key) is False for key in FALSE_FIELDS), 'receipt scope differs')
    require(report.get('result') == dict(wire=wire_contract(), sequence=dict(
                id='1101111002001', group_id='11011110020', type=5, timing=0,
                row_sha256=SEQUENCE_ROW_SHA, param=NPC_PARAM)),
            'field or sequence proof differs')


def verify(*, root=ROOT, context_path=CONTEXT):
    root = Path(root).resolve()
    index = load('knowledge-index').api()
    common = load('verify-quest-loader-current')
    workflow = index.extension('research-workflow')
    context, selected = definition(index, root, context_path)
    key = hashlib.sha256(workflow.canonical(selected)).hexdigest()
    cache = root/'knowledge'/(RECIPE+'-cache')/(key+'.json')
    common.barrier(selected['inputs'])
    if cache.is_file():
        pointer = json.loads(common.read_bounded(cache, 8192))
        report = common.document(pointer, root, 'code-clues/'+RECIPE)
        validate(report, selected)
        common.barrier(selected['inputs'])
        return dict(pointer, report=pointer['path'], reused=True)
    raw = (root/'client-code-snapshots'/SOURCE/'ProjectRED-Win64-Shipping.exe').read_bytes()
    image = whole_exports(index, root, context, raw)
    result = dict(wire=source_bindings(image, raw, context),
                  sequence=resource_row(Path(selected['table']['path']).read_bytes()))
    report = dict(schema=1, recipe=RECIPE, source_sha256=SOURCE, definition=selected, result=result,
                  whole_exports_verified=len(ROLES), limits=LIMITS, **dict.fromkeys(FALSE_FIELDS, False))
    validate(report, selected)
    common.barrier(selected['inputs'])
    path = index.extension('audit-client-release').save_snapshot(root/'code-clues'/RECIPE, report)
    pointer = dict(path=str(path), sha256=common.digest(path))
    workflow.atomic(cache, workflow.canonical(pointer))
    return dict(pointer, report=str(path), reused=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    print(json.dumps(verify(root=args.root)))
