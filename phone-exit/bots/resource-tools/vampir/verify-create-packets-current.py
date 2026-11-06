"""Current Create writers and Result outer reader; explicit archive/record fixtures."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
SHA = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
RECIPE = 'create-packets-current-v1'
CONTEXT = HERE / 'knowledge/native-contexts/create-packets-current.json'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def materials(root=ROOT, context_path=CONTEXT):
    root, context_path = Path(root).resolve(), Path(context_path).resolve()
    context = json.loads(context_path.read_bytes())
    expected_roles = dict(request_constructor='0x1456d6e70', request_writer='0x1456ba520',
        data_writer='0x14578d210', appearance_writer='0x14578cec0',
        result_constructor='0x1456d6ea0', result_reader='0x1456b7780')
    if (context.get('schema') != 1 or context.get('recipe') != RECIPE
            or context.get('source_sha256') != SHA or context.get('functions') != expected_roles
            or context.get('runtime_admitted') is not False):
        raise ValueError('Current Create context/source/roles changed')
    source = root / 'client-code-snapshots' / SHA / 'ProjectRED-Win64-Shipping.exe'
    if digest(source) != SHA:
        raise ValueError('Current Create source changed')
    names = ('verify-create-packets-current.py', 'native-request-harness-11316.py',
             'build-native-entry-code.py', 'build-object-zero-init-code.py',
             'audit-launcher-shape-11318.py', 'verify-character-list-current.py',
             'audit-client-release.py', 'research-workflow.py', 'update-native-harness.py')
    inputs = {str((HERE / name).resolve()): digest(HERE / name) for name in names}
    inputs[str(context_path)] = digest(context_path)
    inputs[str(source)] = SHA
    for run, expected in context['exports'].items():
        path = root / 'ghidra/request-exports' / SHA / run / 'details.json'
        if digest(path) != expected or json.loads(path.read_bytes())['new_source_sha256'] != SHA:
            raise ValueError('Current Create export changed')
        inputs[str(path)] = expected
    pointer = context['record_proof']
    if digest(pointer['path']) != pointer['sha256']:
        raise ValueError('Current Create nested record proof changed')
    proof = load('verify-character-list-current').verify_report(pointer['path'], root=root, workspace=HERE.parents[3])
    if proof['source_sha256'] != SHA:
        raise ValueError('Current Create nested record source differs')
    inputs.update(proof['definition']['inputs'])
    inputs.update(proof['definition']['files'])
    generated_pointer = proof['definition']['generated']
    generated = json.loads(Path(generated_pointer['path']).read_bytes())
    for item in (pointer, generated_pointer, generated['scope']):
        if digest(item['path']) != item['sha256']:
            raise ValueError('Current Create retained record output changed')
        inputs[str(Path(item['path']).resolve())] = item['sha256']
    runtime = load('update-native-harness').runtime_inputs()
    return context, dict(source_sha256=SHA, inputs=inputs, runtime=runtime)


def static_contract(context, image):
    def data(at, size):
        offset = image.offset(at - image.pe.base)
        return image.data[offset:offset + size]
    for at, encoded in {**context['tables'], **context['leaves'], **context['identity_leaves']}.items():
        if data(int(at, 16), len(bytes.fromhex(encoded))).hex() != encoded:
            raise ValueError('Current Create source table/leaf changed')
    for table, slot, target in ((0x14992afa8, 0x10, 0x1456ba520), (0x14992b068, 0x20, 0x1456b7780),
            (0x14992af60, 0x10, 0x14578d210), (0x149922b50, 0x10, 0x14578cec0),
            (0x149922b08, 0x10, 0x14578b8f0), (0x14992b020, 0x20, 0x1457888c0),
            (0x149dc9588, 0x10, 0x1467984c0), (0x14992b7f8, 0x10, 0x1456e8430),
            (0x14992bc40, 0x20, 0x1456f02c0)):
        if struct.unpack('<Q', data(table + slot, 8))[0] != target:
            raise ValueError('Current Create/selection role binding changed')
    for table, packet_id, name in ((0x14992afa8, 103, 'PktCharacterCreate'),
            (0x14992b068, 104, 'PktCharacterCreateResult'), (0x14992b7f8, 109, 'PktCharacterSelect'),
            (0x14992bc40, 110, 'PktCharacterSelectResult')):
        getter = struct.unpack('<Q', data(table + 0x28, 8))[0]
        if data(getter, 6) != b'\xb8' + struct.pack('<I', packet_id) + b'\xc3':
            raise ValueError('Current Create/selection ID getter changed')
        if data(table + 0x50, len(name) + 1) != name.encode() + b'\0':
            raise ValueError('Current Create/selection compiled name changed')
    registration = context['registration']
    if (registration['address'] != '0x1467b86ed' or registration['owner'] != '0x1467b8040'
            or registration['handler'] != '0x1467984c0' or registration['constructor'] != '0x1456d6ea0'
            or data(0x1467b86ed, 0x39).hex() != registration['bytes']):
        raise ValueError('Current Create result factory registration changed')
    return dict(packet_ids=[103, 104, 109, 110], nested_record_reader='0x1457888c0',
                result_handler='0x1467984c0', registration=registration)


def execute(context, *, root=ROOT):
    roles = {name: int(at, 16) for name, at in context['functions'].items()}
    h = load('native-request-harness-11316').make_harness(context['exports'], set(roles.values()),
        leaves={int(at, 16): code for at, code in context['leaves'].items()},
        source_sha256=SHA, copy_thunk=None, root=root)
    native = load('build-native-entry-code')
    whole = load('audit-launcher-shape-11318')
    for function in h.fragments:
        whole.normalize_function(native, h.image, function)
    bindings = static_contract(context, h.image)
    uc, x = h.uc, h.x
    packet, archive, table, items, string_a, string_b = [h.scratch + at for at in
        (0x10000, 0x11000, 0x12000, 0x14000, 0x16000, 0x18000)]
    state, operations = {}, []

    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_' + name))

    def output(value):
        if reg('RCX') != archive:
            raise ValueError('Create output fixture receiver differs')
        operations.append(len(value))
        accepted = len(operations) != state.get('failure')
        if accepted:
            state['output'].extend(value)
        h.finish(int(accepted))

    for slot, width in ((0xc8, 4), (0xd0, 2), (0xe0, 1), (0xe8, 1), (0xf0, 1)):
        at = h.scratch + 0x20000 + slot
        h.add_fixture(at, lambda machine, width=width: output((reg('RDX') & ((1 << (8 * width)) - 1)).to_bytes(width, 'little')))
        uc.mem_write(table + slot, struct.pack('<Q', at))
    uc.mem_write(archive, struct.pack('<Q', table))

    def string_write(machine):
        at = reg('RDX')
        if at not in (packet + 0x20, packet + 0x48):
            raise ValueError('Create string field handoff differs')
        pointer, count, capacity = struct.unpack('<QII', bytes(uc.mem_read(at, 16)))
        if not 1 <= count <= capacity <= 2048 or pointer not in (string_a, string_b):
            raise ValueError('Create string fixture bound')
        value = bytes(uc.mem_read(pointer, count * 2))
        if value[-2:] != b'\0\0':
            raise ValueError('Create string fixture terminator differs')
        encoded = value[:-2].decode('utf-16le').encode('utf-8')
        output(struct.pack('<H', len(encoded)) + encoded)

    def item_write(machine):
        at = reg('RCX')
        if not items <= at < items + 16 * state['item_count'] or reg('RDX') != archive:
            raise ValueError('Create array item handoff differs')
        a, b, c = struct.unpack('<IBxH', bytes(uc.mem_read(at + 8, 8)))
        uc.reg_write(x.UC_X86_REG_RCX, archive)
        output(struct.pack('<IBH', a, b, c))
    h.add_fixture(0x144aad400, string_write)
    h.add_fixture(0x14578b8f0, item_write)

    def text(at, pointer, value):
        encoded = value.encode('utf-16le') + b'\0\0'
        uc.mem_write(pointer, encoded)
        uc.mem_write(at, struct.pack('<QII', pointer, len(encoded) // 2, len(encoded) // 2))

    def write(raw_class, name, appearance_text, variant, failure=None):
        uc.mem_write(packet - 16, b'\xa5' * 0xa0)
        if h.call(roles['request_constructor'], packet) != packet:
            raise ValueError('Create whole constructor return differs')
        if int.from_bytes(uc.mem_read(packet, 8), 'little') != 0x14992afa8:
            raise ValueError('Create whole constructor table differs')
        values = bytes(range(1, 11)) if variant else bytes(10)
        flags = b'\xff\xff' if variant else bytes(2)
        rows = ((0x12345678, 255, 65535), (0, 0, 1)) if variant else ()
        uc.mem_write(packet + 0x18, struct.pack('<I', raw_class))
        text(packet + 0x20, string_a, name)
        text(packet + 0x48, string_b, appearance_text)
        uc.mem_write(packet + 0x38, values)
        uc.mem_write(packet + 0x58, flags)
        for index, row in enumerate(rows):
            uc.mem_write(items + index * 16, struct.pack('<QIBxH', 0x149922b08, *row))
        uc.mem_write(packet + 0x60, struct.pack('<QII', items if rows else 0, len(rows), len(rows)))
        state.update(output=bytearray(), failure=failure, item_count=len(rows))
        operations.clear()
        before = bytes(uc.mem_read(packet - 16, 0xa0))
        uc.reg_write(x.UC_X86_REG_RDX, archive)
        accepted = h.call(roles['request_writer'], packet) & 255
        if bytes(uc.mem_read(packet - 16, 0xa0)) != before:
            raise ValueError('Create writer mutated input or guards')
        def wire_string(value):
            encoded = value.encode('utf-8')
            return struct.pack('<H', len(encoded)) + encoded
        expected = (struct.pack('<I', raw_class) + wire_string(name) + values + wire_string(appearance_text)
                    + flags + struct.pack('<H', len(rows)) + b''.join(struct.pack('<IBH', *row) for row in rows))
        return accepted, bytes(state['output']), expected, len(operations)

    cases = []
    for raw_class in (1, 3, 0xffffffff):
        for name, description in (('', ''), ('Silverwolf', '{"VoiceType":1}'), ('Ж界🙂', '{"1":0.5}')):
            for variant in (False, True):
                accepted, output_bytes, expected, count = write(raw_class, name, description, variant)
                if accepted != 1 or output_bytes != expected:
                    raise ValueError('Current Create three-writer output differs')
                cases.append(dict(raw_class=raw_class, unicode=bool(name and not name.isascii()),
                                  variant=variant, bytes=len(output_bytes), operations=count))
    failures = []
    _, _, _, total = write(1, 'Silverwolf', '{"VoiceType":1}', True)
    for failure in range(1, total + 1):
        accepted, _, _, count = write(1, 'Silverwolf', '{"VoiceType":1}', True, failure)
        if accepted != 0 or count != failure:
            raise ValueError('Current Create fixture failure did not stop at failed field')
        failures.append(dict(failed_operation=failure, operations=count))

    events = []
    def record_construct(machine):
        if reg('RCX') != packet + 0x18:
            raise ValueError('Result nested constructor handoff differs')
        uc.mem_write(packet + 0x18, struct.pack('<Q', 0x14992b020))
        events.append('record_constructor')
        h.finish(packet + 0x18)

    def code_read(machine):
        if reg('RCX') != archive or reg('RDX') != packet + 0x10:
            raise ValueError('Result code read handoff differs')
        events.append('u32')
        if state['header_ok']:
            uc.mem_write(packet + 0x10, struct.pack('<I', state['code']))
        h.finish(int(state['header_ok']))

    def record_read(machine):
        if reg('RCX') != packet + 0x18 or reg('RDX') != archive:
            raise ValueError('Result nested record reader handoff differs')
        events.append('record_reader')
        h.finish(int(state['record_ok']))
    h.add_fixture(0x145783c00, record_construct)
    h.add_fixture(0x1457888c0, record_read)
    h.add_fixture(h.scratch + 0x21000, code_read)
    uc.mem_write(table + 0x58, struct.pack('<Q', h.scratch + 0x21000))
    result_cases = []
    for code in (0, 58, 0xffffffff):
        for header_ok in (False, True):
            for record_ok in (False, True):
                uc.mem_write(packet - 16, b'\xa5' * 0x1b0)
                events.clear()
                if h.call(roles['result_constructor'], packet) != packet:
                    raise ValueError('Result constructor return differs')
                if int.from_bytes(uc.mem_read(packet, 8), 'little') != 0x14992b068 or events != ['record_constructor']:
                    raise ValueError('Result constructor composition differs')
                state.update(code=code, header_ok=header_ok, record_ok=record_ok)
                uc.reg_write(x.UC_X86_REG_RDX, archive)
                accepted = h.call(roles['result_reader'], packet) & 255
                if accepted != int(header_ok and record_ok) or events != ['record_constructor', 'u32'] + (['record_reader'] if header_ok else []):
                    raise ValueError('Result outer code/record control differs')
                if bytes(uc.mem_read(packet - 16, 16)) != b'\xa5' * 16 or bytes(uc.mem_read(packet + 0x188, 24)) != b'\xa5' * 24:
                    raise ValueError('Result outer constructor/reader guard changed')
                result_cases.append(dict(code=code, header_ok=header_ok, record_ok=record_ok, accepted=accepted))
    return dict(cases=cases, failures=failures, result_cases=result_cases, bindings=bindings, exports=h.evidence)


def verify_report(path, *, root=ROOT, context_path=CONTEXT):
    path, root = Path(path).resolve(), Path(root).resolve()
    if (not path.is_relative_to(root / 'code-clues' / RECIPE) or path.name != 'manifest.json'
            or path.parent.name != digest(path)):
        raise ValueError('Current Create cached proof changed')
    report = json.loads(path.read_bytes())
    _, definition = materials(root, context_path)
    if (report.get('definition') != definition or report.get('source_sha256') != SHA
            or report.get('method') != 'bounded_native' or report.get('native_execution') is not True
            or report.get('runtime_admitted') is not False or report.get('network_used') is not False
            or len(report.get('cases', [])) != 18 or len(report.get('result_cases', [])) != 12
            or len(report.get('failures', [])) != 18):
        raise ValueError('Current Create cached scope/definition changed')
    return report


def run(*, root=ROOT, context_path=CONTEXT):
    root = Path(root).resolve()
    context, definition = materials(root, context_path)
    workflow = load('research-workflow')
    key = hashlib.sha256(workflow.canonical(definition)).hexdigest()
    cache = root / 'knowledge/create-packets-current-cache' / (key + '.json')
    if cache.is_file():
        pointer = json.loads(cache.read_bytes())
        report = verify_report(pointer['path'], root=root, context_path=context_path)
        if digest(pointer['path']) != pointer['sha256'] or materials(root, context_path)[1] != definition:
            raise ValueError('Current Create cache changed during validation')
        return Path(pointer['path']), report, True
    executed = execute(context, root=root)
    if materials(root, context_path)[1] != definition:
        raise ValueError('Current Create inputs changed during native execution')
    report = dict(schema=1, recipe=RECIPE, source_sha256=SHA, definition=definition,
        method='bounded_native', native_execution=True, network_used=False, runtime_admitted=False,
        profile_activated=False, live_verified=False, **executed,
        limits=['Whole current packet constructors, three writers, object-dispatch aliases and Result outer reader execute.',
                'Output scalars, FString UTF8 encoding and array item writer are explicit bounded fixtures.',
                'Result nested constructor/reader and archive u32 are fixtures; their current separate CharacterList proof is retained, not replayed.',
                'String helper internal failure behavior, complete Result reader composition and Create handler remain unexecuted.',
                'No valid Viper settings, name policy, producer, game send, server result or creation admission is established.'])
    path = load('audit-client-release').save_snapshot(root / 'code-clues' / RECIPE, report)
    workflow.atomic(cache, workflow.canonical(dict(path=str(path), sha256=digest(path))))
    return path, report, False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, default=CONTEXT)
    args = parser.parse_args()
    path, report, reused = run(context_path=args.context)
    print(json.dumps(dict(report=str(path), sha256=digest(path), reused=reused,
                         cases=len(report['cases']), failures=len(report['failures']), result_cases=len(report['result_cases']))))
