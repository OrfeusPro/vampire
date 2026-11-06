"""Execute current LobbyLogin preparation with bounded SDK and sender fixtures."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from importlib.util import module_from_spec, spec_from_file_location

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/lobby-login-prepare-current.json'
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
RECIPE = 'lobby-login-prepare-current-v1'
STRINGS = (0x18, 0x28, 0x38, 0x48, 0x58, 0x70)
ABI = ('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15')


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def check_inputs(inputs):
    for path, sha in inputs.items():
        if digest(path) != sha:
            raise ValueError('Current LobbyLogin preparation input changed: ' + Path(path).name)


def definition(context_path, root):
    context_path = Path(context_path).resolve()
    context = json.loads(context_path.read_bytes())
    if (context.get('schema') != 1 or context.get('recipe') != RECIPE
            or context.get('source_sha256') != SOURCE
            or context.get('functions') != {'prepare': '0x1467d1200'}
            or context.get('verify_whole_exports') is not True
            or set(context.get('leaves', {})) != {'0x145749670', '0x144ab0d30', '0x144ab0d70'}
            or set(context.get('exports', {})) != {'run-6204f055a2a7'}):
        raise ValueError('Current LobbyLogin preparation context differs')
    source = root / 'client-code-snapshots' / SOURCE / 'ProjectRED-Win64-Shipping.exe'
    if Path(context['source']).resolve() != source:
        raise ValueError('Current LobbyLogin preparation source path differs')
    files = [context_path, Path(__file__).resolve()]
    files.extend(HERE / name for name in ('audit-launcher-shape-11318.py', 'build-native-entry-code.py',
                                         'update-native-harness.py', 'build-object-zero-init-code.py'))
    files.extend(HERE.parents[1] / 'vampir-shared/vampir_core' / name
                 for name in ('lobby_packets.py', 'lobby_current.py', 'login_packet.py'))
    inputs = {str(path): digest(path) for path in files}
    inputs[str(source)] = SOURCE
    for run, sha in context['exports'].items():
        inputs[str(root / 'ghidra/request-exports' / SOURCE / run / 'details.json')] = sha
    sender = load('verify-lobby-sender-current')
    _, sender_definition = sender.definition(sender.CONTEXT, root)
    inputs.update(sender_definition['inputs'])
    check_inputs(inputs)
    return context, dict(schema=1, recipe=RECIPE, source_sha256=SOURCE,
                         inputs=inputs, runtime=load('update-native-harness').runtime_inputs())


def scenarios():
    base = dict(selector=3, kind=2, server=387, sdk_enabled=True, manager=True, auth=True, nid=True,
                global_player='bootstrap', old_token='previous', nm='device-fixture', player='player-Ж',
                token='token-fixture', nid_text='nid-fixture', sdk_text='sdk-fixture', metadata='Ж猫😀')
    return {
        'windows': base,
        'kind-unset': dict(base, kind=0, server=0),
        'platform-other': dict(base, selector=1, server=0xffffffff),
        'sdk-disabled': dict(base, sdk_enabled=False),
        'manager-missing': dict(base, manager=False),
        'auth-missing': dict(base, auth=False),
        'nid-missing': dict(base, nid=False),
        'empty-text': dict(base, global_player='', old_token='', player='', token='', nm='',
                           nid_text='', sdk_text='', metadata=''),
    }


def execute(context, root):
    h = load('update-native-harness').make_harness(context, context['exports'], {0x1467d1200},
        leaves={int(at, 16): code for at, code in context['leaves'].items()}, root=root)
    sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
    from vampir_core.lobby_current import make_current_windows_lobby_login
    from vampir_core.lobby_packets import LobbyLoginPayload, decode_current_lobby_version_result
    sender = load('verify-lobby-sender-current')
    sender_context, _ = sender.definition(sender.CONTEXT, root)
    replay = sender.Replay(sender_context, root)

    uc, base = h.uc, h.scratch
    owner, manager, auth, nid, peer, wrapper, player, token = (
        base + offset for offset in (0x1000, 0x2000, 0x2100, 0x2200, 0x3000, 0x3400, 0x3600, 0x3610))
    heap, heap_end = base + 0x10000, base + 0x30000
    state = {}

    def reg(name):
        return uc.reg_read(getattr(h.x, 'UC_X86_REG_' + name))

    def number(address, size=8):
        return int.from_bytes(uc.mem_read(address, size), 'little')

    def write(address, value, size=8):
        uc.mem_write(address, value.to_bytes(size, 'little'))

    def require(value, reason):
        if not value:
            raise ValueError(reason)

    def alloc(data):
        if not data:
            return 0
        at = state['next']
        require(at + len(data) < heap_end, 'LobbyLogin fixture storage exceeded')
        uc.mem_write(at - 8, b'\xab' * 8 + data + b'\xcd' * 8)
        state['next'] = (at + len(data) + 31) & ~15
        state['sizes'][at] = len(data)
        return at

    def read_text(address):
        ptr, count, capacity = struct.unpack('<QII', uc.mem_read(address, 16))
        require(0 <= count <= capacity <= 1024 and (not count or ptr in state['sizes']),
                'LobbyLogin FString fixture layout differs')
        if not count:
            return ''
        data = bytes(uc.mem_read(ptr, count * 2))
        require(data[-2:] == b'\0\0', 'LobbyLogin FString terminator differs')
        return data[:-2].decode('utf-16-le')

    def write_text(address, text):
        data = text.encode('utf-16-le') + b'\0\0' if text else b''
        uc.mem_write(address, struct.pack('<QII', alloc(data), len(data) // 2, len(data) // 2))

    def copy_global(machine):
        target, ptr, count = (reg(name) for name in ('RCX', 'RDX', 'R8'))
        require(target == owner + 0x40 and 0 <= count <= 1023
                and (not count or state['sizes'].get(ptr) == (count + 1) * 2),
                'LobbyLogin global player FString differs')
        write_text(target, bytes(machine.mem_read(ptr, count * 2)).decode('utf-16-le') if count else '')
        h.finish(target)

    def assign(machine):
        target = reg('RCX')
        write_text(target, read_text(reg('RDX')))
        h.finish(target)

    def resize(machine):
        target, capacity = reg('RCX'), reg('EDX')
        require(0 < capacity <= 1024 and number(target + 8, 4) == capacity,
                'LobbyLogin FString resize differs')
        write(target, alloc(bytes(capacity * 2)))
        write(target + 12, capacity, 4)
        h.finish()

    def output(name, receiver):
        def fixture(machine):
            require(receiver is None or reg('RCX') == receiver, 'LobbyLogin SDK/NID receiver differs')
            target = reg('RCX' if receiver is None else 'RDX')
            write_text(target, state['fixture'][name])
            state['providers'].append(name)
            h.finish(target)
        return fixture

    def getter(name, receiver, pointer):
        def fixture(machine):
            require(reg('RCX') == receiver, 'LobbyLogin SDK getter receiver differs')
            state['providers'].append(name)
            h.finish(pointer)
        return fixture

    def free(machine):
        pointer = reg('RCX')
        require(pointer in state['sizes'] and pointer not in state['freed'],
                'LobbyLogin temporary FString free differs')
        state['freed'].add(pointer)
        h.finish()

    def send_boundary(machine):
        packet = reg('RDX')
        require(reg('RCX') == owner and state['packet'] is None
                and base + 0x36000 <= packet <= base + 0x38000
                and number(packet) == 0x1499437b8,
                'LobbyLogin current owner / constructor vtable differs')
        state['packet'] = packet
        state['login'] = LobbyLoginPayload(tuple(read_text(packet + at) for at in STRINGS),
            tuple(number(packet + at, 4) for at in (0x10, 0x14, 0x68, 0x6c)), number(packet + 0x80, 1))
        h.finish(1)

    def destructor_boundary(machine):
        require(reg('RCX') == state['packet'] and not state['destructor'],
                'LobbyLogin destructor receiver differs')
        state['destructor'] = True
        h.finish()

    fixtures = {
        0x14142a2b0: copy_global, 0x141441dc0: assign, 0x141436f30: resize, 0x1414830e0: free,
        0x1445cd040: output('nm', None), 0x1445ce440: lambda m: h.finish(state['fixture']['selector']),
        0x14560ad70: lambda m: h.finish(manager if state['fixture']['manager'] else 0),
        0x14560b8f0: getter('player', auth, player), 0x145609e40: getter('token', auth, token),
        0x14560b060: output('sdk_text', auth), 0x14560ae30: output('nid_text', nid),
        0x14560b0c0: output('metadata', nid), 0x144aaf380: send_boundary, 0x14574ab90: destructor_boundary,
    }
    for at, fixture in fixtures.items():
        h.add_fixture(at, fixture)

    result = decode_current_lobby_version_result(bytes(33), source_sha256=SOURCE)
    cases = {}
    for name, f in scenarios().items():
        uc.mem_write(base, bytes(0x40000 - 0x1000))
        state.clear()
        state.update(fixture=f, sizes={}, freed=set(), providers=[], next=heap + 16, packet=None, destructor=False)
        write_text(player, f['player'])
        write_text(token, f['token'])
        write_text(owner + 0x40, 'stale-player')
        write_text(owner + 0x50, f['old_token'])
        write_text(0x14b594f30, f['global_player'])
        write(0x14b594f80, wrapper)
        write(0x14b594eb3, int(f['sdk_enabled']), 1)
        write(0x14b594eb9, 0, 1)
        write(wrapper + 0x10, peer)
        write(peer + 0x270, f['server'], 4)
        write(owner + 0x64, f['kind'], 4)
        write(manager + 0x38, auth if f['auth'] else 0)
        write(manager + 0x48, nid if f['nid'] else 0)
        registers = {item: 0xabcd000000000000 + index for index, item in enumerate(ABI)}
        for item, value in registers.items():
            uc.reg_write(getattr(h.x, 'UC_X86_REG_' + item), value)
        h.call(0x1467d1200, owner)
        require(all(reg(item) == value for item, value in registers.items()) and reg('RSP') == base + 0x38008,
                'LobbyLogin current prepare ABI differs')
        require(state['destructor'] and state['packet'] is not None and number(owner + 0x60, 4) == f['server'],
                'LobbyLogin did not reach sender and cleanup with the selected server')
        require(read_text(owner + 0x40) == f['global_player'], 'LobbyLogin owner global player copy differs')
        has_auth = f['sdk_enabled'] and f['manager'] and f['auth']
        has_nid = f['sdk_enabled'] and f['manager'] and f['nid']
        providers = ['nm'] + (['player', 'token', 'sdk_text'] if has_auth else [])
        providers += ['nid_text', 'metadata'] if has_nid else []
        require(state['providers'] == providers, 'LobbyLogin SDK/NID provider routing differs')
        strings = (f['player'] if has_auth else f['global_player'], f['token'] if has_auth else f['old_token'],
                   f['nm'], f['nid_text'] if has_nid else '', f['sdk_text'] if has_auth else '',
                   f['metadata'] if has_nid else '')
        integers = (2 if f['selector'] == 3 else 1, 2 if f['kind'] == 2 else 0, f['server'], 0)
        login = state['login']
        require((login.strings, login.integers, login.raw_80) == (strings, integers, 7),
                'LobbyLogin native prepared fields differ')
        if f['selector'] == 3:
            binding = make_current_windows_lobby_login(version_result=result, kind=f['kind'],
                selected_server_id=f['server'], metadata=strings[-1], source_sha256=SOURCE)
            require((binding.login.integers, binding.login.raw_80, binding.login.strings[-1])
                    == (login.integers, login.raw_80, login.strings[-1]), 'LobbyLogin current Windows binder differs')
        for at, size in state['sizes'].items():
            require(bytes(uc.mem_read(at - 8, 8)) == b'\xab' * 8
                    and bytes(uc.mem_read(at + size, 8)) == b'\xcd' * 8, 'LobbyLogin fixture storage guard changed')
        wire = replay.run('login', True, 1, 0, False, 1, payload_override=login)
        cases[name] = dict(integers=list(login.integers), providers=providers, raw_80=login.raw_80, wire=wire,
                           body_sha256=hashlib.sha256(login.encode(max_payload_size=4096)).hexdigest())
    return cases


def validate(report, selected):
    if (report.get('schema') != 1 or report.get('recipe') != RECIPE or report.get('source_sha256') != SOURCE
            or report.get('definition') != selected or report.get('native_execution') is not True
            or report.get('network_used') is not False or report.get('runtime_admitted') is not False
            or not report.get('limits') or set(report.get('cases', {})) != set(scenarios())
            or any(row.get('raw_80') != 7 or row.get('wire', {}).get('request_id') != 3
                   or row['wire'].get('path') != 'direct' for row in report['cases'].values())):
        raise ValueError('Current LobbyLogin preparation report boundary differs')


def verify(context_path=CONTEXT, *, root=ROOT):
    root = Path(root).resolve()
    context, selected = definition(context_path, root)
    workflow = load('research-workflow')
    key = hashlib.sha256(workflow.canonical(selected)).hexdigest()
    cache = root / 'knowledge' / (RECIPE + '-cache') / (key + '.json')
    if cache.is_file():
        pointer = json.loads(cache.read_bytes())
        path = Path(pointer['path']).resolve()
        if (path != root / 'code-clues' / RECIPE / pointer['sha256'] / 'manifest.json'
                or digest(path) != pointer['sha256']):
            raise ValueError('Current LobbyLogin preparation cache pointer differs')
        validate(json.loads(path.read_bytes()), selected)
        return dict(report=str(path), sha256=pointer['sha256'], reused=True)
    cases = execute(context, root)
    check_inputs(selected['inputs'])
    report = dict(schema=1, recipe=RECIPE, source_sha256=SOURCE, definition=selected, cases=cases,
        native_execution=True, network_used=False, runtime_admitted=False,
        limits=['Version flag off. Exact LoginPrepare, packet constructor and selected-server getter.',
                'Captured prepared fields are transferred to a second bounded native sender harness, including real writer/OUTPUT/CRC/XOR.',
                'SDK/NID providers, FString allocation/assignment, destructor and transport remain fixtures.',
                'No live identity, full Version flag-on path, native socket drain or runtime admission.'])
    validate(report, selected)
    path = load('audit-client-release').save_snapshot(root / 'code-clues' / RECIPE, report)
    sha = digest(path)
    workflow.atomic(cache, workflow.canonical(dict(path=str(path), sha256=sha)))
    return dict(report=str(path), sha256=sha, reused=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--context', type=Path, default=CONTEXT)
    args = parser.parse_args()
    print(json.dumps(verify(args.context, root=args.root)))
