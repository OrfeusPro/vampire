"""Revalidate fixed current Ping/world exports, whole ranges and static bindings."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
HERE = Path(__file__).resolve().parent
SHA = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'

def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def verify(context, root):
    root = Path(root)
    source = root / 'client-code-snapshots' / SHA / 'ProjectRED-Win64-Shipping.exe'
    if context['source_sha256'] != SHA or Path(context['source']).resolve() != source.resolve():
        raise ValueError('Ping/world context source differs')
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA:
        raise ValueError('Ping/world source SHA changed')
    native = load('build-native-entry-code')
    image = native.Image(raw)
    functions = {int(at, 16) for at in context['functions'].values()}
    found = set()
    evidence = []
    expected_roots = {int(at, 16) for at in '14561bc90 1456bab10 1456db460 1456e8430 1456f02c0 1458223b0 1458224f0 14584f520 14584f7d0 14584f8f0 145db2dd0 145db5f80 145db64b0 1467d2820 14679f900'.split()}
    if functions != expected_roots:
        raise ValueError('Ping/world fixed root set changed')
    whole = load('audit-launcher-shape-11318')
    for run, expected in context['exports'].items():
        path = root / 'ghidra/request-exports' / SHA / run / 'details.json'
        if digest(path) != expected:
            raise ValueError('Ping/world export SHA changed')
        document = json.loads(path.read_bytes())
        if document['new_source_sha256'] != SHA:
            raise ValueError('Ping/world export source differs')
        evidence.append(dict(path=str(path), sha256=expected))
        for f in document['functions']:
            at = int(f['address'], 16)
            if at not in functions:
                continue
            if at in found:
                raise ValueError('Duplicate Ping/world export root')
            whole.normalize_function(native, image, f)
            found.add(at)
    if found != functions:
        raise ValueError('Ping/world export root absent')
    for at, encoded in dict(context['leaves'], **context['blocks']).items():
        at = int(at, 16)
        payload = bytes.fromhex(encoded)
        off = image.offset(at - image.pe.base)
        if raw[off:off + len(payload)] != payload:
            raise ValueError('Ping/world static source bytes changed')
    ping = context['ping']
    expected_ping = dict(constructor='0x1456d78c0', getter='0x1456e4e50', reader='0x1456db460', handler='0x14679f900', receiver='0x1467d2820', packet_table='0x1499295b0', handler_table='0x149dc9438', wrapper_getter='0x144ab0d30', config_getter='0x145594dd0', recovery='0x144ab11e0')
    if any((ping.get(key) != value for key, value in expected_ping.items())):
        raise ValueError('Ping source-bound role differs')
    table = int(ping['packet_table'], 16)
    handler_table = int(ping['handler_table'], 16)

    def data(at, size):
        off = image.offset(at - image.pe.base)
        return raw[off:off + size]
    for base, slot, key in ((table, 32, 'reader'), (table, 40, 'getter'), (handler_table, 16, 'handler')):
        if struct.unpack('<Q', data(base + slot, 8))[0] != int(ping[key], 16):
            raise ValueError('Ping static table link changed')
    if data(table + 80, 14) != b'PktPingResult\x00' or data(int(ping['getter'], 16), 6) != b'\xb8\x11\x00\x00\x00\xc3':
        raise ValueError('Ping packet name/ID changed')
    get = int(context['mapping']['0x1445cd3c0'], 16)
    leaf = data(get, 8)
    if get != 5441901856 or leaf[:3] != b'H\x8b\x05' or leaf[-1:] != b'\xc3' or (get + 7 + struct.unpack_from('<i', leaf, 3)[0] != int(ping['clock_global'], 16)):
        raise ValueError('Ping clock singleton role differs')
    registration = ping['registration']
    at = int(registration['address'], 16)
    if at != 5477466892 or registration['owner'] != '0x1467b8040' or len(bytes.fromhex(registration['bytes'])) != 75 or (data(at, 75) != bytes.fromhex(registration['bytes'])):
        raise ValueError('Ping registration binding differs')
    return dict(source_sha256=SHA, evidence=evidence, function_count=len(found), network_used=False, profile_activated=False, limits=['Whole native ranges and pinned static bindings only; execution and fixtures are reported separately.'])
