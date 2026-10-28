"""Whole Windows Version suffix helper with synthetic TLS, WinAPI and string fixtures."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from importlib.util import spec_from_file_location, module_from_spec

HERE = Path(__file__).resolve().parent


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = module_from_spec(spec); spec.loader.exec_module(module)
    return module


def verify(context, root):
    at = int(context['function'], 16)
    h = load('update-native-harness').make_harness(context, context['exports'], {at}, root=root)
    rows = load('update-bindings').rows(load('build-native-entry-code'), h.image, at)
    calls = {hex(r['address']): hex(r['direct_target']) if r['direct_target'] is not None else r['operands']
             for r in rows if r['call']}
    if calls != context['call_sites']: raise ValueError('Windows helper call sites differ')
    imports = load('build-object-zero-init-code')
    for name, item in context['imports'].items():
        actual = imports.import_at(h.raw, h.image, int(item['slot'], 16))
        if actual['name'] != name or actual['dll'].lower() != item['dll'].lower():
            raise ValueError('Windows helper import differs')
    fixture = {key: int(value, 16) for key, value in context['fixtures'].items()}
    offset = h.image.offset(fixture['memset'] - h.image.pe.base)
    if h.raw[offset:offset + 2] != b'\xff\x25': raise ValueError('Windows memset thunk differs')
    memset_slot = fixture['memset'] + 6 + struct.unpack_from('<i', h.raw, offset + 2)[0]
    if imports.import_at(h.raw, h.image, memset_slot)['name'] != 'memset':
        raise ValueError('Windows memset import differs')
    guard, cache, tls_index, cookie = [int(context[key], 16) for key in ('guard', 'cache', 'tls_index', 'cookie')]
    teb, vector, block, output = h.scratch + 0x8000, h.scratch + 0x9000, 0x29000000, h.scratch + 0x1000
    h.uc.mem_map(block, 0x102000)
    h.uc.reg_write(h.x.UC_X86_REG_GS_BASE, teb)
    h.uc.mem_write(teb + 0x58, struct.pack('<Q', vector))
    h.uc.mem_write(vector, struct.pack('<Q', block))
    h.uc.mem_write(tls_index, b'\0' * 4)
    state = {}

    def reg(name): return h.uc.reg_read(getattr(h.x, 'UC_X86_REG_' + name))
    def wide(pointer):
        data = bytearray()
        for index in range(128):
            value = bytes(h.uc.mem_read(pointer + index * 2, 2))
            if value == b'\0\0': return data.decode('utf-16le')
            data.extend(value)
        raise ValueError('Windows fixture text bound')
    def write_wide(pointer, value): h.uc.mem_write(pointer, (value + '\0').encode('utf-16le'))

    def hook(name):
        def execute(machine):
            a, b, c, d = [reg(key) for key in ('RCX', 'RDX', 'R8', 'R9')]
            stack = reg('RSP'); state['events'].append(name); result = 0
            if name == 'acquire':
                if a != guard: raise ValueError('Windows guard address differs')
                h.uc.mem_write(guard, struct.pack('<i', state['acquired']))
            elif name == 'release':
                if a != guard: raise ValueError('Windows release address differs')
                h.uc.mem_write(guard, b'\0' * 4)
            elif name == 'system_info':
                h.uc.mem_write(a, b'\x6b' * 48)
            elif name == 'memset':
                if b != 0 or c != 0x118: raise ValueError('Windows struct zeroing differs')
                h.uc.mem_write(a, b'\0' * c); result = a
            elif name == 'version':
                if bytes(h.uc.mem_read(a, 0x11c)) != struct.pack('<I', 0x11c) + bytes(0x118):
                    raise ValueError('Windows version struct initialization differs')
                major, minor, build, product, suite = state['values']
                h.uc.mem_write(a + 4, struct.pack('<III', major, minor, build))
                h.uc.mem_write(a + 0x118, struct.pack('<HB', suite, product))
                result = state['version_ok']
            elif name == 'format':
                if a != cache or b != 128 or wide(c) != '%d.%d.%d.%d.%d.%s':
                    raise ValueError('Windows format binding differs')
                extra = [int.from_bytes(h.uc.mem_read(stack + offset, 4), 'little') for offset in (0x28, 0x30, 0x38, 0x40)]
                tail = int.from_bytes(h.uc.mem_read(stack + 0x48, 8), 'little')
                if [d, *extra] != list(state['values']) or wide(tail) != '64bit':
                    raise ValueError('Windows format field order differs')
                value = '.'.join(map(str, state['values'])) + '.64bit'
                write_wide(cache, value); state['formatted'] = value
            elif name == 'wide_string':
                if a != output or b != cache: raise ValueError('Windows output projection differs')
                value = wide(b); pointer = h.scratch + 0x2000
                write_wide(pointer, value)
                count = len(value) + 1
                h.uc.mem_write(a, struct.pack('<QII', pointer, count, count)); result = a
            elif name == 'cookie_check':
                if a != 0x12345678: raise ValueError('Windows cookie differs')
                result = reg('RAX')  # Explicit cookie fixture preserves the caller's result.
            else: raise ValueError('Unknown Windows fixture')
            h.finish(result)
        return execute
    for name, address in fixture.items(): h.add_fixture(address, hook(name))
    for offset, (name, item) in enumerate(context['imports'].items()):
        target = h.scratch + 0x6000 + offset * 16
        h.add_fixture(target, hook(item['fixture']))
        h.uc.mem_write(int(item['slot'], 16), struct.pack('<Q', target))
    profiles = [dict(name='cached', guard=0, epoch=0, acquired=-1, version_ok=1),
                dict(name='cold', guard=1, epoch=0, acquired=-1, version_ok=1),
                dict(name='failed-version', guard=1, epoch=0, acquired=-1, version_ok=0),
                dict(name='other-thread', guard=1, epoch=0, acquired=7, version_ok=1),
                dict(name='negative-equal', guard=-1, epoch=-1, acquired=-1, version_ok=1),
                dict(name='negative-cold', guard=-1, epoch=-2, acquired=-1, version_ok=1)]
    abi = {key: 0x123456789abcdef0 + index for index, key in enumerate(('RBX', 'RSI', 'RDI', 'RBP', 'R12', 'R13', 'R14', 'R15'))}
    abi.update({'XMM'+str(i):0x123456789abcdef0fedcba9876543210+i for i in range(6,16)})
    cases = []
    for poison in (0, 0x55, 0xaa, 0xff):
        for profile in profiles:
            for values in ((10, 0, 26100, 1, 256), (6, 3, 9600, 255, 65535)):
                state.update(profile, values=values, events=[], formatted=None)
                h.uc.mem_write(guard, struct.pack('<i', profile['guard']))
                h.uc.mem_write(block + 0x101184, struct.pack('<i', profile['epoch']))
                h.uc.mem_write(cookie, struct.pack('<Q', 0x12345678))
                write_wide(cache, 'cached-fixture')
                h.uc.mem_write(output - 16, b'\xa5' * 16 + bytes((poison,)) * 16 + b'\xa6' * 16)
                for key, value in abi.items(): h.uc.reg_write(getattr(h.x, 'UC_X86_REG_' + key), value)
                if h.call(at, output) != output: raise ValueError('Windows helper return differs')
                cold = profile['guard'] > profile['epoch'] and profile['acquired'] == -1
                expected = ('.'.join(map(str, values)) + '.64bit' if profile['version_ok'] else '') if cold else 'cached-fixture'
                if wide(cache) != expected or wide(h.scratch + 0x2000) != expected:
                    raise ValueError('Windows helper result differs')
                events = (['acquire'] if profile['guard'] > profile['epoch'] else [])
                if cold: events += ['system_info', 'memset', 'version'] + (['format'] if profile['version_ok'] else []) + ['release']
                if state['events'] != events + ['wide_string', 'cookie_check']:
                    raise ValueError('Windows helper lifecycle differs')
                if any(reg(key) != value for key, value in abi.items()) or reg('RSP') != h.scratch + 0x38008:
                    raise ValueError('Windows helper ABI differs')
                if bytes(h.uc.mem_read(output - 16, 16)) != b'\xa5' * 16 or bytes(h.uc.mem_read(output + 16, 16)) != b'\xa6' * 16:
                    raise ValueError('Windows helper output canary differs')
                cases.append(dict(profile=profile['name'], poison=poison, values=values, result=expected, events=state['events']))
    return dict(schema=1, source_sha256=context['source_sha256'], method='bounded_native', cases=cases,
        evidence=h.evidence, network_used=False, host_identity_read=False, profile_activated=False,
        runtime=load('update-native-harness').runtime_inputs(),
        limits=['Whole current Windows suffix function; TLS state, WinAPI, CRT guard/cookie/format and FString constructor are fixtures.',
                'No host OS version, actual CRT formatting, CPU helper, full Version/Login integration, auth or sockets.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args(); report = verify(json.loads(args.context.read_text('utf-8')), args.root)
    report['context_sha256'] = hashlib.sha256(args.context.read_bytes()).hexdigest()
    report['tool_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    target = load('research-workflow').snapshot(args.root, 'native-version-windows-checks', report)
    print(json.dumps(dict(report=str(target), cases=len(report['cases']))))
