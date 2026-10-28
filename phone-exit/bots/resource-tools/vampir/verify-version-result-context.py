"""Current ID 2 constructor/reader with the reviewed native input archive."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ORDER = (('u32', 0x10), ('u32', 0x14), ('bool', 0x18), ('u32', 0x1c), ('u32', 0x20))


def verify(context, root):
    archive_context = context['native_input']
    if archive_context['source_sha256'] != context['source_sha256']:
        raise ValueError('VersionResult archive source differs')
    roots = {int(at, 16) for at in archive_context['functions'].values()}
    reader = int(context['reader'], 16)
    roots.add(reader)
    exports = dict(archive_context['exports'], **context['exports'])
    leaves = {int(at, 16): row['bytes'] for at, row in archive_context['leaves'].items()}
    leaves.update({int(at, 16): row['bytes'] for at, row in context['leaves'].items()})
    h = load('update-native-harness').make_harness(context, exports, roots, leaves=leaves, root=root)

    def require(ok, message):
        if not ok:
            raise ValueError(message)

    def data(at, size):
        off = h.image.offset(at - h.image.pe.base)
        return h.raw[off:off + size]

    for row in context['tables']:
        payload = bytes.fromhex(row['bytes'])
        require(data(int(row['address'], 16), len(payload)) == payload
                and hashlib.sha256(payload).hexdigest() == row['sha256'], 'VersionResult table/literal differs')
    table, constructor, getter = [int(context[key], 16) for key in ('packet_table', 'constructor', 'id_getter')]
    require(struct.unpack('<Q', data(table + 0x20, 8))[0] == reader, 'VersionResult reader slot differs')
    require(struct.unpack('<Q', data(table + 0x28, 8))[0] == getter
            and h.call(getter) == 2, 'VersionResult ID differs')
    native = load('build-native-entry-code')
    calls = {hex(r['address']): r['operands'] for r in load('update-bindings').rows(native, h.image, reader) if r['call']}
    require(calls == context['call_sites'], 'VersionResult call sites differ')
    packet, archive = h.scratch + 0x1000, h.scratch + 0x2000
    state = {}
    seed, position, _, check, construction = load('login-result-input-fixtures').install(
        load, h, archive_context, state, packet, archive, ORDER)
    sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
    from vampir_core.version_result import decode_version_result

    def read(body, poison=0x55, fail_at=None):
        state.clear()
        state.update(body=body, operations=[], written=[], fail_at=fail_at)
        h.uc.mem_write(packet - 16, b'\xa5' * 16 + bytes([poison]) * 0x28 + b'\xa6' * 16)
        require(h.call(constructor, packet) == packet, 'VersionResult constructor return differs')
        require(int.from_bytes(h.uc.mem_read(packet, 8), 'little') == table, 'VersionResult constructor table differs')
        before = bytes(h.uc.mem_read(packet, 0x28))
        seed(body, poison)
        abi = {name: 0x1234567800000000 + i for i, name in enumerate(('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15'))}
        abi.update({'XMM'+str(i):0x123456789abcdef0fedcba9876543210+i for i in range(6,16)})
        for name, value in abi.items():
            h.uc.reg_write(getattr(h.x, 'UC_X86_REG_' + name), value)
        h.uc.reg_write(h.x.UC_X86_REG_RDX, archive)
        returned = h.call(reader, packet) & 255
        check()
        require(all(h.uc.reg_read(getattr(h.x, 'UC_X86_REG_' + name)) == value for name, value in abi.items())
                and h.uc.reg_read(h.x.UC_X86_REG_RSP) == h.scratch + 0x38008, 'VersionResult ABI differs')
        after = bytes(h.uc.mem_read(packet, 0x28))
        allowed = {i for kind, offset in ORDER for i in range(offset, offset + (1 if kind == 'bool' else 4))}
        require(all(a == b for i, (a, b) in enumerate(zip(before, after)) if i not in allowed)
                and bytes(h.uc.mem_read(packet - 16, 16)) == b'\xa5' * 16
                and bytes(h.uc.mem_read(packet + 0x28, 16)) == b'\xa6' * 16, 'VersionResult object guards differ')
        values = [int.from_bytes(after[offset:offset + (1 if kind == 'bool' else 4)], 'little') for kind, offset in ORDER]
        if returned:
            decoded = decode_version_result(body[:17])
            require(values == [decoded.result_code, decoded.raw14, int(decoded.flag18), decoded.raw1c, decoded.raw20],
                    'VersionResult runtime projection differs')
            require(position() == 17 and len(state['operations']) == 5, 'VersionResult consumption differs')
        return dict(returned=returned, consumed=position(), operations=state['operations'].copy(), values=values)

    cases = []
    for code in (0, 1, 58, 0xffffffff):
        for flag in (0, 1, 2, 255):
            for poison in (0x55, 0xaa):
                body = struct.pack('<IIBII', code, 0x80000000, flag, 0xffffffff, 0x12345678)
                case = read(body, poison)
                require(case['returned'] == 1, 'VersionResult full body rejected')
                cases.append(case)
    body = struct.pack('<IIBII', 0, 123, 1, 456, 789)
    truncated = [read(body[:size]) for size in range(17)]
    failures = [read(body, fail_at=slot) for slot in range(5)]
    require(all(c['returned'] == 0 for c in truncated + failures), 'VersionResult rejected input accepted')
    require(all(len(c['operations']) == slot + 1 for slot, c in enumerate(failures)), 'VersionResult failure did not stop reader')
    extra = read(body + b'extra')
    require(extra['returned'] == 1 and extra['consumed'] == 17, 'VersionResult extra-body native behavior differs')
    return dict(schema=1, source_sha256=context['source_sha256'], method='bounded_native', evidence=h.evidence,
                cases=cases, truncated=truncated, failures=failures, extra=extra, construction_cases=construction,
                network_used=False, profile_activated=False,
                limits=['Explicit ID 2 table, constructor, reader and native buffer/scalar/raw input only.',
                        'Buffer allocation, registration, dispatch and VersionResult handler are not executed.',
                        'Little-endian input; runtime exact-size policy remains stricter than native reader.',
                        'No Login, character list, creation, authorization or runtime profile promotion.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    result = verify(json.loads(args.context.read_text('utf-8')), args.root)
    result.update(context_sha256=hashlib.sha256(args.context.read_bytes()).hexdigest(),
                  tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    path = load('research-workflow').snapshot(args.root, 'native-version-result-checks', result)
    print(json.dumps(dict(report=str(path), cases=len(result['cases']), truncated=len(result['truncated']), failures=len(result['failures']))))
