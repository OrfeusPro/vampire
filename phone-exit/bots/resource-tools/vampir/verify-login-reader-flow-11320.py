"""Whole current LoginResult reader flow with explicit opaque archive fixtures.

Checks destinations, short circuiting, ABI and memory guards. Does not decode
nested time/period objects, construct packets, or authorize runtime use.
"""
import argparse
import json
import re
import struct
from pathlib import Path
import importlib.util

HERE = Path(__file__).resolve().parent
SOURCE = '544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c'
ALIGNMENT = '99974a080331ea0ab6ad3bfecf1a173a7ee65f3b308f0be1c58691f9222e4d07'


def resolve_handler(discovery, root):
    """Constrain source-bound gate candidates by the mapped post-state call."""
    d = load('discover-login-result-11320')
    path = Path(root) / 'knowledge/login-batch-alignment-11320' / ALIGNMENT / 'manifest.json'
    alignment = json.loads(path.read_bytes())
    if d.digest(path) != ALIGNMENT or alignment['source_sha256'] != SOURCE:
        raise ValueError('Handler alignment identity changed')
    if d.digest(HERE / 'align-login-batch-11320.py') != alignment['tool_sha256']:
        raise ValueError('Handler alignment producer changed')
    for name, sha in alignment['inputs'].items():
        if d.digest(name) != sha:
            raise ValueError('Handler alignment input changed')
    post = int(alignment['roots']['0x146755a10'], 16)
    native = load('build-native-entry-code')
    image = native.Image((Path(root) / 'client-code-snapshots' / SOURCE / 'ProjectRED-Win64-Shipping.exe').read_bytes())
    found = []
    for candidate in discovery['handler_candidates']:
        at = int(candidate, 16)
        bounds = image.roots[image.containing(at)]
        off = image.offset(bounds[0])
        code = image.data[off:off + bounds[1] - bounds[0]]
        if not any(code[i] == 0xe8 and at + i + 5 + struct.unpack_from('<i', code, i + 1)[0] == post for i in range(len(code) - 4)):
            continue
        rows = load('update-bindings').rows(native, image, at)
        calls = {r['direct_target'] for r in rows if r['call']}
        if post in calls and 0x1467d0c60 in calls:
            found.append(candidate)
    if len(found) != 1:
        raise ValueError('Missing/ambiguous gate+post-state handler')
    return dict(handler=found[0], post_state=hex(post), gate='0x1467d0c60',
                candidate_count=len(discovery['handler_candidates']), alignment=str(path),
                alignment_sha256=ALIGNMENT, semantic_verification=False)


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify(discovery, exports, root):
    if discovery['source_sha256'] != SOURCE or discovery['reader'] != '0x1456dc140':
        raise ValueError('Explicit current reader scope required')
    d = load('discover-login-result-11320')
    for path, sha in discovery['inputs'].items():
        if d.digest(path) != sha:
            raise ValueError('Reader discovery input changed')
    context = dict(source_sha256=SOURCE, source=str(Path(root) / 'client-code-snapshots' / SOURCE / 'ProjectRED-Win64-Shipping.exe'),
                   helpers=dict(memcpy='0x1487f8c59'), verify_whole_exports=True)
    h = load('update-native-harness').make_harness(context, exports, {0x1456dc140}, root=Path(root))
    actual = load('update-bindings').rows(load('build-native-entry-code'), h.image, 0x1456dc140)
    calls = [r for r in actual if r['call']]
    operations = discovery['operations']
    if len(calls) != len(operations) or not 1 <= len(calls) <= 64:
        raise ValueError('Reader call coverage differs')
    offsets, targets = [], []
    packet, archive, table = [h.scratch + n for n in (0x1000, 0x2000, 0x3000)]
    virtual = {}
    for call, op in zip(calls, operations):
        target = hex(call['direct_target']) if call['direct_target'] is not None else call['operands']
        if (hex(call['address']), target) != (op['address'], op['target']):
            raise ValueError('Reader call identity differs')
        match = re.fullmatch(r'rdx, \[(?:rdi|rcx) \+ (0x[0-9a-f]+)\]', op['destination'])
        if not match:
            raise ValueError('Unclassified reader destination')
        offset = int(match[1], 16)
        if not 0x10 <= offset < 0x160:
            raise ValueError('Reader destination bound')
        offsets.append(offset)
        if call['direct_target'] is None:
            match = re.fullmatch(r'qword ptr \[rax \+ (0x[0-9a-f]+)\]', target)
            if not match:
                raise ValueError('Unreviewed reader indirect call')
            slot = int(match[1], 16)
            if slot not in (0x50, 0x58, 0x60, 0x70, 0x88):
                raise ValueError('Unreviewed archive slot')
            virtual[slot] = h.scratch + 0x6000 + slot
            targets.append(virtual[slot])
        else:
            targets.append(call['direct_target'])
    state = {}

    def reg(name):
        return h.uc.reg_read(getattr(h.x, 'UC_X86_REG_' + name))

    def fixture(at):
        def execute(machine):
            i = len(state['seen'])
            if i >= len(offsets) or targets[i] != at or reg('RCX') != archive or reg('RDX') != packet + offsets[i]:
                raise ValueError('Reader operation order/receiver/destination differs')
            state['seen'].append(i)
            if state['fail_at'] == i:
                h.finish(0)
                return
            value = (i + 1) & 255
            h.uc.mem_write(packet + offsets[i], bytes([value]))
            state['expected'][offsets[i]] = value
            h.finish(state['truthy'])
        return execute

    for at in set(targets):
        h.add_fixture(at, fixture(at))
    for slot, at in virtual.items():
        h.uc.mem_write(table + slot, struct.pack('<Q', at))
    h.uc.mem_write(archive - 16, b'\xa5' * 16 + struct.pack('<Q', table) + b'\xa6' * 16)
    archive_guard = bytes(h.uc.mem_read(archive - 16, 40))
    abi = {n: 0xfedcba9876543210 + i for i, n in enumerate(('RBX', 'RSI', 'RDI', 'RBP', 'R12', 'R13', 'R14', 'R15'))}
    cases = []
    for poison in (0x55, 0xaa):
        for truthy in (1, 0x101):
            for fail_at in [None] + list(range(len(offsets))):
                state.clear()
                state.update(seen=[], expected=bytearray([poison] * 0x160), fail_at=fail_at, truthy=truthy)
                h.uc.mem_write(packet - 16, b'\xa5' * 16 + bytes(state['expected']) + b'\xa6' * 16)
                for name, value in abi.items():
                    h.uc.reg_write(getattr(h.x, 'UC_X86_REG_' + name), value)
                h.uc.reg_write(h.x.UC_X86_REG_RDX, archive)
                result = h.call(0x1456dc140, packet) & 255
                expected_seen = len(offsets) if fail_at is None else fail_at + 1
                if result != int(fail_at is None) or state['seen'] != list(range(expected_seen)):
                    raise ValueError('Reader return/short circuit differs')
                expected = b'\xa5' * 16 + bytes(state['expected']) + b'\xa6' * 16
                if bytes(h.uc.mem_read(packet - 16, len(expected))) != expected:
                    raise ValueError('Reader memory/guards differ')
                if bytes(h.uc.mem_read(archive - 16, 40)) != archive_guard or any(reg(n) != v for n, v in abi.items()):
                    raise ValueError('Reader archive/ABI guards differ')
                cases.append(dict(poison=poison, truthy=truthy, fail_at=fail_at, operations=expected_seen, guards=True))
    return dict(schema=1, source_sha256=SOURCE, reader='0x1456dc140', operations=operations, cases=cases,
                handler_link=resolve_handler(discovery, root),
                exports=exports, runtime=load('update-native-harness').runtime_inputs(), network_used=False,
                profile_activated=False, runtime_activated=False,
                limits=['Opaque archive/string/nested dispatch fixtures write one sentinel byte per successful operation.',
                        'No constructor, nested data layout, wire decoding, handler or full contract claim.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--discovery', required=True, type=Path)
    parser.add_argument('--export', required=True, type=Path)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    discovery = json.loads(args.discovery.read_bytes())
    d = load('discover-login-result-11320')
    if d.digest(args.discovery) != args.discovery.parent.name:
        raise ValueError('Discovery content identity differs')
    exports = {args.export.parent.name: d.digest(args.export)}
    result = verify(discovery, exports, args.root)
    result['inputs'] = {str(args.discovery): d.digest(args.discovery), str(HERE / 'verify-login-reader-flow-11320.py'): d.digest(__file__)}
    path = load('research-workflow').snapshot(args.root, 'login-reader-flow-11320', result)
    print(json.dumps(dict(report=str(path), sha256=d.digest(path), cases=len(result['cases']))))
