"""Whole current lobby reader/handler with explicit archive and metadata fixtures."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/lobby-version-result-11322.json'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def payload(code, flag, first, second, offset, text, left, right):
    data = text.encode('utf-8')
    return struct.pack('<IBQQHH', code, flag, first, second, offset, len(data)) + data + struct.pack('<II', left, right)


def verify(context_path=CONTEXT, *, root=ROOT):
    context_path, root = Path(context_path), Path(root)
    context = json.loads(context_path.read_bytes())
    if (context.get('schema') != 1 or context.get('recipe') != 'lobby-version-result-current-v1'
            or context.get('source_sha256') != '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'):
        raise ValueError('Current lobby source context differs')
    roles = {key: int(value, 16) for key, value in context['functions'].items()}
    if set(roles) != {'constructor', 'reader', 'handler'}:
        raise ValueError('Lobby whole-root roles differ')
    leaves = {int(key, 16): value for key, value in context['leaves'].items()}
    h = load('native-request-harness-11316').make_harness(context['exports'], set(roles.values()),
        leaves=leaves, root=root, source_sha256=context['source_sha256'], copy_thunk=None)
    uc, x = h.uc, h.x
    direct = {name: int(address, 16) for name, address in context['fixtures'].items()}
    expected_calls = set(direct.values()) | set(leaves)
    # Source bytes are checked by the harness, including every whole export.
    for fragment in h.fragments:
        for row in fragment['instructions']:
            text = row['text']
            if text.startswith(('CALL 0x', 'JMP 0x')):
                target = int(text.split()[-1], 16)
                if target not in expected_calls and not any(int(f['address'], 16) == target for f in h.fragments):
                    # Intraprocedural branches remain in each source-checked whole body.
                    if not any(int(r['address'], 16) == target for r in fragment['instructions']):
                        raise ValueError('Unreviewed lobby direct target ' + hex(target))
    packet, archive, table, text_buffer, clock, manager = [h.scratch + value for value in
        (0x1000, 0x2000, 0x3000, 0x4000, 0x9000, 0xa000)]
    vtable = int(context['packet_table'], 16)
    off = h.image.offset(vtable - h.image.pe.base)
    if h.raw[off:off + len(bytes.fromhex(context['packet_table_bytes']))].hex() != context['packet_table_bytes']:
        raise ValueError('Lobby packet table changed')
    state, events = {}, []
    primitive = {name: h.scratch + 0xd000 + 0x10 * index for index, name in enumerate(('u32', 'bool', 'u16'))}
    uc.mem_write(table + 0x58, struct.pack('<Q', primitive['u32']))
    uc.mem_write(table + 0x60, struct.pack('<Q', primitive['u32']))
    uc.mem_write(table + 0x70, struct.pack('<Q', primitive['u16']))
    uc.mem_write(table + 0x88, struct.pack('<Q', primitive['bool']))
    uc.mem_write(archive, struct.pack('<Q', table))

    def invoke(at, a=0, b=0, c=0, d=0):
        for register, value in ((x.UC_X86_REG_RDX, b), (x.UC_X86_REG_R8, c), (x.UC_X86_REG_R9, d)):
            uc.reg_write(register, value)
        return h.call(at, a)

    def read(name, receiver, target):
        if receiver != archive or not packet + 0x10 <= target <= packet + 0x54:
            raise ValueError('Archive fixture receiver or packet destination differs')
        state['read_count'] += 1
        count = state['read_count']
        events.append(dict(operation=name, destination=target - packet))
        if state.get('failure') == count:
            h.finish(0); return
        body, cursor = state['body'], state['cursor']
        width = {'u32': 4, 'bool': 1, 'u16': 2, 'time': 8}.get(name)
        if name == 'string':
            if cursor + 2 > len(body):
                h.finish(0); return
            size = struct.unpack_from('<H', body, cursor)[0]
            if cursor + 2 + size > len(body):
                h.finish(0); return
            encoded = body[cursor + 2:cursor + 2 + size]
            text = encoded.decode('utf-8')
            raw = text.encode('utf-16-le') + b'\0\0'
            if len(raw) > 4096:
                raise ValueError('Fixture string exceeds explicit conversion budget')
            uc.mem_write(text_buffer, raw)
            uc.mem_write(target, struct.pack('<QII', text_buffer, len(raw) // 2, len(raw) // 2))
            width = 2 + size
        else:
            if cursor + width > len(body):
                h.finish(0); return
            raw = body[cursor:cursor + width]
            if name == 'bool': raw = bytes((int(bool(raw[0])),))
            uc.mem_write(target + (8 if name == 'time' else 0), raw)
        state['cursor'] += width
        h.finish(1)

    for name, address in primitive.items():
        h.add_fixture(address, lambda machine, name=name:
            read(name, machine.reg_read(x.UC_X86_REG_RCX), machine.reg_read(x.UC_X86_REG_RDX)))

    def fixture(machine):
        at = machine.reg_read(x.UC_X86_REG_RIP)
        a, b, c, d = [machine.reg_read(register) for register in
            (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        if at == direct['time_read']:
            read('time', a, b); return
        if at == direct['string_read']:
            read('string', a, b); return
        if at == direct['time_constructor']:
            uc.mem_write(a, b'\0' * 16)
        elif at == direct['string_constructor']:
            uc.mem_write(a, b'\0' * 16)
        elif at == direct['ui_manager']:
            h.finish(manager); return
        elif at == direct['ui_owner']:
            h.finish(0); return
        elif at == direct['ui_action']:
            raise ValueError('UI action is outside this explicit manager-state fixture')
        elif at == direct['metadata_validate']:
            events.append(dict(operation='metadata_validate', pointer=a - packet, second=b, raw_50=c, raw_54=d))
            h.finish(state['metadata_valid']); return
        elif at == direct['metadata_apply']:
            events.append(dict(operation='metadata_apply', packet_string=a == packet + 0x40,
                               blank=bytes(uc.mem_read(a, 16)) == b'\0' * 16))
        elif at == direct['peer_manager']:
            h.finish(manager); return
        elif at == direct['peer_time']:
            events.append(dict(operation='peer_time', receiver=a == manager, first=b))
        elif at == direct['free']:
            events.append(dict(operation='free'))
        else:
            raise ValueError('Unknown current lobby fixture')
        h.finish(0)
    for address in direct.values():
        h.add_fixture(address, fixture)
    clock_global = int(context['clock_global'], 16)
    uc.mem_write(clock_global, struct.pack('<Q', clock))
    uc.mem_write(manager + 0x28, struct.pack('<I', 2))
    expected_order = [('u32', 0x10), ('bool', 0x14), ('time', 0x18), ('time', 0x28),
                      ('u16', 0x38), ('string', 0x40), ('u32', 0x50), ('u32', 0x54)]
    cases, prefix_cases, failure_cases, handler_cases = [], [], [], []
    for text in ('', 'fixture', 'Ж♥猫'):
        body = payload(0, 255, 0x1020304050607080, 1792600142863, 540, text, 0x89abcdef, 0xffffffff)
        uc.mem_write(packet - 16, b'\xa5' * 0x90)
        invoke(roles['constructor'], packet)
        if (int.from_bytes(uc.mem_read(packet, 8), 'little') != vtable
                or bytes(uc.mem_read(packet + 0x40, 24)) != b'\0' * 24):
            raise ValueError('Whole current constructor fields differ')
        events.clear(); state.update(body=body, cursor=0, read_count=0, failure=None)
        accepted = invoke(roles['reader'], packet, archive) & 255
        if accepted != 1 or state['cursor'] != len(body):
            raise ValueError('Whole current reader failed complete payload')
        if [(e['operation'], e['destination']) for e in events] != expected_order:
            raise ValueError('Native reader field order differs')
        pointer, count, capacity = struct.unpack('<QII', bytes(uc.mem_read(packet + 0x40, 16)))
        decoded = bytes(uc.mem_read(pointer, (count - 1) * 2)).decode('utf-16-le')
        if decoded != text or struct.unpack('<II', bytes(uc.mem_read(packet + 0x50, 8))) != (0x89abcdef, 0xffffffff):
            raise ValueError('New current reader destinations differ')
        if bytes(uc.mem_read(packet - 16, 16)) != b'\xa5' * 16 or bytes(uc.mem_read(packet + 0x58, 24)) != b'\xa5' * 24:
            raise ValueError('Current reader/constructor guard changed')
        cases.append(dict(payload_hex=body.hex(), text=text, consumed=state['cursor'], operations=list(events)))
        for size in range(len(body)):
            events.clear(); state.update(body=body[:size], cursor=0, read_count=0, failure=None)
            if invoke(roles['reader'], packet, archive) & 255:
                raise ValueError('Native reader accepted short prefix')
            prefix_cases.append(dict(text=text, size=size, consumed=state['cursor'], operations=len(events)))
        for stage in range(1, 9):
            events.clear(); state.update(body=body, cursor=0, read_count=0, failure=stage)
            if invoke(roles['reader'], packet, archive) & 255 or len(events) != stage:
                raise ValueError('Native reader failed to gate subsequent operations')
            failure_cases.append(dict(text=text, failing_operation=stage, operations=len(events)))
        # Restore the complete packet for whole handler forwarding checks.
        state.update(body=body, cursor=0, read_count=0, failure=None)
        invoke(roles['reader'], packet, archive)
        for valid in (0, 1):
            events.clear(); state['metadata_valid'] = valid
            uc.mem_write(clock, b'\0' * 80)
            invoke(roles['handler'], 0, 0, packet)
            validate = next(e for e in events if e['operation'] == 'metadata_validate')
            apply = next(e for e in events if e['operation'] == 'metadata_apply')
            peer = next(e for e in events if e['operation'] == 'peer_time')
            if (validate['pointer'], validate['second'], validate['raw_50'], validate['raw_54']) != (0x40, 1792600142863, 0x89abcdef, 0xffffffff):
                raise ValueError('Current handler new metadata arguments differ')
            if apply['packet_string'] != bool(valid) or apply['blank'] != (not valid):
                raise ValueError('Current handler metadata validation branch differs')
            if peer != dict(operation='peer_time', receiver=True, first=0x1020304050607080):
                raise ValueError('Current handler first time forwarding differs')
            ticks = struct.unpack('<qq', bytes(uc.mem_read(clock + 32, 16)))
            if ticks != (17926001428630000,) * 2:
                raise ValueError('Current native clock setter differs')
            handler_cases.append(dict(text=text, metadata_valid=bool(valid), events=list(events), server_ticks=ticks))
    inputs = {str(context_path.resolve()): digest(context_path), str(Path(__file__).resolve()): digest(__file__),
              str(h.source.resolve()): h.sha,
              str(HERE / 'native-request-harness-11316.py'): digest(HERE / 'native-request-harness-11316.py'),
              str(HERE / 'build-native-entry-code.py'): digest(HERE / 'build-native-entry-code.py')}
    for item in h.evidence: inputs[item['path']] = item['sha256']
    if any(digest(path) != expected for path, expected in inputs.items()):
        raise ValueError('Current lobby inputs changed during native verification')
    report = dict(schema=1, recipe=context['recipe'], source_sha256=context['source_sha256'],
        context=dict(path=str(context_path.resolve()), sha256=digest(context_path)), inputs=inputs,
        cases=cases, prefix_cases=prefix_cases, failure_cases=failure_cases, handler_cases=handler_cases,
        native_execution=True, network_used=False, runtime_admitted=False,
        runtime_versions=dict(capstone='5.0.6', unicorn='2.1.4'),
        limits=['Whole current packet constructor, reader, handler and bounded native clock setter execute.',
                'Archive scalar, TimeBase and string conversion are explicit inherited-interface fixtures; new full wire primitive execution is not claimed.',
                'Metadata validation/application, managers, allocation/free and peer continuation remain fixtures; UI manager state is explicitly 2.',
                'Exact-length/strict UTF-8 portable policy is narrower than the native packet reader; no lobby/game session admission.'])
    path = load('audit-client-release').save_snapshot(root / 'code-clues/lobby-version-result-current-v1', report)
    return dict(report=str(path), sha256=digest(path), cases=len(cases), prefixes=len(prefix_cases),
                failure_gates=len(failure_cases), handler_cases=len(handler_cases))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, default=CONTEXT)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    print(json.dumps(verify(args.context, root=args.root)))
