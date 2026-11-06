"""Execute current lobby metadata consumers; timezone/engine providers are fixtures."""
import argparse
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/lobby-metadata-11322.json'
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify(context_path=CONTEXT, *, root=ROOT):
    context_path, root = Path(context_path), Path(root)
    context = json.loads(context_path.read_bytes())
    if (context.get('recipe') != 'lobby-metadata-current-v1' or context.get('schema') != 1
            or context.get('source_sha256') != SOURCE):
        raise ValueError('Current lobby metadata context differs')
    roles = {key: int(value, 16) for key, value in context['functions'].items()}
    if set(roles) != {'validate', 'apply'}:
        raise ValueError('Metadata whole-root roles differ')
    h = load('native-request-harness-11316').make_harness(context['exports'], set(roles.values()),
        root=root, source_sha256=SOURCE, copy_thunk=None)
    normalizer, native = load('audit-launcher-shape-11318'), load('build-native-entry-code')
    for fragment in h.fragments:
        normalizer.normalize_function(native, h.image, fragment)
    uc, x = h.uc, h.x
    fixtures = {int(value, 16): key for key, value in context['fixtures'].items()}
    for fragment in h.fragments:
        addresses = {int(row['address'], 16) for row in fragment['instructions']}
        for row in fragment['instructions']:
            if row['text'].startswith(('CALL 0x', 'JMP 0x')):
                target = int(row['text'].split()[-1], 16)
                if target not in addresses | set(roles.values()) | set(fixtures):
                    raise ValueError('Unreviewed metadata direct call ' + hex(target))
    for literal in context['literals']:
        at = int(literal['address'], 16)
        expected = bytes.fromhex(literal['bytes'])
        offset = h.image.offset(at - h.image.pe.base)
        if h.raw[offset:offset + len(expected)] != expected:
            raise ValueError('Metadata source literal changed')
    state, events = {}, []
    arg, converted, formatted, service, intern = [h.scratch + offset for offset in
        (0x1000, 0x2000, 0x3000, 0x4000, 0x5000)]
    global_string, generation, zone_pointer = (int(context[key], 16) for key in
        ('global_string', 'generation', 'zone_pointer'))
    pools = [int(value, 16) for value in context['pools']]

    def alloc(data):
        at = state['arena']
        state['arena'] += (len(data) + 15) & ~15
        if not h.scratch + 0x8000 <= at < state['arena'] < h.scratch + 0x28000:
            raise ValueError('Metadata fixture arena budget exceeded')
        uc.mem_write(at, data)
        return at

    def ctext(pointer, wide=False):
        width = 2 if wide else 1
        data = bytearray()
        for index in range(256):
            unit = bytes(uc.mem_read(pointer + index * width, width))
            if unit == bytes(width):
                return data.decode('utf-16-le' if wide else 'utf-8')
            data.extend(unit)
        raise ValueError('Metadata fixture string exceeds finite budget')

    def put_wide(at, text):
        raw = (text + '\0').encode('utf-16-le')
        uc.mem_write(at, struct.pack('<QII', alloc(raw), len(raw) // 2, len(raw) // 2))

    def put_narrow(at, text):
        raw = text.encode('utf-8')
        if len(raw) <= 15:
            data = raw.ljust(16, b'\0')
            capacity = 15
        else:
            data = struct.pack('<Q', alloc(raw + b'\0')) + bytes(8)
            capacity = len(raw)
        uc.mem_write(at, data + struct.pack('<QQ', len(raw), capacity))

    def narrow(at):
        size, capacity = struct.unpack('<QQ', bytes(uc.mem_read(at + 16, 16)))
        pointer = at if capacity <= 15 else int.from_bytes(uc.mem_read(at, 8), 'little')
        return bytes(uc.mem_read(pointer, size)).decode('utf-8')

    def wide(at):
        pointer, size, capacity = struct.unpack('<QII', bytes(uc.mem_read(at, 16)))
        return '' if not size else bytes(uc.mem_read(pointer, (size - 1) * 2)).decode('utf-16-le')

    def fixture(machine):
        at = machine.reg_read(x.UC_X86_REG_RIP)
        name = fixtures[at]
        a, b, c, d = [machine.reg_read(register) for register in
            (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        events.append(name)
        result = 0
        if name == 'wide_to_narrow':
            text = ctext(b, wide=True)
            if text != state['text']:
                raise ValueError('Metadata input FString forwarding differs')
            uc.mem_write(a, bytes(0x90))
            uc.mem_write(a + 0x88, struct.pack('<Q', alloc(text.encode('utf-8') + b'\0')))
            result = a
        elif name == 'narrow_constructor':
            put_narrow(a, ctext(b)); result = a
        elif name == 'narrow_assign':
            if a != global_string:
                raise ValueError('Metadata global assignment target differs')
            put_narrow(a, bytes(uc.mem_read(b, c)).decode('utf-8')); result = a
        elif name == 'compare':
            left, right = bytes(uc.mem_read(a, c)), bytes(uc.mem_read(b, c))
            result = int(left != right)
        elif name == 'service':
            result = service
        elif name == 'wide_constructor':
            put_wide(a, ctext(b, wide=True)); result = a
        elif name == 'provider':
            if a != service or wide(c) != state['provider_literal']:
                raise ValueError('Metadata provider arguments differ')
            uc.mem_write(b, struct.pack('<QQ', service if state['provider'] else 0, 0)); result = b
        elif name == 'wide_allocate':
            if not 1 <= b <= 256 or c != 0:
                raise ValueError('Metadata wide allocation fixture bounds')
            uc.mem_write(a, struct.pack('<Q', alloc(bytes(b * 2))))
            uc.mem_write(a + 12, struct.pack('<I', b)); result = a
        elif name == 'copy':
            if c > 512 or not all(h.scratch <= p < h.scratch + 0x40000 - c for p in (a, b)):
                raise ValueError('Metadata copy fixture bounds')
            if c: uc.mem_write(a, bytes(uc.mem_read(b, c)))
            result = a
        elif name == 'match':
            result = int(state['prefix'] and b == int(context['literals'][1]['address'], 16))
        elif name == 'prepend':
            put_wide(a, ctext(b, wide=True) + wide(c)); result = a
        elif name == 'date':
            if b != 1970 or c != 1 or d != 1:
                raise ValueError('Metadata epoch constructor arguments differ')
            uc.mem_write(a, struct.pack('<q', state['epoch_ticks'])); result = a
        elif name == 'format':
            if state['operation'] == 'validate':
                ticks = int.from_bytes(uc.mem_read(b, 8), 'little', signed=True)
                expected = state['epoch_ticks'] + (abs(state['time']) // 1000) * (1 if state['time'] >= 0 else -1) * 10000000
                if ticks != expected:
                    raise ValueError('Metadata native milliseconds division differs')
            uc.mem_write(a, bytes(16)); result = a
        elif name == 'format_text':
            put_wide(formatted, 'bounded-format'); result = formatted
        elif name == 'find_error':
            if c != 11:
                raise ValueError('Metadata error sentinel width differs')
            result = 0 if state['format_error'] else 0xffffffff
        elif name == 'offset':
            call_index = state['offset_calls']
            state['offset_calls'] += 1
            expected_time = state['offset_base'] + (0x39ef8b000 if state['operation'] == 'validate' else 0x3a9456800) * call_index
            expected_name = state['text']
            if ctext(a) != expected_name or b != (expected_time & 0xffffffffffffffff):
                raise ValueError('Metadata offset provider forwarding differs: ' + repr(
                    (ctext(a), expected_name, b, expected_time, call_index)))
            delta = state['deltas'][call_index] * 1000
            signed_time = b if b < 1 << 63 else b - (1 << 64)
            uc.mem_write(c, struct.pack('<q', signed_time + delta))
            result = int(state['offset_fail'] != call_index)
        elif name == 'intern':
            if a != int(context['intern_manager'], 16) or narrow(c) != state['text']:
                raise ValueError('Metadata intern input differs')
            put_narrow(intern + 0x20, state['text'])
            uc.mem_write(b, struct.pack('<Q', intern)); result = b
        elif name == 'narrow_to_wide':
            uc.mem_write(a, bytes(0x110))
            uc.mem_write(a + 0x108, struct.pack('<Q', alloc((ctext(b) + '\0').encode('utf-16-le'))))
            result = a
        elif name == 'now':
            uc.mem_write(a, struct.pack('<q', 123)); result = a
        elif name == 'seconds':
            result = state['now_seconds']
        elif name.startswith('pool_'):
            if a not in pools + [p + 16 for p in pools] or ('resize' in name and b != 0):
                raise ValueError('Metadata cache reset arguments differ')
        elif name == 'log':
            pass
        elif name == 'cookie':
            result = machine.reg_read(x.UC_X86_REG_RAX)
        elif name in ('free', 'narrow_free'):
            pass
        else:
            raise ValueError('Unreviewed metadata fixture ' + name)
        h.finish(result)

    for address in fixtures:
        h.add_fixture(address, fixture)

    def reset(text, **options):
        state.clear()
        state.update(text=text, arena=h.scratch + 0x8000, provider=True, prefix=False,
            provider_literal=context['literals'][0]['text'], operation='validate',
            time=1792600142863, epoch_ticks=621355968000000000, deltas=(0, 0),
            offset_base=1792600142863, offset_calls=0, offset_fail=-1,
            format_error=False, now_seconds=1792600142)
        state.update(options)
        uc.mem_write(h.scratch + 0x30000, bytes(0x8000))
        put_wide(arg, text)
        events.clear()

    def call(role, b=0, c=0, d=0):
        for register, value in ((x.UC_X86_REG_RDX, b), (x.UC_X86_REG_R8, c), (x.UC_X86_REG_R9, d)):
            uc.reg_write(register, value & 0xffffffffffffffff)
        return h.call(roles[role], arg) & 255

    validation_cases, apply_cases = [], []
    offsets = (-2147483648, -3600, 0, 3600, 2147483647)
    for left, right, text in itertools.product(offsets, offsets, ('fixture', 'fixture-long-zone-name')):
        for failure in ('none', 'provider', 'format', 'first', 'second', 'left', 'right'):
            expected = failure == 'none'
            deltas = (left + (failure == 'left'), right + (failure == 'right'))
            reset(text, provider=failure != 'provider', format_error=failure == 'format',
                offset_fail={'first': 0, 'second': 1}.get(failure, -1), deltas=deltas)
            accepted = bool(call('validate', state['time'], left & 0xffffffff, right & 0xffffffff))
            if accepted != expected:
                raise ValueError('Metadata native validation mismatch: ' + failure)
            validation_cases.append(dict(left=left, right=right, long_name=len(text) > 15,
                failure=failure, accepted=accepted, offset_calls=state['offset_calls']))
    for time, prefix in itertools.product((-1792600142863, 0, 999, 1000, 1792600142863), (False, True)):
        reset('fixture', time=time, offset_base=time, prefix=prefix)
        if not call('validate', time):
            raise ValueError('Native metadata signed time / normalization case failed')
        validation_cases.append(dict(time=time, prefix=prefix, accepted=True))
    for left, right in ((0, 0), (0xffffffff, 0x80000000)):
        reset('')
        if not call('validate', state['time'], left, right) or 'provider' in events:
            raise ValueError('Empty metadata must avoid provider and succeed')
        validation_cases.append(dict(empty=True, accepted=True, events=list(events)))

    for previous, text, capacity, old_count in itertools.product(
            ('', 'old', 'fixture', 'fixture-long-zone-name'),
            ('', 'fixture', 'fixture-long-zone-name'), (1, 2), (0, 7)):
        reset(text, operation='apply', offset_base=1792600142000)
        uc.mem_write(global_string, bytes(0xd0))
        put_narrow(global_string, previous)
        uc.mem_write(generation, struct.pack('<I', 41))
        uc.mem_write(zone_pointer, struct.pack('<Q', 0x11223344))
        for pool in pools:
            uc.mem_write(pool, bytes(0x50))
            for offset, value in ((8, 99), (12, old_count), (0x28, 99), (0x2c, 129), (0x48, capacity)):
                uc.mem_write(pool + offset, struct.pack('<I', value))
        call('apply')
        changed = previous != text
        if narrow(global_string) != text or int.from_bytes(uc.mem_read(generation, 4), 'little') != 41 + changed:
            raise ValueError('Native metadata apply identity/generation mismatch')
        target = int.from_bytes(uc.mem_read(zone_pointer, 8), 'little')
        intern_pointer = (int.from_bytes(uc.mem_read(intern + 0x20, 8), 'little')
                          if len(text.encode('utf-8')) > 15 else intern + 0x20)
        if target != (0x11223344 if not changed else (intern_pointer if text else 0)):
            raise ValueError('Native metadata cached zone pointer mismatch')
        if changed:
            for pool in pools:
                for offset, expected in ((8, 0), (0x28, 0), (0x2c, 128), (0x30, 0xffffffff), (0x34, 0)):
                    if int.from_bytes(uc.mem_read(pool + offset, 4), 'little') != expected:
                        raise ValueError('Native metadata reset field mismatch')
        elif any(name.startswith('pool_') for name in events):
            raise ValueError('Unchanged metadata unexpectedly reset caches')
        apply_cases.append(dict(previous=previous, text=text, capacity=capacity, old_count=old_count,
            changed=changed, events=list(events), offset_calls=state['offset_calls']))
    inputs = {str(path.resolve()): digest(path) for path in
        (context_path, Path(__file__), HERE / 'native-request-harness-11316.py',
         HERE / 'audit-launcher-shape-11318.py',
         HERE / 'knowledge-index.py', HERE / 'extract-native-enums.py', HERE / 'requirements-native.txt',
         HERE / 'build-native-entry-code.py', HERE / 'audit-client-release.py')}
    inputs[str(h.source.resolve())] = h.sha
    inputs.update({row['path']: row['sha256'] for row in h.evidence})
    if any(digest(path) != sha for path, sha in inputs.items()):
        raise ValueError('Metadata inputs changed during verification')
    report = dict(schema=1, recipe=context['recipe'], source_sha256=SOURCE, inputs=inputs,
        validation_cases=validation_cases, apply_cases=apply_cases, native_execution=True,
        runtime_admitted=False, network_used=False,
        runtime_versions=dict(capstone='5.0.6', unicorn='2.1.4'),
        limits=['Whole validation/apply bodies execute; scalar comparisons, sign extension, time division, cache generation and reset writes are native.',
            'Unicode/string allocation, service/format/timezone providers, date/now, pool internals, logging and frees are explicit bounded fixtures.',
            'Offset-provider data is synthetic. No actual timezone database, operating-system timezone, active engine state, lobby connection or world admission is proven.',
            'Raw packet fields remain raw in the public decoder; fixture names do not assign protocol meaning.'])
    path = load('audit-client-release').save_snapshot(root / 'code-clues/lobby-metadata-current-v1', report)
    return dict(report=str(path), sha256=digest(path), validation_cases=len(validation_cases), apply_cases=len(apply_cases))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, default=CONTEXT)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    print(json.dumps(verify(args.context, root=args.root)))
