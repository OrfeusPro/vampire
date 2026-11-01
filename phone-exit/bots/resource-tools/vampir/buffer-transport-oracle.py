"""Independent bytearray oracle; never fills or controls native replay memory."""
import copy
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CONTRACT = load('buffer-transport-case-contracts')


def expected_case(spec):
    CONTRACT.validate_spec(spec)
    mode, initial = spec['mode'], spec['initial']
    original = bytes.fromhex(initial['payload_hex'])
    capacity = initial['capacity']
    raw = original + (b'\0' if initial['sentinel'] else b'')
    size = capacity if mode == 'archive' else len(raw)
    storage = bytearray(b'\x5a' * capacity)
    storage[:len(raw)] = raw
    cursor = count = len(original)
    archive_capacity = capacity
    last_count = 0
    observations = []
    for step in spec['steps']:
        calls = dict.fromkeys(CONTRACT.CALL_KEYS, 0)
        events = []
        pointer_changed = False

        def resize(requested):
            nonlocal size, capacity, storage, pointer_changed
            calls['resize'] += 1
            if requested > capacity:
                calls['grow'] += 1
                old_size, old_capacity, old_storage = size, capacity, storage
                capacity = max(requested, old_capacity + old_capacity // 2)
                storage = bytearray(b'\x5a' * capacity)
                events.append(dict(kind='allocate', size=capacity + (39 if capacity >= 4096 else 0)))
                events.append(dict(kind='memset', size=requested - old_size))
                storage[old_size:requested] = bytes(requested - old_size)
                events.append(dict(kind='memmove', size=old_size))
                storage[:old_size] = old_storage[:old_size]
                if old_capacity:
                    events.append(dict(kind='free', size=old_capacity + (39 if old_capacity >= 4096 else 0)))
                pointer_changed = True
            elif requested > size:
                events.append(dict(kind='memset', size=requested - size))
                storage[size:requested] = bytes(requested - size)
            size = requested

        if mode == 'resize':
            resize(step['requested_size'])
        else:
            payload = bytes.fromhex(step['payload_hex'])
            n = len(payload)
            if mode in ('append', 'transport'):
                calls['append'] = 1
                calls['transport'] = int(mode == 'transport')
                old_size = size
                resize(n + 1 if old_size == 0 else old_size + n)
                at = 0 if old_size == 0 else old_size - 1
                events.append(dict(kind='memcpy', size=n))
                storage[at:at + n] = payload
                storage[size - 1] = 0
                if mode == 'transport' and step['state'] == 1 and step['busy'] == 0:
                    events.append(dict(kind='wake'))
            elif mode == 'archive':
                calls['archive_raw'] = 1
                if n:
                    if archive_capacity - cursor < n:
                        archive_capacity = archive_capacity or 512
                        while True:
                            archive_capacity *= 2
                            if archive_capacity - cursor >= n:
                                break
                        resize(archive_capacity)
                    events.append(dict(kind='memcpy', size=n))
                    storage[cursor:cursor + n] = payload
                    cursor += n
                    count += n
                    calls['set_count'] = 1
                    last_count = n
            else:
                raise ValueError('Buffer transport oracle mode differs')
        archive = None if mode != 'archive' else dict(capacity=archive_capacity,
            cursor=cursor, count=count, flags_bits=initial['flags_bits'], last_count=last_count,
            payload_hex=bytes(storage[:count]).hex())
        observations.append(dict(size=size, capacity=capacity, payload_hex=bytes(storage[:size]).hex(),
            spare_hex=bytes(storage[size:capacity]).hex(), pointer_changed=pointer_changed,
            return_al=None if mode == 'resize' else 1, calls=calls, events=events, archive=archive,
            wake_arguments_checked=True if any(e['kind'] == 'wake' for e in events) else None))
    return dict(spec=copy.deepcopy(spec), observation=dict(steps=observations,
        guards=True, abi=True, source_immutable=True, ownership_checked=True))


def validate_case(actual, spec):
    expected = expected_case(spec)
    try:
        if CONTRACT.canonical(actual) != CONTRACT.canonical(expected):
            raise ValueError('Buffer transport actual case differs')
    except (TypeError, ValueError) as error:
        raise ValueError('Buffer transport actual case differs') from error
    return actual
