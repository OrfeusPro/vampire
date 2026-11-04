"""Bounded QuestUpdate1810 writer, mirror reader and explicit writer failures."""
import struct

VECTORS = ((0., 0., 0.), (1., -2.5, 3.25),
           (-0., 1.1754943508222875e-38, 3.4028234663852886e38),
           (90049., 151840., -44.))
KEYS = (0, 1, 110120, 0x8000000000000000, 0xffffffffffffffff)
FLAGS = (0, 1, 2, 255)
WIDTHS = (4, 4, 4, 8, 8, 1)


def values():
    for vector in VECTORS:
        for key in KEYS:
            for flag in FLAGS:
                yield vector, key, key ^ 0xffffffffffffffff, flag
    yield VECTORS[-1], 0, 110120, 0


def expected_cases():
    valid = []
    for index, (vector, key, other, flag) in enumerate(values()):
        body = struct.pack('<fffQQB', *vector, key, other, flag)
        projected = struct.pack('<dddQQB', *struct.unpack('<fffQQB', body))
        valid.append(dict(index=index, body_hex=body.hex(), mirror_hex=projected.hex()))
    return dict(valid=valid,
        prefixes=[dict(size=size, accepted=False, consumed=size) for size in range(29)],
        trailing=[dict(size=31, accepted=True, consumed=29)],
        failures=[dict(index=index, accepted=False, widths=list(WIDTHS[:index + 1])) for index in range(6)])


def verify(harness, context, root, source_store):
    functions = {name: int(address, 16) for name, address in context['functions'].items()}
    leaves = {int(address, 16): body for address, body in context['leaves'].items()}
    packet_table = int(context['packet_table'], 16)
    output_table = int(context['output_table'], 16)
    input_table = int(context['input_table'], 16)
    bindings = {(int(table, 16), int(slot, 16)): int(target, 16) for table, slot, target in context['bindings']}
    getter = bindings[packet_table, 0x28]
    constructors = [address for address, raw in leaves.items()
                    if bytes.fromhex(raw).startswith(b'\x48\x8d\x05')
                    and address + 7 + int.from_bytes(bytes.fromhex(raw)[3:7], 'little', signed=True) == packet_table]
    if len(constructors) != 1:
        raise ValueError('QuestUpdate packet constructor leaf is missing or ambiguous')
    constructor = constructors[0]

    def make(scope):
        current = dict(context, execution_scope=scope)
        roots = set(functions.values())
        if scope == 'raw_failure':
            roots.remove(functions['output_raw'])
        h = harness.make_harness(current, current['exports'], roots, leaves, root, source_store=source_store)
        for role, address in context['fixtures'].items():
            address = int(address, 16)
            if address not in h.available_fixtures or role == 'memcpy':
                continue
            def rejected(machine, role=role):
                raise ValueError('QuestUpdate excluded fixture reached: ' + role)
            h.add_fixture(address, rejected)
        return h

    h = make('whole_io')
    packet, output, buffer, archive, source = [h.scratch + offset for offset in (0x1000, 0x2000, 0x3000, 0x4000, 0x5000)]

    def number(machine, address, size=8):
        return int.from_bytes(machine.uc.mem_read(address, size), 'little')

    def construct(machine):
        machine.uc.mem_write(packet - 16, b'\xa1' * 16 + b'\xa5' * 64 + b'\xa2' * 16)
        if (machine.call(constructor, packet) != packet or number(machine, packet) != packet_table
                or machine.call(getter, packet) != 1810):
            raise ValueError('QuestUpdate constructor / packet ID differs')
        if bytes(machine.uc.mem_read(packet + 0x10, 24)) != b'\xa5' * 24:
            raise ValueError('QuestUpdate constructor changed vector defaults')
        if bytes(machine.uc.mem_read(packet + 0x28, 17)) != bytes(17):
            raise ValueError('QuestUpdate constructor changed scalar defaults')

    def output_reset(machine):
        machine.uc.mem_write(output - 16, b'\xb1' * 16 + b'\xcc' * 64 + b'\xb2' * 16)
        if machine.call(functions['output_constructor'], output, rdx=1) != output or number(machine, output) != output_table:
            raise ValueError('QuestUpdate OUTPUT constructor differs')
        machine.uc.mem_write(output + 0x18, struct.pack('<QQQ', buffer, buffer, buffer + 128))
        machine.uc.mem_write(output + 0x30, struct.pack('<III', 128, 0, 0))
        machine.uc.mem_write(buffer - 16, b'\xc1' * 16 + b'\x5a' * 128 + b'\xc2' * 16)

    def initial_regions(machine):
        machine.reset_regions()
        machine.allow_write(packet, 64)
        machine.allow_write(output, 64)
        machine.allow_write(buffer, 128)

    def input_read(body):
        h.uc.mem_write(archive - 16, b'\xd1' * 16 + bytes(64) + b'\xd2' * 16)
        h.allow_write(archive, 64)
        h.allow_read(source, len(body))
        h.call(functions['input_constructor'], archive)
        if number(h, archive) != input_table:
            raise ValueError('QuestUpdate unbuffered INPUT constructor differs')
        h.uc.mem_write(archive + 0x20, struct.pack('<QI', source, len(body)))
        h.uc.mem_write(archive + 0x30, struct.pack('<Q', source))
        h.uc.mem_write(source - 16, b'\xe1' * 16 + body + b'\xe2' * 16)
        accepted = bool(h.call(functions['reader'], packet, rdx=archive) & 255)
        consumed = number(h, archive + 0x30) - source
        if not 0 <= consumed <= len(body):
            raise ValueError('QuestUpdate mirror cursor exceeds the input')
        for address, expected in ((archive - 16, b'\xd1' * 16), (archive + 64, b'\xd2' * 16),
                                  (source - 16, b'\xe1' * 16 + body + b'\xe2' * 16),
                                  (packet - 16, b'\xa1' * 16), (packet + 64, b'\xa2' * 16)):
            if bytes(h.uc.mem_read(address, len(expected))) != expected:
                raise ValueError('QuestUpdate mirror guard or input bytes changed')
        return accepted, consumed

    actual_valid = []
    for index, (vector, key, other, flag) in enumerate(values()):
        initial_regions(h)
        construct(h)
        output_reset(h)
        h.uc.mem_write(packet + 0x10, struct.pack('<dddQQB', *vector, key, other, flag))
        before = bytes(h.uc.mem_read(packet - 16, 96))
        h.reset_regions()
        h.allow_read(packet, 64)
        h.allow_write(output, 64)
        h.allow_write(buffer, 128)
        if h.call(functions['writer'], packet, rdx=output) & 255 != 1:
            raise ValueError('QuestUpdate complete writer failed')
        body = struct.pack('<fffQQB', *vector, key, other, flag)
        if bytes(h.uc.mem_read(buffer - 16, 160)) != b'\xc1' * 16 + body + b'\x5a' * 99 + b'\xc2' * 16:
            raise ValueError('QuestUpdate writer bytes or output guard differ')
        if struct.unpack('<II', h.uc.mem_read(output + 0x34, 8)) != (29, 29):
            raise ValueError('QuestUpdate output counters differ')
        if bytes(h.uc.mem_read(packet - 16, 96)) != before:
            raise ValueError('QuestUpdate writer changed its source packet')
        if bytes(h.uc.mem_read(output - 16, 16)) != b'\xb1' * 16 or bytes(h.uc.mem_read(output + 64, 16)) != b'\xb2' * 16:
            raise ValueError('QuestUpdate OUTPUT archive guard changed')
        initial_regions(h)
        construct(h)
        if input_read(body) != (True, 29):
            raise ValueError('QuestUpdate complete mirror failed')
        projected = struct.pack('<dddQQB', *struct.unpack('<fffQQB', body))
        if bytes(h.uc.mem_read(packet + 0x10, 41)) != projected:
            raise ValueError('QuestUpdate mirror fields differ')
        actual_valid.append(dict(index=index, body_hex=body.hex(), mirror_hex=projected.hex()))
    prefixes = []
    for size in range(29):
        initial_regions(h)
        construct(h)
        accepted, consumed = input_read(bytes(size))
        if (accepted, consumed) != (False, size):
            raise ValueError('QuestUpdate truncated input accepted or incorrectly consumed')
        prefixes.append(dict(size=size, accepted=accepted, consumed=consumed))
    initial_regions(h)
    construct(h)
    accepted, consumed = input_read(bytes(29) + b'\xe3\x6c')
    if (accepted, consumed) != (True, 29):
        raise ValueError('QuestUpdate trailing-input behavior differs')
    trailing = [dict(size=31, accepted=accepted, consumed=consumed)]

    failing = make('raw_failure')
    fail_index = [0]
    widths = []
    def raw_failure(machine):
        width = machine.reg_read(failing.x.UC_X86_REG_R8)
        if width not in (1, 4, 8):
            raise ValueError('QuestUpdate raw failure width differs')
        accepted = len(widths) != fail_index[0]
        widths.append(width)
        failing.finish(int(accepted))
    failing.add_fixture(functions['output_raw'], raw_failure)
    failures = []
    for index in range(6):
        fail_index[0] = index
        widths.clear()
        initial_regions(failing)
        construct(failing)
        output_reset(failing)
        accepted = bool(failing.call(functions['writer'], packet, rdx=output) & 255)
        if accepted or widths != list(WIDTHS[:index + 1]):
            raise ValueError('QuestUpdate writer failed to stop on raw failure')
        failures.append(dict(index=index, accepted=accepted, widths=widths.copy()))
    cases = dict(valid=actual_valid, prefixes=prefixes, trailing=trailing, failures=failures)
    if cases != expected_cases():
        raise ValueError('QuestUpdate exact native case matrix differs')
    return dict(cases=cases, whole_io=h.validate(), raw_failure=failing.validate(),
                source_sha256=context['source_sha256'], packet_id=1810,
                network_used=False, runtime_activated=False, profile_activated=False)
