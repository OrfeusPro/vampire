"""Bounded native receive and dispatch scenarios for QuestUpdateResult 1811."""
from itertools import product
import struct

WIRE = struct.Struct('<IQBBQQ')
FIELDS = ((0x10, 4), (0x18, 8), (0x20, 1), (0x30, 1), (0x38, 8), (0x40, 8))
SLOTS = (0x58, 0x50, 0x78, 0x80, 0x50, 0x50)
SIZES = (4, 8, 1, 1, 8, 8)
SAMPLE = (0, 110120, 2, 0, 0, 0)


def wire_matrix():
    for value in product((0, 10, 0xffffffff), (0, 110120, 0xffffffffffffffff),
                         (0, 2, 6, 7, 255), (0, 5, 31, 32, 255), (0, 0xffffffffffffffff), (0, 123)):
        yield value, WIRE.size, 0
    for length in range(WIRE.size):
        yield SAMPLE, length, 0
    for failure in range(1, 7):
        yield SAMPLE, WIRE.size, failure


def expected_wire(value, length, failure):
    consumed, attempts = 0, []
    for index, (slot, size) in enumerate(zip(SLOTS, SIZES), 1):
        attempts.append(slot)
        if index == failure or consumed + size > length:
            break
        consumed += size
    accepted = consumed == WIRE.size
    decoded = list(value) if accepted else None
    if decoded is not None:
        decoded[2] = min(decoded[2], 6)
    return dict(input=list(value), length=length, failure=failure, consumed=consumed,
                attempts=attempts, accepted=accepted, decoded=decoded)


def application_matrix():
    return product((0, 10, 0xffffffff, 0x1197), (False, True), (False, True),
                   (110120, 0xffffffffffffffff), (0, 2, 6), (0, 5))


def expected_application(code, special, existing, key, state, index):
    accepted = code == 0 or (code == 0x1197 and not special)
    calls = ['error'] if not special and code else []
    if accepted:
        calls += ['project', 'lookup']
        calls += ['apply_existing'] if existing else ['wrap_key', 'apply_new']
    return dict(code=code, special=special, existing=existing, key=key, state=state,
                index=index, calls=calls, applies=accepted)


def run(index, root, context):
    roles = {name: int(address, 16) for name, address in context['roles'].items()}
    leaves = {int(address, 16): data for address, data in context['leaves'].items()}
    harness = index.extension('native-request-harness-11316')
    h = harness.make_harness(context['exports'], set(roles.values()), leaves=leaves,
                             root=root, source_sha256=context['source_sha256'], copy_thunk=None)
    native = index.extension('build-native-entry-code')
    bindings = index.extension('update-bindings')
    for export in h.fragments:
        address = int(export['address'], 16)
        if (export.get('block_coverage_complete') is not True or export.get('direct_flow_coverage_complete') is not True
                or index.missing_conditional_fallthroughs(export['instructions'])):
            raise ValueError(f'Quest reply export control flow differs at {address:#x}')
        # The reused gate contains a switch table inside its unwind range.
        # The harness checks every exported instruction against the exact EXE.
        if address == roles['gate']:
            continue
        try:
            expected = bindings.rows(native, h.image, address)
        except ValueError as error:
            raise ValueError(f'Quest reply unwind decode failed at {address:#x}') from error
        if [(int(row['address'], 16), row['bytes'].lower()) for row in export['instructions']] != [
                (row['address'], row['bytes'].lower()) for row in expected]:
            raise ValueError(f'Quest reply whole export differs at {address:#x}')

    def source_bytes(address, size):
        offset = h.image.offset(address - h.image.pe.base)
        return h.raw[offset:offset + size]

    def pointer_at(address):
        return int.from_bytes(source_bytes(address, 8), 'little')

    tables = context['tables']
    outer, inner, handler = (int(tables[name], 16) for name in ('outer', 'nested', 'handler'))
    if (pointer_at(outer + 0x20), pointer_at(outer + 0x28), pointer_at(inner + 0x20), pointer_at(handler + 0x10)) != (
            roles['reader'], int(context['id_getter'], 16), roles['nested_reader'], roles['handler']):
        raise ValueError('Quest reply virtual slots changed')
    registration = context['registration']
    start = int(registration['start'], 16)
    raw = bytes.fromhex(registration['bytes'])
    if len(raw) != 57 or source_bytes(start, len(raw)) != raw:
        raise ValueError('Quest reply bounded registration window changed')
    if start + 7 + struct.unpack_from('<i', raw, 3)[0] != handler:
        raise ValueError('Quest reply registration table differs')
    for offset, target in ((0x21, roles['constructor']), (0x34, int(registration['register'], 16))):
        if raw[offset] != 0xe8 or start + offset + 5 + struct.unpack_from('<i', raw, offset + 1)[0] != target:
            raise ValueError('Quest reply registration call differs')

    uc, x, base = h.uc, h.x, h.scratch
    packet, archive, archive_table, model, model_table, record, setting = (
        base + offset for offset in (0x1000, 0x2000, 0x3000, 0x5000, 0x6000, 0x7000, 0x8000))
    scratch_stack = (base + 0x36000, base + 0x39000)
    allowed_writes = [(packet, packet + 0x48), scratch_stack]
    current = {}
    calls, attempts = [], []

    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_' + name))

    def put(address, value, size=8):
        uc.mem_write(address, int(value).to_bytes(size, 'little'))

    def get(address, size=8):
        return int.from_bytes(uc.mem_read(address, size), 'little')

    def permit(address, size):
        if not any(lo <= address and address + size <= hi for lo, hi in allowed_writes):
            raise ValueError(f'Quest reply write outside declared scope at {address:#x}')

    from unicorn import UC_HOOK_MEM_WRITE
    uc.hook_add(UC_HOOK_MEM_WRITE, lambda _u, _a, address, size, _v, _d: permit(address, size))

    def primitive(slot, size):
        def read(_machine):
            if reg('RCX') != archive:
                raise ValueError('Quest reply archive receiver differs')
            attempts.append(slot)
            offset = current['consumed']
            if len(attempts) == current['failure'] or offset + size > len(current['raw']):
                h.finish(0)
                return
            target = reg('RDX')
            permit(target, size)
            uc.mem_write(target, current['raw'][offset:offset + size])
            current['consumed'] += size
            h.finish(1)
        return read

    for number, (slot, size) in enumerate(sorted(set(zip(SLOTS, SIZES)))):
        callback = base + 0x4000 + number * 16
        put(archive_table + slot, callback)
        h.add_fixture(callback, primitive(slot, size))
    put(archive, archive_table)
    guard = b'A' * 16 + b'\xcc' * 0x48 + b'B' * 16

    def construct():
        uc.mem_write(packet - 16, guard)
        if h.call(roles['constructor'], packet) != packet:
            raise ValueError('Quest reply constructor return changed')
        if get(packet) != outer or get(packet + 0x28) != inner or any(get(packet + off, size) for off, size in FIELDS):
            raise ValueError('Quest reply constructor defaults changed')

    def receive(value, length, failure):
        current.update(raw=WIRE.pack(*value)[:length], consumed=0, failure=failure)
        attempts.clear()
        uc.reg_write(x.UC_X86_REG_RDX, archive)
        accepted = bool(h.call(roles['reader'], packet) & 255)
        if bytes(uc.mem_read(packet - 16, 16)) != guard[:16] or bytes(uc.mem_read(packet + 0x48, 16)) != guard[-16:]:
            raise ValueError('Quest reply packet guards changed')
        return dict(input=list(value), length=length, failure=failure, consumed=current['consumed'],
                    attempts=list(attempts), accepted=accepted,
                    decoded=[get(packet + off, size) for off, size in FIELDS] if accepted else None)

    wire = []
    for value, length, failure in wire_matrix():
        construct()
        observed = receive(value, length, failure)
        if observed != expected_wire(value, length, failure):
            raise ValueError('Quest reply wire scenario differs')
        wire.append(observed)

    def project(_machine):
        if reg('RDX') != current['key'] or reg('R8') != packet + 0x28:
            raise ValueError('Quest reply projection key or nested pointer differs')
        if [get(packet + off, size) for off, size in FIELDS[3:]] != [current['index'], 1, 2]:
            raise ValueError('Quest reply projection input fields differ')
        target = reg('RCX')
        permit(target, 32)
        uc.mem_write(target, current['projection'])
        calls.append('project')
        h.finish(target)

    def lookup(_machine):
        if reg('RCX') != model or reg('RDX') != current['key']:
            raise ValueError('Quest reply lookup receiver or key differs')
        calls.append('lookup')
        h.finish(record if current['existing'] else 0)

    def wrap_key(_machine):
        if reg('RDX') != current['key']:
            raise ValueError('Quest reply missing record key differs')
        target = reg('RCX')
        permit(target, 16)
        uc.mem_write(target, struct.pack('<QQ', current['key'], 0))
        calls.append('wrap_key')
        h.finish(target)

    def apply(existing):
        def callback(_machine):
            if (reg('RCX') != model or reg('R8') & 255 != current['state']
                    or get(reg('RSP') + 0x28, 1) != 1
                    or bytes(uc.mem_read(reg('R9'), 32)) != current['projection']
                    or (reg('RDX') != record if existing else get(reg('RDX')) != current['key'])):
                raise ValueError('Quest reply application arguments differ')
            calls.append('apply_existing' if existing else 'apply_new')
            h.finish()
        return callback

    def error(_machine):
        if reg('RCX') & 0xffffffff != current['code'] or reg('RDX') & 0xffffffff:
            raise ValueError('Quest reply error presentation arguments differ')
        calls.append('error')
        h.finish()

    def unexpected(_machine):
        raise ValueError('Quest reply entered an excluded allocation branch')

    model_global = int(context['model_global'], 16)
    put(model_global, model)
    put(model, model_table)
    put(model_table + 0x48, base + 0x9000)
    put(model_table + 0x50, base + 0x9010)
    fixtures = dict(project=project, lookup=lookup, wrap_key=wrap_key, error=error,
                    settings=lambda _machine: h.finish(setting), release=unexpected)
    if set(fixtures) != set(context['fixtures']):
        raise ValueError('Quest reply fixture roles differ')
    for name, address in context['fixtures'].items():
        h.add_fixture(int(address, 16), fixtures[name])
    h.add_fixture(base + 0x9000, apply(False))
    h.add_fixture(base + 0x9010, apply(True))

    applications = []
    for case in application_matrix():
        code, special, existing, key, state, task_index = case
        construct()
        observed = receive((code, key, state, task_index, 1, 2), WIRE.size, 0)
        if not observed['accepted']:
            raise ValueError('Quest reply handler input did not decode')
        put(setting + 8, special, 1)
        current.update(code=code, existing=existing, key=key, state=state, index=task_index,
                       projection=struct.pack('<QBB2xII12x', 110120005 + task_index, 6, task_index, 1, 2))
        calls.clear()
        immutable = [(at, bytes(uc.mem_read(at, size))) for at, size in
                     ((packet - 16, 0x68), (model, 0x100), (record, 0x60), (setting, 16))]
        allowed_writes[:] = [scratch_stack]
        uc.reg_write(x.UC_X86_REG_RDX, 0)
        uc.reg_write(x.UC_X86_REG_R8, packet)
        h.call(roles['handler'], handler, budget=100000)
        allowed_writes[:] = [(packet, packet + 0x48), scratch_stack]
        expectation = expected_application(*case)
        if calls != expectation['calls'] or any(bytes(uc.mem_read(at, len(raw))) != raw for at, raw in immutable):
            raise ValueError('Quest reply handler order or fixture input changed')
        applications.append(expectation)
    return dict(wire=wire, applications=applications)
