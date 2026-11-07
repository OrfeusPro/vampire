"""Current QuestStart wire/producer and eligibility branches with explicit providers."""
from itertools import product
import struct


def run(index, root, context):
    functions = {key: int(value, 16) for key, value in context['roles'].items()}
    leaves = {int(at, 16): value for at, value in context['leaves'].items()}
    h = index.extension('native-request-harness-11316').make_harness(
        context['exports'], set(functions.values()), leaves=leaves, root=root,
        source_sha256=context['source_sha256'], copy_thunk=None)
    native, bindings = index.extension('build-native-entry-code'), index.extension('update-bindings')
    for export in h.fragments:
        at = int(export['address'], 16)
        if at == functions.get('result_gate'):
            # This previously qualified gate contains an embedded switch table.
            continue
        expected = bindings.rows(native, h.image, at)
        if (export.get('block_coverage_complete') is not True
                or export.get('direct_flow_coverage_complete') is not True
                or index.missing_conditional_fallthroughs(export['instructions'])
                or [(int(row['address'], 16), row['bytes']) for row in export['instructions']] !=
                   [(row['address'], row['bytes']) for row in expected]):
            raise ValueError('QuestStart whole control flow differs')
    uc, x, base = h.uc, h.x, h.scratch
    packet, archive, table, argument, model, row, settings = (base + off for off in
        (0x1000, 0x2000, 0x3000, 0x5000, 0x6000, 0x7000, 0x8000))
    current, attempts, calls = {}, [], []
    allowed = [(base + 0x35000, base + 0x39000)]

    def require(ok, reason):
        if not ok:
            raise ValueError('QuestStart native: ' + reason)

    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_' + name))

    def put(at, value, size=8):
        uc.mem_write(at, (int(value) % (1 << (8 * size))).to_bytes(size, 'little'))

    def get(at, size=8):
        return int.from_bytes(uc.mem_read(at, size), 'little')

    def permit(at, size):
        require(any(lo <= at and at + size <= hi for lo, hi in allowed), 'write outside declared scope')

    from unicorn import UC_HOOK_MEM_WRITE
    uc.hook_add(UC_HOOK_MEM_WRITE, lambda _u, _a, at, size, _v, _d: permit(at, size))
    entries = {}
    nonvolatile = ('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15')
    def call(at, rcx=0, rdx=0, r8=0, r9=0):
        for name, value in zip(nonvolatile, range(0x7710, 0x7718)):
            uc.reg_write(getattr(x, 'UC_X86_REG_' + name), value)
        for name, value in (('RDX', rdx), ('R8', r8), ('R9', r9)):
            uc.reg_write(getattr(x, 'UC_X86_REG_' + name), value)
        result = h.call(at, rcx, budget=100000)
        require([reg(name) for name in nonvolatile] == list(range(0x7710, 0x7718)), 'Win64 nonvolatile register')
        require(reg('RSP') == base + 0x38008, 'Win64 stack')
        entries[hex(at)] = entries.get(hex(at), 0) + 1
        return result

    def source(at, size):
        off = h.image.offset(at - h.image.pe.base)
        return h.raw[off:off + size]

    for table_at, slot, target in context['bindings']:
        require(int.from_bytes(source(int(table_at, 16) + slot, 8), 'little') == int(target, 16), 'vtable binding')
    for window in context['windows']:
        require(source(int(window['address'], 16), len(bytes.fromhex(window['bytes']))) == bytes.fromhex(window['bytes']), 'static window')
    require(source(0x149906398, 24) == 'QuestInfoId\0'.encode('utf-16le'), 'numeric key literal')
    require(source(0x1499069a8, 30) == 'QuestTaskIndex\0'.encode('utf-16le'), 'task index literal')

    # A qualified QuestData reader is retained by the wrapper. Here its boundary
    # is a bounded provider; the outer result must forward the exact +0x20 object.
    def nested(_machine):
        require(reg('RCX') == archive and reg('RDX') == packet + 0x20, 'nested INPUT forwarding')
        attempts.append('nested')
        current['consumed'] += len(current['nested_body']) if current['nested_ok'] else 0
        h.finish(int(current['nested_ok']))

    h.add_fixture(int(context['nested_dispatch'], 16), nested)
    def primitive(slot, size, writing=False):
        def callback(_machine):
            require(reg('RCX') == archive, 'archive receiver')
            attempts.append(slot)
            if len(attempts) == current.get('failure', 0):
                h.finish(0)
                return
            if writing:
                current['raw'] += (reg('RDX') & ((1 << (size * 8)) - 1)).to_bytes(size, 'little')
            else:
                offset = current['consumed']
                if offset + size > len(current['raw']):
                    h.finish(0)
                    return
                permit(reg('RDX'), size)
                uc.mem_write(reg('RDX'), current['raw'][offset:offset + size])
                current['consumed'] += size
            h.finish(1)
        return callback
    put(archive, table)
    for i, (slot, size, writing) in enumerate(((0x48, 8, True), (0x50, 8, False), (0x58, 4, False))):
        at = base + 0x4000 + i * 16
        put(table + slot, at)
        h.add_fixture(at, primitive(slot, size, writing))
    wire = []
    ctor = int(context['constructor'], 16)
    default = int(context['default_constructor'], 16)
    for key in (0, 110110, 2**64 - 1):
        allowed[:] = [(packet, packet + 0x40), (base + 0x35000, base + 0x39000)]
        uc.mem_write(packet - 16, b'A' * 16 + b'X' * 0x40 + b'B' * 16)
        put(argument, key)
        require(call(ctor, packet, argument) == packet and get(packet + 0x10) == key, 'constructor key')
        current.update(raw=b'', consumed=0, failure=0)
        attempts.clear()
        require(call(functions['writer'], packet, archive) & 255 == 1, 'writer return')
        require(current['raw'] == struct.pack('<Q', key) and attempts == [0x48], 'writer body')
        for length in range(9):
            call(default, packet)
            current.update(raw=struct.pack('<Q', key)[:length], consumed=0, failure=0)
            attempts.clear()
            accepted = bool(call(functions['reader'], packet, archive) & 255)
            require(accepted == (length == 8), 'request truncation')
            if accepted:
                require(get(packet + 0x10) == key, 'request mirror')
            wire.append(dict(key=str(key), length=length, accepted=accepted))
        current.update(raw=b'', failure=1)
        attempts.clear()
        require(call(functions['writer'], packet, archive) & 255 == 0 and not current['raw'], 'writer failure')
    replies = []
    for code, key, nested_ok in product((0, 100, 2**32 - 1), (110110, 2**64 - 1), (False, True)):
        for length in (0, 3, 4, 11, 12):
            call(functions['result_constructor'], packet)
            require(get(packet + 0x10, 4) == 0 and get(packet + 0x18) == 0
                    and get(packet + 0x20) == int(context['nested_table'], 16), 'result defaults')
            prefix = struct.pack('<IQ', code, key)
            current.update(raw=prefix[:length], consumed=0, failure=0,
                           nested_body=b'qualified-child', nested_ok=nested_ok)
            attempts.clear()
            accepted = bool(call(functions['result_reader'], packet, archive) & 255)
            require(accepted == (length == 12 and nested_ok), 'outer result truncation/child failure')
            if accepted:
                require(get(packet + 0x10, 4) == code and get(packet + 0x18) == key, 'result prefix fields')
            replies.append(dict(code=code, key=str(key), length=length, nested_ok=nested_ok, accepted=accepted))

    # Producer selector0: only a real source constructor makes the output packet.
    def fixture(at, callback):
        h.add_fixture(at, callback)
    def named_field(_machine):
        require(reg('RDX') in (0x149906398, 0x1499069a8, 0x149a3fe28), 'producer named field')
        h.finish(argument)
    fixture(0x1445cbdf0, named_field)
    fixture(0x1445c7660, lambda _m: h.finish(current['key']))
    fixture(0x1445c7680, lambda _m: h.finish(0))
    def string(_m):
        put(reg('RDX'), 0); put(reg('RDX') + 8, 0); h.finish(reg('RDX'))
    fixture(0x141478350, string)
    fixture(0x144aae610, lambda _m: h.finish(model))
    def pending(_m):
        require(reg('RCX') == model and reg('RDX') == 1804, 'producer pending ID')
        h.finish(int(current['pending']))
    fixture(0x144aae620, pending)
    def lookup(_m):
        require(get(reg('RDX')) == current['key'], 'Quest lookup key')
        put(reg('RCX'), row if current['exists'] else 0); h.finish(reg('RCX'))
    fixture(0x145b4bf30, lookup)
    fixture(0x1414884f0, lambda _m: h.finish(get(reg('RCX'))))
    def send(_m):
        require(reg('RCX') == model and reg('R8') == 1804 and reg('R9') == current['key'], 'producer correlation')
        require(get(reg('RSP') + 0x28) == 0, 'producer send flag')
        out = reg('RDX')
        require(get(out) == int(context['request_table'], 16) and get(out + 0x10) == current['key'], 'producer packet')
        calls.append('send'); h.finish(1)
    fixture(0x144aae9f0, send)
    fixture(0x1456b66e0, lambda _m: h.finish())
    fixture(0x1414830e0, lambda _m: (_ for _ in ()).throw(ValueError('Unexpected QuestStart free')))
    producers = []
    uc.mem_write(argument, bytes(0x58))
    allowed[:] = [(base + 0x35000, base + 0x39000)]
    for key, pending_value, exists in product((110110, 2**64 - 1), (False, True), (False, True)):
        current.update(key=key, pending=pending_value, exists=exists)
        calls.clear()
        result = call(functions['producer'], model, argument) & 255
        sent = not pending_value and exists
        require(result == int(not pending_value) and calls == (['send'] if sent else []), 'producer branch')
        producers.append(dict(key=str(key), pending=pending_value, exists=exists, sent=sent))

    # The full source eligibility predicate accepts model states1 and3; other
    # gates (Quest row, level, predecessor and condition) are explicit providers.
    gate_calls = []
    def completed(_m):
        gate_calls.append(reg('RCX'))
        h.finish(int(current['already'] if reg('RCX') == current['key'] else current['predecessor']))
    fixture(0x145df6a70, completed)
    fixture(0x1456ac510, lambda _m: h.finish(current['level']))
    fixture(0x145cf7e60, lambda _m: h.finish(settings))
    fixture(0x145cfbe30, lambda _m: h.finish(int(current['condition'])))
    fixture(0x1455be4a0, lambda _m: h.finish(model))
    fixture(0x1455bbca0, lambda _m: h.finish(packet if current['record'] else 0))
    eligibility = []
    for state in range(7):
        for blocked in ('none', 'already', 'missing', 'level', 'predecessor', 'condition'):
            current.update(key=110110, exists=blocked != 'missing', already=blocked == 'already',
                           level=0 if blocked == 'level' else 1, predecessor=blocked != 'predecessor',
                           condition=blocked == 'condition', record=True)
            put(row + 0xac, 1, 4); put(row + 0xb0, 110100); put(row + 0xc0, 0, 4)
            put(packet + 0x28, state, 1)
            allowed[:] = [(base + 0x35000, base + 0x39000)]
            accepted = bool(call(functions['eligibility'], 110110) & 255)
            require(accepted == (blocked == 'none' and state in (1, 3)), 'eligibility state/prerequisite')
            eligibility.append(dict(state=state, blocked=blocked, accepted=accepted))
    return dict(requests=wire, outer_replies=replies, producers=producers,
                eligibility=eligibility, abi_checks=sum(entries.values()), native_entries=entries,
                nested_reader='retained_parent_proof_with_explicit_provider_here')
