"""Observe real archive scalar entry/return; only input buffer and memcpy are fixtures."""
import struct


def install(load, h, context, state, packet, archive, order):
    native, rows = load('build-native-entry-code'), load('update-bindings').rows
    functions = {key: int(at, 16) for key, at in context['functions'].items()}
    calls = {hex(r['address']): {'target': hex(r['direct_target']) if r['direct_target'] is not None else r['operands']}
             for at in functions.values() for r in rows(native, h.image, at) if r['call']}
    if calls != context['call_sites']:
        raise ValueError('Input archive call sites differ')
    table = int(context['table'], 16)
    off = h.image.offset(table - h.image.pe.base)
    data = bytes.fromhex(context['table_bytes'])
    if h.raw[off:off + len(data)] != data:
        raise ValueError('Input archive table differs')
    for slot, name in ((0x28, 'time'), (0x50, 'u64'), (0x58, 'u32'), (0x60, 'u32'),
                       (0x70, 'u16'), (0x88, 'bool'), (0x90, 'raw')):
        if struct.unpack_from('<Q', data, slot)[0] != functions[name]:
            raise ValueError('Input archive slot differs')
    buffer = h.scratch + 0x5000
    targets = {functions[name]: name for name in ('time', 'u64', 'u32', 'u16', 'bool')}
    if context.get('string_fixtures'):
        targets[functions['string']] = 'string'
        if struct.unpack_from('<Q', data, 0x30)[0] != functions['std_string']:
            raise ValueError('Input archive std-string slot differs')

    def reg(name):
        return h.uc.reg_read(getattr(h.x, 'UC_X86_REG_' + name))

    def require(ok, message):
        if not ok:
            raise ValueError(message)

    import unicorn

    def entered(machine, at, size, unused):
        if state.get('input_pending') and at == state['input_pending']:
            state['input_pending'] = None
            if reg('RAX') & 255:
                state['written'].append(state['input_offset'])
        if at in targets and not state.get('input_pending'):
            require(reg('RCX') == archive and len(state['operations']) < len(order), 'Input archive receiver/count differs')
            expected_kind, offset = order[len(state['operations'])]
            kind = targets[at]
            require(kind == ('u32' if expected_kind == 'raw32' else expected_kind)
                    and reg('RDX') == packet + offset, 'Input archive field order/destination differs')
            state['operations'].append([expected_kind, hex(offset)])
            if state['fail_at'] == len(state['operations']) - 1:
                h.finish(0)
                return
            state['input_pending'] = int.from_bytes(h.uc.mem_read(reg('RSP'), 8), 'little')
            state['input_offset'] = offset
            state['input_entries'][kind] = state['input_entries'].get(kind, 0) + 1
    h.uc.hook_add(unicorn.UC_HOOK_CODE, entered)

    def position():
        value = int.from_bytes(h.uc.mem_read(archive + 0x30, 8), 'little') - buffer
        require(0 <= value <= len(state['body']), 'Input archive cursor outside body')
        return value

    def set_position(value):
        require(0 <= value <= len(state['body']), 'Input archive fixture cursor bound')
        h.uc.mem_write(archive + 0x30, struct.pack('<Q', buffer + value))

    def seed(body, poison):
        state.update(input_pending=None, input_entries={})
        h.uc.mem_write(archive - 16, b'\xa5' * 16 + bytes([poison]) * 0x40 + b'\xa6' * 16)
        h.call(functions['constructor'], archive)
        require(int.from_bytes(h.uc.mem_read(archive, 8), 'little') == table, 'Input archive constructor table differs')
        require(len(body) <= 4096, 'Input archive fixture buffer bound')
        h.uc.mem_write(buffer - 16, b'\xa5' * 16 + body + b'\xa6' * 16)
        h.uc.mem_write(archive + 0x20, struct.pack('<QI', buffer, len(body)))
        set_position(0)
        state['input_guard'] = bytes(h.uc.mem_read(archive - 16, 0x60))
        state['buffer_guard'] = bytes(h.uc.mem_read(buffer - 16, len(body) + 32))

    def check():
        require(state['input_pending'] is None, 'Input archive scalar did not return')
        before, after = state['input_guard'], bytes(h.uc.mem_read(archive - 16, 0x60))
        mutable = set(range(16 + 0x10, 16 + 0x14)) | set(range(16 + 0x30, 16 + 0x38))
        require(all(a == b for i, (a, b) in enumerate(zip(before, after)) if i not in mutable),
                'Input archive wrote outside cursor/bookkeeping')
        require(bytes(h.uc.mem_read(buffer - 16, len(state['buffer_guard']))) == state['buffer_guard'],
                'Input archive modified source buffer/guards')
    return seed, position, set_position, check
