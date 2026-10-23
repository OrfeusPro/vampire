"""Explicit OS/CRT boundary fixtures for integrated Version replay; no host calls."""
import struct
from pathlib import Path


def install(load, h, config, shared, state, write_text, read_text, literal, reg):
    cpu, windows = config['cpu'], config['windows']
    rows = load('update-bindings').rows; native = load('build-native-entry-code')
    for context, functions in ((cpu, cpu['functions'].values()), (windows, [windows['function']])):
        if context['source_sha256'] != h.sha or Path(context['source']).resolve() != h.source.resolve():
            raise ValueError('Integrated system source differs')
        calls = {hex(r['address']): hex(r['direct_target']) if r['direct_target'] is not None else r['operands']
                 for at in functions for r in rows(native, h.image, int(at, 16)) if r['call']}
        if calls != context['call_sites']: raise ValueError('Integrated system call sites differ')
    imports = load('build-object-zero-init-code')
    for name, item in windows['imports'].items():
        found = imports.import_at(h.raw, h.image, int(item['slot'], 16))
        if found['name'] != name or found['dll'].lower() != item['dll'].lower():
            raise ValueError('Integrated Windows import differs')
    if imports.import_at(h.raw, h.image, int(cpu['space_slot'], 16))['name'] != 'iswspace':
        raise ValueError('Integrated whitespace import differs')
    cf, wf = [{key: int(value, 16) for key, value in context['fixtures'].items()} for context in (cpu, windows)]
    if (cf['ascii'], cf['wide'], cf['free'], wf['wide_string']) != (
            shared['ascii_string'], shared['wide_string'], shared['free'], shared['wide_string']):
        raise ValueError('Integrated shared string bindings differ')
    for address, expected in ((cf['move'], 'memmove'), (wf['memset'], 'memset')):
        offset = h.image.offset(address - h.image.pe.base)
        if h.raw[offset:offset + 2] != b'\xff\x25': raise ValueError('Integrated CRT thunk differs')
        slot = address + 6 + struct.unpack_from('<i', h.raw, offset + 2)[0]
        if imports.import_at(h.raw, h.image, slot)['name'] != expected:
            raise ValueError('Integrated CRT import differs')
    vendor, brand = [int(cpu[key], 16) for key in ('vendor', 'brand')]
    guard, cache, tls_index, cookie = [int(windows[key], 16) for key in ('guard', 'cache', 'tls_index', 'cookie')]
    teb, vector, block = h.scratch + 0x8000, h.scratch + 0x9000, 0x29000000
    h.uc.mem_map(block, 0x102000)
    h.uc.reg_write(h.x.UC_X86_REG_GS_BASE, teb)
    h.uc.mem_write(teb + 0x58, struct.pack('<Q', vector))
    h.uc.mem_write(vector, struct.pack('<Q', block))
    h.uc.mem_write(tls_index, b'\0' * 4)

    def handler(name):
        def execute(machine):
            a, b, c, d = [reg(key) for key in ('RCX', 'RDX', 'R8', 'R9')]
            stack = reg('RSP'); result = 0; state['system_events'].append(name)
            if name == 'space': result = int(a in (9, 10, 11, 12, 13, 32))
            elif name == 'move':
                if c > 2048 or not all(h.scratch <= p <= h.scratch + 0x40000 - c for p in (a, b)):
                    raise ValueError('Integrated CPU move bound')
                h.uc.mem_write(a, bytes(h.uc.mem_read(b, c))); result = a
            elif name == 'shrink': read_text(a)
            elif name == 'cpu_format':
                if literal(b, True) != '%s|%s': raise ValueError('Integrated CPU format branch differs')
                values = [literal(c, True), literal(d, True)]
                if values != state['cpu_values']: raise ValueError('Integrated native CPU trim differs')
                result = write_text(a, '|'.join(values))
            elif name == 'acquire':
                if a != guard: raise ValueError('Integrated Windows acquire address differs')
                h.uc.mem_write(guard, struct.pack('<i', -1))
            elif name == 'release':
                if a != guard: raise ValueError('Integrated Windows release address differs')
                h.uc.mem_write(guard, b'\0' * 4)
            elif name == 'system_info': h.uc.mem_write(a, b'\x6b' * 48)
            elif name == 'memset':
                if b != 0 or c != 0x118: raise ValueError('Integrated Windows memset differs')
                h.uc.mem_write(a, b'\0' * c); result = a
            elif name == 'version':
                if bytes(h.uc.mem_read(a, 0x11c)) != struct.pack('<I', 0x11c) + bytes(0x118):
                    raise ValueError('Integrated version struct differs')
                h.uc.mem_write(a + 4, struct.pack('<III', 10, 0, 26100))
                h.uc.mem_write(a + 0x118, struct.pack('<HB', 256, 1))
                result = int(not state['empty'])
            elif name == 'windows_format':
                extra = [int.from_bytes(h.uc.mem_read(stack + off, 4), 'little') for off in (0x28, 0x30, 0x38, 0x40)]
                tail = int.from_bytes(h.uc.mem_read(stack + 0x48, 8), 'little')
                if (a, b, literal(c, True), d, extra, literal(tail, True)) != (
                        cache, 128, '%d.%d.%d.%d.%d.%s', 10, [0, 26100, 1, 256], '64bit'):
                    raise ValueError('Integrated Windows format inputs differ')
                h.uc.mem_write(cache, (state['suffix'] + '\0').encode('utf-16le'))
            elif name == 'cookie_check':
                if a != 0x12345678: raise ValueError('Integrated Windows cookie differs')
                result = reg('RAX')
            else: raise ValueError('Unknown integrated system fixture')
            h.finish(result)
        return execute
    for key in ('space', 'move', 'shrink'): h.add_fixture(cf[key], handler(key))
    h.add_fixture(cf['format'], handler('cpu_format'))
    for key in ('acquire', 'release', 'memset', 'cookie_check'): h.add_fixture(wf[key], handler(key))
    h.add_fixture(wf['format'], handler('windows_format'))
    for index, (name, item) in enumerate(windows['imports'].items()):
        target = h.scratch + 0x6100 + index * 16
        h.add_fixture(target, handler(item['fixture']))
        h.uc.mem_write(int(item['slot'], 16), struct.pack('<Q', target))
    h.uc.mem_write(int(cpu['space_slot'], 16), struct.pack('<Q', cf['space']))
    import unicorn
    targets = {int(at, 16): key for key, at in cpu['functions'].items()}
    targets[int(windows['function'], 16)] = 'windows'
    def count(machine, address, size, unused):
        if address in targets:
            key = targets[address]; state['system_calls'][key] = state['system_calls'].get(key, 0) + 1
    h.uc.hook_add(unicorn.UC_HOOK_CODE, count)

    def seed():
        state.update(system_events=[], system_calls={},
            suffix='' if state['empty'] else '10.0.26100.1.256.64bit',
            cpu_values=['', ''] if state['empty'] else ['GenuineIntel', 'Fixture CPU'])
        state['first_text'] = '|'.join(state['cpu_values'])
        for pointer, value, size in ((vendor, '' if state['empty'] else 'GenuineIntel', 13),
                                     (brand, '' if state['empty'] else '  Fixture CPU\t', 64)):
            h.uc.mem_write(pointer, (value + '\0').encode('ascii').ljust(size, b'\0'))
        state['cpu_cache_before'] = bytes(h.uc.mem_read(vendor, 77))
        h.uc.mem_write(cache, 'old-cache\0'.encode('utf-16le'))
        h.uc.mem_write(guard, struct.pack('<i', 1))
        h.uc.mem_write(block + 0x101184, b'\0' * 4)
        h.uc.mem_write(cookie, struct.pack('<Q', 0x12345678))

    def check():
        expected = dict(formatter=1, first=1, second=1, trim=3, trim_start=3, trim_end=3, windows=1)
        if state['system_calls'] != expected: raise ValueError('Integrated native system call counts differ')
        events = [e for e in state['system_events'] if e not in ('space', 'move', 'shrink', 'cpu_format')]
        if events != ['acquire', 'system_info', 'memset', 'version'] + ([] if state['empty'] else ['windows_format']) + ['release', 'cookie_check']:
            raise ValueError('Integrated Windows lifecycle differs')
        if bytes(h.uc.mem_read(vendor, 77)) != state['cpu_cache_before']:
            raise ValueError('Integrated CPU cache modified')
    return seed, check
