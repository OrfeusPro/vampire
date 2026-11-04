"""Execute reviewed state-application roots with explicit Win64 and fixture boundaries."""
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

SCRATCH = 0x28000000
SCRATCH_SIZE = 0x40000
STACK_START, STACK_END, STACK_ENTRY = SCRATCH + 0x34000, SCRATCH + 0x3c000, SCRATCH + 0x38008
STOP = SCRATCH + 0x3f000
INDIRECT_FIXTURE = SCRATCH + 0x3e000


def make_harness(index, store, context, exports, tables):
    """Only the checked context roots, leaves and fixture entries can execute."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[3] / '.tools/vampir-analysis'))
    import unicorn
    from unicorn import x86_const as x

    sha = context['source_sha256']
    native = index.extension('build-native-entry-code')
    if unicorn.__version__ != '2.1.4' or native.capstone.__version__ != '5.0.6':
        raise ValueError('Pinned Tutorial state runtime required')
    image = store.image(native, sha)
    raw = store.source(sha)
    if Path(context['source']).resolve() != Path(store.root).resolve() / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe':
        raise ValueError('Tutorial state context source path differs')
    bindings = index.extension('update-bindings')
    leaf_api = index.extension('login-input-transfer-rules')
    roots = {int(at, 16) for at in context['functions'].values()}
    leaves = {int(at, 16): text for at, text in context['leaves'].items()}
    boundaries = {int(at, 16) for at in context['fixtures'].values()}
    global_at = int(context['handler_global'], 16) if context.get('handler_global') else None
    if not roots or roots & set(leaves) or boundaries & (roots | set(leaves)):
        raise ValueError('Tutorial state execution boundaries overlap')
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    uc.mem_map(SCRATCH, SCRATCH_SIZE)
    uc.mem_write(STOP, b'\xc3')
    uc.mem_write(INDIRECT_FIXTURE, b'\xc3')
    pages, allowed = set(), {}
    readable, writable, source_ranges = [], [], []
    stack_bounds = [(STACK_START + 16, STACK_END - 16)]
    active = dict(running=False, previous=None, fixture=None, finished=False, fixture_return=None)
    h = SimpleNamespace(uc=uc, x=x, scratch=SCRATCH, fixtures={}, entry_counts={},
                        call_counts=0, abi_checks=0, read_checks=0, write_checks=0, fixture_calls=0)

    def map_extent(at, size):
        for page in range(at & ~4095, ((at + size - 1) & ~4095) + 4096, 4096):
            if SCRATCH <= page < SCRATCH + SCRATCH_SIZE:
                raise ValueError('Tutorial state source overlaps scratch')
            if page not in pages:
                uc.mem_map(page, 4096, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
                try:
                    offset = image.offset(page - image.pe.base)
                except ValueError:
                    # Zero-filled PE data can have a virtual range but no raw bytes.
                    pass
                else:
                    uc.mem_write(page, raw[offset:offset + 4096])
                pages.add(page)

    def include(rows):
        for row in rows:
            at = row['address']
            if at in allowed and allowed[at] != row:
                raise ValueError('Tutorial state instruction declarations conflict')
            allowed[at] = row
            map_extent(at, len(bytes.fromhex(row['bytes'])))

    found = set()
    for report in exports:
        if report.get('new_source_sha256') != sha:
            raise ValueError('Tutorial state export source differs')
        for function in report['functions']:
            at = int(function['address'], 16)
            if at not in roots:
                continue
            whole = bindings.rows(native, image, at)
            actual = [(int(row['address'], 16), row['bytes'].lower()) for row in function['instructions']]
            if (function.get('decompilation_completed') is not True or
                    actual != [(row['address'], row['bytes'].lower()) for row in whole]):
                raise ValueError('Tutorial state export lacks exact whole unwind coverage')
            include(whole)
            found.add(at)
    if found != roots:
        raise ValueError('Tutorial state target exports incomplete')
    for at, text in leaves.items():
        if hex(at) == context.get('handler_trampoline'):
            rows = index.extension('quest-action-transfer-rules-v1').decode(native, image, at, 7)
            if text != '488b0148ff6010' or ''.join(row['bytes'] for row in rows) != text:
                raise ValueError('Tutorial state trampoline differs from reviewed virtual tail')
            include(rows)
        else:
            include(leaf_api.leaf_rows(native, image, at, bytes.fromhex(text)))
    if boundaries & allowed.keys():
        raise ValueError('Tutorial state fixture overlaps an instruction')
    for table, text in tables.items():
        at, data = int(table, 16), bytes.fromhex(text)
        offset = image.offset(at - image.pe.base)
        if not data or raw[offset:offset + len(data)] != data:
            raise ValueError('Tutorial state table bytes differ')
        map_extent(at, len(data))
        uc.mem_write(at, data)
        source_ranges.append((at, at + len(data)))
    globals_to_map = dict(context.get('readonly_globals', {}))
    if global_at is not None:
        globals_to_map[hex(global_at)] = None
    for at_text, encoded in globals_to_map.items():
        at = int(at_text, 16)
        if encoded is not None and (not isinstance(encoded, str) or len(encoded) not in (2, 8, 16, 32)):
            raise ValueError('Tutorial state global shadow lies outside exact source storage')
        expected = bytes.fromhex(encoded) if encoded is not None else None
        size = len(expected) if expected is not None else 8
        sections = [section for section in image.pe.sections
                    if section['name'] in (('.data',) if expected is None else ('.data', '.rdata'))
                    and section['rva'] <= at - image.pe.base
                    and at - image.pe.base + size <= section['rva'] + section['size']]
        if len(sections) != 1:
            raise ValueError('Tutorial state global shadow lies outside exact source storage')
        section = sections[0]
        relative = at - image.pe.base - section['rva']
        raw_size = max(0, min(size, section['raw_size'] - relative))
        actual = raw[section['raw'] + relative:section['raw'] + relative + raw_size] + bytes(size - raw_size)
        if expected is not None and actual != expected:
            raise ValueError('Tutorial state readonly source bytes changed')
        map_extent(at, size)
        uc.mem_write(at, actual)
        source_ranges.append((at, at + size))

    def set_global(value):
        if global_at is None or active['running'] or type(value) is not int or not SCRATCH <= value < STACK_START:
            raise ValueError('Tutorial state global pointer must refer to bounded scratch')
        uc.mem_write(global_at, struct.pack('<Q', value))

    for at in boundaries - {INDIRECT_FIXTURE}:
        if any(lo <= at < hi for lo, hi in source_ranges):
            raise ValueError('Tutorial state fixture overlaps reviewed data')
        map_extent(at, 1)
        # Stop the translator at the boundary, including entries near a page end.
        # The code hook checks and completes the fixture before this RET can run.
        uc.mem_write(at, b'\xc3')
    callers = {at: {} for at in boundaries}
    for at, row in allowed.items():
        target = row['direct_target']
        if target in callers and (row['call'] or row['mnemonic'] == 'jmp'):
            callers[target][at] = 'call' if row['call'] else 'tail'
    for caller, operand, target in context.get('indirect_fixtures', []):
        at, dest = int(caller, 16), int(target, 16)
        row = allowed.get(at)
        if (row is None or row['call'] is not True or row['operands'] != operand
                or row['direct_target'] is not None or dest not in callers or at in callers[dest]):
            raise ValueError('Tutorial state indirect fixture scope differs')
        callers[dest][at] = 'call'
    h.available_fixtures = {at for at, sites in callers.items() if sites}

    def within(at, size, regions):
        return any(lo <= at and at + size <= hi for lo, hi in regions)

    def permit(at, size, regions):
        if (type(at) is not int or type(size) is not int or not 0 <= size <= 0x30000
                or not within(at, size, [(SCRATCH, STACK_START)])
                or (active['running'] and active['fixture'] is None) or len(regions) >= 4096):
            raise ValueError('Tutorial state scratch permission differs')
        regions.append((at, at + size))

    def allow_read(at, size):
        permit(at, size, readable)

    def allow_write(at, size):
        permit(at, size, writable)
        permit(at, size, readable)

    def reset_regions():
        if active['running']:
            raise ValueError('Tutorial state cannot reset active scratch permissions')
        readable.clear()
        writable.clear()

    def write(at, data):
        if active['fixture'] is None or not within(at, len(data), writable + stack_bounds):
            raise ValueError('Tutorial state fixture write outside declared output')
        uc.mem_write(at, bytes(data))
        h.write_checks += 1

    def add_fixture(at, handler):
        if active['running'] or at not in h.available_fixtures or at in h.fixtures or not callable(handler):
            raise ValueError('Tutorial state fixture is duplicate or lacks a reviewed caller')
        h.fixtures[at] = handler

    def finish(value=0):
        frame = active['fixture']
        if frame is None:
            raise ValueError('Tutorial state fixture return without entry')
        stack, returning = frame
        if uc.reg_read(x.UC_X86_REG_RSP) != stack or bytes(uc.mem_read(stack, 8)) != struct.pack('<Q', returning):
            raise ValueError('Tutorial state fixture changed its return boundary')
        if not active['frames'] or active['frames'].pop() != (stack, returning):
            raise ValueError('Tutorial state fixture return does not match a live native frame')
        uc.reg_write(x.UC_X86_REG_RAX, value)
        uc.reg_write(x.UC_X86_REG_RSP, stack + 8)
        uc.reg_write(x.UC_X86_REG_RIP, returning)
        active.update(fixture=None, fixture_return=returning)

    def code_hook(machine, address, size, unused):
        previous = active['previous']
        if address == STOP:
            if active['frames'] or (active['fixture_return'] != STOP and (previous is None or previous['mnemonic'] != 'ret')):
                raise ValueError('Tutorial state stop lacks native return provenance')
            active['finished'] = True
            machine.emu_stop()
            return
        active['fixture_return'] = None
        if address in boundaries:
            if address not in h.fixtures or previous is None:
                raise ValueError(f'Tutorial state fixture handler/caller missing at {address:#x}')
            stack = machine.reg_read(x.UC_X86_REG_RSP)
            if stack % 16 != 8 or not within(stack, 8, stack_bounds):
                raise ValueError('Tutorial state fixture stack boundary differs')
            returning, = struct.unpack('<Q', machine.mem_read(stack, 8))
            kind = callers[address].get(previous['address'])
            call_return = previous['address'] + len(bytes.fromhex(previous['bytes']))
            if not ((kind == 'call' and returning == call_return and returning in allowed)
                    or (kind == 'tail' and active['frames'] and active['frames'][-1] == (stack, returning))):
                raise ValueError('Tutorial state fixture caller/return boundary differs')
            h.fixture_calls += 1
            h.entry_counts[address] = h.entry_counts.get(address, 0) + 1
            active['fixture'] = (stack, returning)
            h.fixtures[address](machine)
            if active['fixture'] is not None:
                raise ValueError('Tutorial state fixture did not complete its return')
            return
        if address not in allowed or size != len(bytes.fromhex(allowed[address]['bytes'])):
            raise ValueError(f'Unreviewed Tutorial state execution target: {address:#x}')
        if address in roots or address in leaves:
            h.entry_counts[address] = h.entry_counts.get(address, 0) + 1
        row = allowed[address]
        stack = machine.reg_read(x.UC_X86_REG_RSP)
        if row['call']:
            active['frames'].append((stack - 8, address + size))
        elif row['mnemonic'] == 'ret':
            returning, = struct.unpack('<Q', machine.mem_read(stack, 8))
            if not active['frames'] or active['frames'].pop() != (stack, returning):
                raise ValueError('Tutorial state native return does not match a live call frame')
        active['previous'] = row

    def memory_hook(machine, access, address, size, value, unused):
        if access == unicorn.UC_MEM_WRITE:
            if not within(address, size, writable + stack_bounds):
                raise ValueError(f'Tutorial state native write outside declared output: {address:#x}/{size}')
            h.write_checks += 1
        else:
            if not within(address, size, readable + source_ranges + stack_bounds):
                raise ValueError(f'Tutorial state native read outside declared input: {address:#x}/{size}')
            h.read_checks += 1

    uc.hook_add(unicorn.UC_HOOK_CODE, code_hook)
    uc.hook_add(unicorn.UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE, memory_hook)

    nonvolatile = ('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15')
    volatile = ('RAX', 'RCX', 'RDX', 'R8', 'R9', 'R10', 'R11')
    xmm_saved = tuple('XMM' + str(i) for i in range(6, 16))
    def call(address, receiver=0, budget=30000, *, rdx=0, r8=0, r9=0, stack_args=()):
        if active['running'] or address not in roots | set(leaves or {}):
            raise ValueError('Tutorial state call entry is outside exact root/leaf scope')
        if type(budget) is not int or not 1 <= budget <= 1000000 or len(stack_args) > 8:
            raise ValueError('Tutorial state call instruction/argument budget exceeded')
        for value in (receiver, rdx, r8, r9, *stack_args):
            if type(value) is not int or not 0 <= value < 1 << 64: raise ValueError('Tutorial state Win64 argument differs')
        uc.mem_write(STACK_START, b'\xcd' * (STACK_END - STACK_START))
        uc.mem_write(STACK_START, b'\xd1' * 16); uc.mem_write(STACK_END - 16, b'\xd2' * 16)
        for name in volatile: uc.reg_write(getattr(x, 'UC_X86_REG_' + name), 0)
        saved = {}
        for i, name in enumerate(nonvolatile):
            saved[name] = 0x1a2b300000000000 + i * 0x10101
            uc.reg_write(getattr(x, 'UC_X86_REG_' + name), saved[name])
        for i in range(16): uc.reg_write(getattr(x, 'UC_X86_REG_XMM' + str(i)), 0)
        for i, name in enumerate(xmm_saved):
            saved[name] = 0x123456789abcdef00112233445566770 + i
            uc.reg_write(getattr(x, 'UC_X86_REG_' + name), saved[name])
        uc.reg_write(x.UC_X86_REG_EFLAGS, 0x202)
        uc.reg_write(x.UC_X86_REG_MXCSR, 0x1f80)
        uc.reg_write(x.UC_X86_REG_RSP, STACK_ENTRY); uc.mem_write(STACK_ENTRY, struct.pack('<Q', STOP))
        uc.mem_write(STACK_ENTRY + 8, bytes(32))
        for i, value in enumerate(stack_args): uc.mem_write(STACK_ENTRY + 0x28 + i * 8, struct.pack('<Q', value))
        for reg, value in ((x.UC_X86_REG_RCX, receiver), (x.UC_X86_REG_RDX, rdx),
                           (x.UC_X86_REG_R8, r8), (x.UC_X86_REG_R9, r9)): uc.reg_write(reg, value)
        active.update(running=True, previous=None, fixture=None, finished=False, fixture_return=None, frames=[(STACK_ENTRY, STOP)])
        try:
            uc.emu_start(address, 0, count=budget)
            if not active['finished'] or uc.reg_read(x.UC_X86_REG_RIP) != STOP:
                raise ValueError('Tutorial state instruction budget exhausted or invalid return')
            if uc.reg_read(x.UC_X86_REG_RSP) != STACK_ENTRY + 8:
                raise ValueError('Tutorial state Win64 stack return differs')
            if any(uc.reg_read(getattr(x, 'UC_X86_REG_' + name)) != value for name, value in saved.items()):
                raise ValueError('Tutorial state Win64 nonvolatile register changed')
            if uc.reg_read(x.UC_X86_REG_MXCSR) & 0xffc0 != 0x1f80:
                raise ValueError('Tutorial state floating-point control mode changed')
            if bytes(uc.mem_read(STACK_START, 16)) != b'\xd1' * 16 or bytes(uc.mem_read(STACK_END - 16, 16)) != b'\xd2' * 16:
                raise ValueError('Tutorial state stack guard changed')
            h.abi_checks += 1; h.call_counts += 1
            return uc.reg_read(x.UC_X86_REG_RAX)
        except unicorn.UcError as error:
            raise ValueError(f'Tutorial state emulation failed at {uc.reg_read(x.UC_X86_REG_RIP):#x}: {error}') from error
        finally:
            active.update(running=False, fixture=None, previous=None)

    def validate():
        if active['running'] or h.call_counts != h.abi_checks or not h.call_counts:
            raise ValueError('Tutorial state execution or ABI check incomplete')
        return dict(call_counts=h.call_counts, abi_checks=h.abi_checks, read_checks=h.read_checks,
                    write_checks=h.write_checks, fixture_calls=h.fixture_calls,
                    entry_counts={hex(at): n for at, n in sorted(h.entry_counts.items())})

    h.raw, h.image, h.root = raw, image, Path(store.root)
    h.call, h.finish, h.add_fixture, h.validate = call, finish, add_fixture, validate
    h.set_global, h.write = set_global, write
    h.allow_read, h.allow_write, h.reset_regions = allow_read, allow_write, reset_regions
    return h
