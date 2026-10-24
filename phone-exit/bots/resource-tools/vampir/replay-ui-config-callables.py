"""Source-bound string-copy callables; container insertion is static, event dispatch unknown."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('callables_refresh', HERE / 'replay-nktileview-refresh.py')
refresh = importlib.util.module_from_spec(spec); spec.loader.exec_module(refresh)
native, getter, unicorn, x = refresh.native, refresh.getter, refresh.unicorn, refresh.x
ROOTS = (0x1445c1f50, 0x1445c67a0, 0x1445c78d0)
LEAF = 0x1445c7970
ASSIGN = 0x1414277b0
ALLOCATE = 0x141436ed0
COPY = 0x1487f5ab9


def run(request, leaf_request):
    for r in (request, leaf_request):
        if r['source_sha256'] != getter.SHA or r['question'] != 'ui-nktileview-property-schema':
            raise ValueError('Другой источник / вопрос')
    if not {hex(a) for a in ROOTS} <= {f['address'] for f in request['functions']}:
        raise ValueError('Нет явных roots')
    if hex(LEAF) not in {f['address'] for f in leaf_request['functions']}:
        raise ValueError('Нет явного задания leaf')
    if native.capstone.__version__ != '5.0.6' or unicorn.__version__ != '2.1.4':
        raise ValueError('Изменились закреплённые инструменты')
    raw = Path(request['source']).read_bytes()
    if getter.sha(raw) != getter.SHA: raise ValueError('Изменился EXE')
    image = native.Image(raw); selected = set()
    for a in ROOTS:
        row = image.containing(a)
        if row is None or image.pe.base + image.roots[row][0] != a:
            raise ValueError('Изменился unwind root')
        selected.add(image.roots[row])
    fragments = native.decode_ranges(image, selected)
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    for at, target in ((0x1445c78e2, 0x1445c67a0), (0x1445c67d9, ALLOCATE),
                       (0x1445c67ec, COPY), (0x1445c203d, 0x1445c4f60),
                       (0x1445c2072, 0x141425d60), (0x1445c208b, 0x1445d8430)):
        if rows[at]['direct_target'] != target:
            raise ValueError('Изменилась цепочка вызовов')
    for at, expected in ((0x1445c1f83, ('imul', 'rcx, rsi, 0xb0')),
                         (0x1445c2007, ('imul', 'rdi, rax, 0xb0')),
                         (0x1445c2026, ('mov', 'qword ptr [rcx], r14')),
                         (0x1445c2035, ('mov', 'qword ptr [rcx + 8], r14'))):
        if (rows[at]['mnemonic'], rows[at]['operands']) != expected:
            raise ValueError('Изменилась структура insertion / переноса ключа')
    if image.containing(LEAF) is not None:
        raise ValueError('У leaf появилась unwind запись')
    offset = image.offset(LEAF - image.pe.base)
    leaf_bytes = raw[offset:offset + 11]
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    leaf_rows = [(q.mnemonic, q.op_str) for q in decoder.disasm(leaf_bytes, LEAF)]
    if leaf_rows != [('mov', 'rdx, qword ptr [rdx]'), ('mov', 'rcx, qword ptr [rcx]'), ('jmp', hex(ASSIGN))]:
        raise ValueError('Изменился leaf thunk')
    if raw[offset + 11:offset + 16] != b'\xcc' * 5:
        raise ValueError('Изменилась граница leaf / INT3 padding')
    # Entry-only analysis of insertion: do not execute its storage / hashing / callable-copy helpers.
    registration = dict(root=hex(ROOTS[0]), entry_stride='0xb0',
        status='static_sparse_container_shape_not_event_dispatch',
        callees=[hex(a) for a in sorted({r['direct_target'] for f in fragments for r in f['instructions']
                 if f['root_begin_rva'] == ROOTS[0] - image.pe.base and r['call'] and r['direct_target']})])
    ranges = [(image.pe.base + f['begin_rva'], image.pe.base + f['end_rva']) for f in fragments
              if f['root_begin_rva'] != ROOTS[0] - image.pe.base] + [(LEAF, LEAF + 11)]
    fixtures = {ALLOCATE, COPY, ASSIGN}
    pages = {p for a, b in ranges for p in range(a & ~4095, (b + 4095) & ~4095, 4096)}
    pages.update(a & ~4095 for a in fixtures)
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    for page in pages:
        uc.mem_map(page, 4096)
        off = image.offset(page - image.pe.base)
        uc.mem_write(page, raw[off:off + 4096])
    base = 0x20000000; uc.mem_map(base, 0x20000)
    source, text, capture, output, buffer, arg, stack, stop = [base + a for a in
        (0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x10008, 0x1f000)]
    state = {}
    def ret(machine, result):
        sp = machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RAX, result)
        machine.reg_write(x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(x.UC_X86_REG_RSP, sp + 8)
    def hook(machine, address, size, unused):
        if address not in fixtures:
            if not any(a <= address and address + size <= b for a, b in ranges):
                raise ValueError('Исполнение вне выбранных callables: ' + hex(address))
            return
        rcx, rdx, r8 = [machine.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        if address == ALLOCATE:
            if rdx != state['units'] or r8 != 0 or bytes(machine.mem_read(rcx, 12)) != struct.pack('<Qi', 0, rdx):
                raise ValueError('Неверный запрос allocation')
            state['allocations'] += 1
            machine.mem_write(rcx, struct.pack('<Q', buffer))
            machine.mem_write(rcx + 12, struct.pack('<i', rdx + state['capacity_extra']))
            ret(machine, 0xdeadbeef)
        elif address == COPY:
            if (rcx, rdx, r8) != (buffer, text, state['units'] * 2):
                raise ValueError('Неверные аргументы byte copy')
            state['copies'] += 1
            machine.mem_write(rcx, bytes(machine.mem_read(rdx, r8)))
            ret(machine, rcx)
        else:
            if (rcx, rdx) != (output, state['leaf_string']):
                raise ValueError('Leaf не разыменовал оба аргумента')
            state['assignments'] += 1
            # Assignment implementation deliberately excluded; only forwarding ABI is tested.
            ret(machine, output)
    uc.hook_add(unicorn.UC_HOOK_CODE, hook)
    clone_cases = []
    values = [(s.encode('utf-16le') + b'\0\0') for s in ('', 'RED', 'Тест', 'A😀', '/Game/RED', 'A/B', 'A\0B')] + [b'']
    for data in values:
        for capacity_extra in (0, 7):
            for entry in (0x1445c67a0, 0x1445c78d0):
                state.clear(); state.update(units=len(data) // 2, capacity_extra=capacity_extra, allocations=0, copies=0)
                uc.mem_write(stack - 0x400, b'\x91' * 0x800); uc.mem_write(stack, struct.pack('<Q', stop))
                uc.mem_write(text, data + b'\x7a' * 16)
                source_bytes = struct.pack('<Qii', text if data else 0, len(data) // 2, len(data) // 2 + 9)
                uc.mem_write(source, source_bytes); uc.mem_write(capture, struct.pack('<Q', source))
                uc.mem_write(output - 8, b'\xa5' * 32); uc.mem_write(buffer, b'\x5a' * 128)
                for reg, val in ((x.UC_X86_REG_RCX, capture if entry == 0x1445c67a0 else output),
                                 (x.UC_X86_REG_RDX, output if entry == 0x1445c67a0 else capture),
                                 (x.UC_X86_REG_RSP, stack)):
                    uc.reg_write(reg, val)
                uc.emu_start(entry, stop, count=256)
                expected = struct.pack('<Qii', buffer if data else 0, len(data) // 2,
                    len(data) // 2 + capacity_extra if data else 0)
                if uc.reg_read(x.UC_X86_REG_RIP) != stop or uc.reg_read(x.UC_X86_REG_RAX) != output:
                    raise ValueError('Native callable не вернул output')
                if bytes(uc.mem_read(output, 16)) != expected or bytes(uc.mem_read(output - 8, 8)) != b'\xa5' * 8 or bytes(uc.mem_read(output + 16, 8)) != b'\xa5' * 8:
                    raise ValueError('Неверные поля / границы результата')
                if bytes(uc.mem_read(buffer, 128)) != data + b'\x5a' * (128 - len(data)):
                    raise ValueError('Неверное содержимое clone')
                if bytes(uc.mem_read(source, 16)) != source_bytes or bytes(uc.mem_read(text, len(data) + 16)) != data + b'\x7a' * 16:
                    raise ValueError('Изменён источник')
                if state['allocations'] != int(bool(data)) or state['copies'] != int(bool(data)):
                    raise ValueError('Неверная ветвь zero length')
                clone_cases.append(dict(entry=hex(entry), input_utf16_hex=data.hex(), source_count=len(data) // 2,
                    capacity_extra_fixture=capacity_extra, allocations=state['allocations'], copies=state['copies'], complete_return=True))
    leaf_cases = []
    for string_ptr in (0, text, text + 2):
        state.clear(); state.update(leaf_string=string_ptr, assignments=0)
        uc.mem_write(capture, struct.pack('<Q', output)); uc.mem_write(arg, struct.pack('<Q', string_ptr))
        uc.mem_write(output, b'\xa5' * 16); uc.mem_write(stack, struct.pack('<Q', stop))
        for reg, val in ((x.UC_X86_REG_RCX, capture), (x.UC_X86_REG_RDX, arg), (x.UC_X86_REG_RSP, stack)):
            uc.reg_write(reg, val)
        uc.emu_start(LEAF, stop, count=32)
        if uc.reg_read(x.UC_X86_REG_RIP) != stop or uc.reg_read(x.UC_X86_REG_RAX) != output or state['assignments'] != 1:
            raise ValueError('Leaf не завершил tail forwarding')
        if bytes(uc.mem_read(output, 16)) != b'\xa5' * 16:
            raise ValueError('Unexpected write from forwarding-only fixture')
        leaf_cases.append(dict(string_pointer=hex(string_ptr), forwarded=True, assignment_fixture=True))
    return dict(source_sha256=getter.SHA, fragments=fragments, registration=registration,
        leaf=dict(address=hex(LEAF), boundary='11 exact bytes then 5 INT3; no unwind; direct tail to known root',
            bytes=leaf_bytes.hex(), sha256=getter.sha(leaf_bytes)), clone_cases=clone_cases, leaf_cases=leaf_cases,
        limits=['Allocation and byte-copy are fixtures; native allocator, ownership and malformed counts not tested.',
            'String clone native bodies return completely; assignment leaf only forwards to a fixture.',
            'Sparse-container insertion only statically decoded; dispatch, lifetime and update events unknown.',
            'No active config, precedence, successful resource load or Brush proof.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--leaf-request', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists(): parser.error('Прежний отчёт не перезаписывается')
    result = run(json.loads(args.request.read_text('utf-8')), json.loads(args.leaf_request.read_text('utf-8')))
    result['replay_sha256'] = getter.sha(Path(__file__).read_bytes())
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(clone_cases=len(result['clone_cases']), leaf_cases=len(result['leaf_cases']))))
