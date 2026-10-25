"""Native FString assignment body with explicit resize/copy services; no game process."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('assignment_hash', HERE / 'replay-ui-config-hash.py')
hash_code = importlib.util.module_from_spec(spec); spec.loader.exec_module(hash_code)
native, getter, unicorn, x = hash_code.native, hash_code.getter, hash_code.unicorn, hash_code.x
ASSIGN = 0x1414277b0
RESIZE, COPY = 0x141438050, 0x1487f5ab9


def run(request):
    if request['source_sha256'] != getter.SHA or request['question'] != 'ui-nktileview-property-schema':
        raise ValueError('Другой источник / вопрос')
    if hex(ASSIGN) not in {f['address'] for f in request['functions']}:
        raise ValueError('Нет явного assignment root')
    if native.capstone.__version__ != '5.0.6' or unicorn.__version__ != '2.1.4':
        raise ValueError('Изменились закреплённые инструменты')
    raw = Path(request['source']).read_bytes()
    if getter.sha(raw) != getter.SHA: raise ValueError('Изменился EXE')
    image = native.Image(raw); row = image.containing(ASSIGN)
    if row is None or image.pe.base + image.roots[row][0] != ASSIGN:
        raise ValueError('Изменился unwind root')
    fragments = native.decode_ranges(image, {image.roots[row]})
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    if rows[0x141427801]['direct_target'] != RESIZE or rows[0x141427830]['direct_target'] != COPY:
        raise ValueError('Изменились resize / byte-copy callees')
    ranges = [(image.pe.base + f['begin_rva'], image.pe.base + f['end_rva']) for f in fragments]
    pages = {p for a, b in ranges for p in range(a & ~4095, (b + 4095) & ~4095, 4096)}
    pages.update(a & ~4095 for a in (RESIZE, COPY))
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    for page in pages:
        uc.mem_map(page, 4096); offset = image.offset(page - image.pe.base)
        uc.mem_write(page, raw[offset:offset + 4096])
    base = 0x20000000; uc.mem_map(base, 0x20000)
    dest, old, source, new, stack, stop = [base + a for a in (0x1000, 0x2000, 0x4000, 0x6000, 0x10008, 0x1f000)]
    state = {}
    def ret(result):
        sp = uc.reg_read(x.UC_X86_REG_RSP)
        uc.reg_write(x.UC_X86_REG_RAX, result)
        uc.reg_write(x.UC_X86_REG_RIP, int.from_bytes(uc.mem_read(sp, 8), 'little'))
        uc.reg_write(x.UC_X86_REG_RSP, sp + 8)
    def hook(machine, address, size, unused):
        if address not in (RESIZE, COPY):
            if not any(a <= address and address + size <= b for a, b in ranges):
                raise ValueError('Исполнение вне assignment / явных services: ' + hex(address))
            return
        rcx, rdx, r8 = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        if address == RESIZE:
            if rcx != dest or rdx != state['count'] or bytes(uc.mem_read(dest + 8, 4)) != bytes(4):
                raise ValueError('Неверные resize arguments / native count reset')
            state['resizes'] += 1
            uc.mem_write(dest, struct.pack('<Q', new if rdx else 0))
            uc.mem_write(dest + 12, struct.pack('<i', rdx + state['extra'] if rdx else 0))
            ret(0xdeadbeef)
        else:
            target = new if state['resizes'] else old
            if (rcx, rdx, r8) != (target, source, state['count'] * 2):
                raise ValueError('Неверные copy arguments')
            state['copies'] += 1; uc.mem_write(rcx, bytes(uc.mem_read(rdx, r8))); ret(rcx)
    uc.hook_add(unicorn.UC_HOOK_CODE, hook)
    def execute(pointer):
        uc.mem_write(stack - 0x400, b'\x91' * 0x800); uc.mem_write(stack, struct.pack('<Q', stop))
        for reg, value in ((x.UC_X86_REG_RCX, dest), (x.UC_X86_REG_RDX, pointer),
                          (x.UC_X86_REG_RBX, 0x123456789abcdef0), (x.UC_X86_REG_RSI, 0x23456789abcdef01),
                          (x.UC_X86_REG_RDI, 0x3456789abcdef012), (x.UC_X86_REG_RSP, stack)):
            uc.reg_write(reg, value)
        uc.emu_start(ASSIGN, stop, count=4096)
        if uc.reg_read(x.UC_X86_REG_RIP) != stop or uc.reg_read(x.UC_X86_REG_RSP) != stack + 8 or uc.reg_read(x.UC_X86_REG_RAX) != dest:
            raise ValueError('Нет полного assignment return')
        if tuple(uc.reg_read(r) for r in (x.UC_X86_REG_RBX, x.UC_X86_REG_RSI, x.UC_X86_REG_RDI)) != (
                0x123456789abcdef0, 0x23456789abcdef01, 0x3456789abcdef012):
            raise ValueError('Не сохранены nonvolatile registers')
    cases = []
    for value in (None, '', 'RED', 'Тест', 'A😀', 'A/B', 'Long' * 20, 'A\0B'):
        data = (value + '\0').encode('utf-16le') if value is not None else b''
        prefix = (value.split('\0', 1)[0] if value else '').encode('utf-16le')
        count = len(prefix) // 2 + 1 if prefix else 0
        for old_present, capacity in ((False, 0), (True, 0), (True, 1), (True, 8), (True, 128)):
            for extra in (0, 7):
                initial = struct.pack('<Qii', old if old_present else 0, min(capacity, 3), capacity)
                state.clear(); state.update(count=count, extra=extra, resizes=0, copies=0)
                uc.mem_write(dest - 8, b'\xa5' * 8 + initial + b'\xa5' * 8)
                uc.mem_write(old, b'\x61' * 512); uc.mem_write(new, b'\x62' * 512)
                uc.mem_write(source - 8, b'\x7a' * 8 + data + b'\x7b' * 8)
                pointer = source if value is not None else 0
                execute(pointer)
                identity = pointer == (old if old_present else 0)
                resize = not identity and capacity != count
                target = new if resize and count else 0 if resize else old if old_present else 0
                expected = initial if identity else struct.pack('<Qii', target, count, count + extra if resize and count else count if resize else capacity)
                if bytes(uc.mem_read(dest - 8, 32)) != b'\xa5' * 8 + expected + b'\xa5' * 8:
                    raise ValueError('Неверные native pointer/count/capacity / guards')
                if (state['resizes'], state['copies']) != (int(resize), int(not identity and count > 0)):
                    raise ValueError('Неверные identity / resize / copy branches')
                copied = prefix + b'\0\0' if not identity and count else b''
                for address, fill in ((old, b'\x61'), (new, b'\x62')):
                    expected_data = copied + fill * (512 - len(copied)) if copied and address == target else fill * 512
                    if bytes(uc.mem_read(address, 512)) != expected_data:
                        raise ValueError('Повреждены copy bytes / buffer guards')
                if bytes(uc.mem_read(source - 8, len(data) + 16)) != b'\x7a' * 8 + data + b'\x7b' * 8:
                    raise ValueError('Изменён source')
                cases.append(dict(value_fixture=value, old_present=old_present, capacity_fixture=capacity,
                    extra_capacity_fixture=extra, identity=identity, native_units=count,
                    resize_calls=state['resizes'], copy_calls=state['copies'], complete_return=True))
    identities = []
    for count, capacity in ((0, 0), (0, 8), (4, 4), (4, 128)):
        state.clear(); state.update(count=count, extra=0, resizes=0, copies=0)
        initial = struct.pack('<Qii', old, count, capacity); uc.mem_write(dest, initial)
        # No terminator: identity must exit before scanning the source buffer.
        uc.mem_write(old, b'\x61' * 512); execute(old)
        if bytes(uc.mem_read(dest, 16)) != initial or state['resizes'] or state['copies'] or bytes(uc.mem_read(old, 512)) != b'\x61' * 512:
            raise ValueError('Identity assignment не сохранил object / buffer')
        identities.append(dict(count=count, capacity=capacity, unchanged=True))
    return dict(source_sha256=getter.SHA, fragments=fragments, cases=cases, identity_cases=identities,
        limits=['Complete native assignment body; resize and byte copy are explicit fixtures.',
            'Resize fixture always supplies capacity >= requested; real allocator / growth fallback / failure / overflow not executed.',
            'Nonidentity scans until UTF16 NUL; identity exits before scan; counted clone has different semantics.',
            'Synthetic old pointer/capacity combinations and embedded NUL are boundary probes, not valid settings contracts.',
            'No registration/consumer integration, active config, persistence or Brush proof.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists(): parser.error('Прежний отчёт не перезаписывается')
    result = run(json.loads(args.request.read_text('utf-8')))
    result['replay_sha256'] = getter.sha(Path(__file__).read_bytes())
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(cases=len(result['cases']), identity_cases=len(result['identity_cases']))))
