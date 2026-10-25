"""Native path-copy and config-load wrappers; provider/context/loader/string services are explicit fixtures."""
import argparse
import importlib.util
import itertools
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('load_hash', HERE / 'replay-ui-config-hash.py')
hash_code = importlib.util.module_from_spec(spec); spec.loader.exec_module(hash_code)
native, getter, unicorn, x = hash_code.native, hash_code.getter, hash_code.unicorn, hash_code.x
ROOTS = (0x14157cf70, 0x141534f70)
FIXTURES = {0x14144b5b0: 'provide_path', 0x141426b30: 'copy_string', 0x141547b10: 'construct_context',
    0x141483080: 'free_string', 0x1414277b0: 'override_string', 0x14155bbe0: 'load_context',
    0x141549ba0: 'destroy_context', 0x1487e8ce0: 'cookie'}


def run(request):
    if request['source_sha256'] != getter.SHA or request['question'] != 'ui-nktileview-property-schema':
        raise ValueError('Другой источник / вопрос')
    if not {hex(a) for a in ROOTS} <= {f['address'] for f in request['functions']}:
        raise ValueError('Нет явных wrappers')
    if native.capstone.__version__ != '5.0.6' or unicorn.__version__ != '2.1.4':
        raise ValueError('Изменились закреплённые инструменты')
    raw = Path(request['source']).read_bytes()
    if getter.sha(raw) != getter.SHA: raise ValueError('Изменился EXE')
    image = native.Image(raw); selected = set()
    for address in ROOTS:
        row = image.containing(address)
        if row is None or image.pe.base + image.roots[row][0] != address: raise ValueError('Изменился unwind root')
        selected.add(image.roots[row])
    fragments = native.decode_ranges(image, selected)
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    for at, target in ((0x14157cf79, 0x14144b5b0), (0x141534fd0, 0x141547b10),
                       (0x14153502a, 0x14155bbe0), (0x141535037, 0x141549ba0)):
        if rows[at]['direct_target'] != target: raise ValueError('Изменились wrapper callees')
    ranges = [(image.pe.base + f['begin_rva'], image.pe.base + f['end_rva']) for f in fragments]
    pages = {p for a, b in ranges for p in range(a & ~4095, (b + 4095) & ~4095, 4096)}
    pages.update(a & ~4095 for f in fragments for r in f['instructions'] for a in r['rip_references'])
    pages.update(a & ~4095 for a in FIXTURES)
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    for page in pages:
        uc.mem_map(page, 4096)
        try: off = image.offset(page - image.pe.base)
        except ValueError: continue
        uc.mem_write(page, raw[off:off + 4096])
    base = 0x20000000; uc.mem_map(base, 0x20000)
    output, original, copy, override, file_obj, category, global_obj, stack, stop = [base + a for a in
        (0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x5100, 0x5200, 0x10008, 0x1f000)]
    cookie = 0x123456789abcdef0; uc.mem_write(0x14b271780, struct.pack('<Q', cookie))
    state = {}
    def qword(at): return int.from_bytes(uc.mem_read(at, 8), 'little')
    def ret(result=0):
        sp = uc.reg_read(x.UC_X86_REG_RSP); uc.reg_write(x.UC_X86_REG_RAX, result)
        uc.reg_write(x.UC_X86_REG_RIP, qword(sp)); uc.reg_write(x.UC_X86_REG_RSP, sp + 8)
    def hook(machine, address, size, unused):
        if address not in FIXTURES:
            if not any(a <= address and address + size <= b for a, b in ranges):
                raise ValueError('Исполнение вне path/load wrappers: ' + hex(address))
            return
        rcx, rdx, r8, r9 = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        name = FIXTURES[address]; state['calls'].append(name)
        if name == 'provide_path': ret(state['input_pointer'])
        elif name == 'copy_string':
            if rdx != state['input_pointer']: raise ValueError('Неверный строковый source')
            state['copied_object'] = rcx
            encoded = state['encoded']
            if encoded: uc.mem_write(copy, encoded)
            uc.mem_write(rcx, struct.pack('<Qii', copy if encoded else 0, len(encoded) // 2, len(encoded) // 2)); ret(rcx)
        elif name == 'construct_context':
            if (rdx, r8 & 255, r9, qword(uc.reg_read(x.UC_X86_REG_RSP) + 0x28)) != (global_obj, 1, state['copied_object'], 0):
                raise ValueError('Неверный context constructor ABI')
            if bytes(uc.mem_read(r9, 16)) != struct.pack('<Qii', copy if state['encoded'] else 0, len(state['encoded']) // 2, len(state['encoded']) // 2):
                raise ValueError('В constructor передан другой temporary')
            state['context'] = rcx; model = bytearray(b'\xa5' * 0x190); model[0x50:0x60] = bytes(16)
            uc.mem_write(rcx, bytes(model)); ret(rcx)
        elif name == 'free_string':
            if rcx != copy or not state['encoded']: raise ValueError('Неверный temporary free')
            uc.mem_write(rcx, b'\xdd' * len(state['encoded'])); ret()
        elif name == 'override_string':
            if (rcx, rdx) != (state['context'] + 0x50, override) or not state['override']:
                raise ValueError('Неверный override slot / pointer')
            uc.mem_write(rcx, struct.pack('<Qii', override, 4, 4)); ret(rcx)
        elif name in ('load_context', 'destroy_context'):
            if rcx != state['context']: raise ValueError('Передан другой context')
            if name == 'load_context' and (rdx, r8) != (category, file_obj): raise ValueError('Неверный loader category / output object')
            expected = bytearray(b'\xa5' * 0x190)
            expected[0x50:0x60] = struct.pack('<Qii', override, 4, 4) if state['override'] else bytes(16)
            expected[0x181] = state['flag6'] & 255; expected[0x182] = state['flag4'] & 255; expected[0x183] = state['flag7'] & 255
            if bytes(uc.mem_read(rcx, 0x190)) != bytes(expected): raise ValueError('Неверные context flags / override / surrounding bytes')
            ret(state['loader_result'] if name == 'load_context' else 0)
        else:
            if rcx != cookie: raise ValueError('Неверный cookie')
            ret(uc.reg_read(x.UC_X86_REG_RAX))  # preserve actual native result, not the fixture oracle
    uc.hook_add(unicorn.UC_HOOK_CODE, hook)
    def start(entry, regs, fifth=0, sixth=0, seventh=0, eighth=0, ninth=0):
        uc.mem_write(stack - 0x1000, b'\x91' * 0x1100); uc.mem_write(stack, struct.pack('<Q', stop))
        uc.mem_write(stack + 0x28, struct.pack('<5Q', fifth, sixth, seventh, eighth, ninth))
        uc.reg_write(x.UC_X86_REG_RSP, stack)
        for reg, value in regs: uc.reg_write(reg, value)
        uc.emu_start(entry, stop, count=1024)
        if uc.reg_read(x.UC_X86_REG_RIP) != stop or uc.reg_read(x.UC_X86_REG_RSP) != stack + 8:
            raise ValueError('Нет полного wrapper return')
    path_cases = []
    for value in (None, '', 'Demo/Config', 'Тест', 'A😀', 'A\0B'):
        data = (value + '\0').encode('utf-16le') if value else b''
        state.clear(); state.update(calls=[], input_pointer=original if value is not None else 0, encoded=data)
        if value is not None: uc.mem_write(original, (value + '\0').encode('utf-16le'))
        uc.mem_write(output - 8, b'\x6a' * 32)
        start(0x14157cf70, [(x.UC_X86_REG_RCX, output)])
        if state['calls'] != ['provide_path', 'copy_string'] or uc.reg_read(x.UC_X86_REG_RAX) != output:
            raise ValueError('Path wrapper не вернул copied object')
        expected = struct.pack('<Qii', copy if data else 0, len(data) // 2, len(data) // 2)
        if bytes(uc.mem_read(output - 8, 32)) != b'\x6a' * 8 + expected + b'\x6a' * 8:
            raise ValueError('Path copy fields / guard')
        path_cases.append(dict(provider_fixture=value, complete_return=True))
    load_cases = []
    for input_kind, flag4, flag5, flag6, flag7, override_present, result in itertools.product(
            (None, '', 'Initial'), (0, 1, 2, 255), (0, 255), (0, 2), (0, 255), (False, True), (0, 1, 0x1234, 0x123400)):
        data = (input_kind + '\0').encode('utf-16le') if input_kind else b''
        state.clear(); state.update(calls=[], input_pointer=original if input_kind is not None else 0, encoded=data,
            override=override_present, flag4=flag4, flag6=flag6, flag7=flag7, loader_result=result)
        if input_kind is not None: uc.mem_write(original, (input_kind + '\0').encode('utf-16le'))
        uc.mem_write(override, 'Alt\0'.encode('utf-16le'))
        start(0x141534f70, [(x.UC_X86_REG_RCX, file_obj), (x.UC_X86_REG_RDX, category),
            (x.UC_X86_REG_R8, state['input_pointer']), (x.UC_X86_REG_R9, flag4)],
            flag5, flag6, flag7, override if override_present else 0, global_obj)
        expected_calls = ['copy_string', 'construct_context'] + (['free_string'] if data else []) + (
            ['override_string'] if override_present else []) + ['load_context', 'destroy_context', 'cookie']
        if state['calls'] != expected_calls or uc.reg_read(x.UC_X86_REG_RAX) != result & 255:
            raise ValueError('Неверный порядок services / loader result forwarding')
        load_cases.append(dict(input_fixture=input_kind, flag4=flag4, ignored_flag5=flag5,
            flag6=flag6, flag7=flag7, override_fixture=override_present, loader_result=result,
            forwarded_low_byte=result & 255, complete_return=True))
    return dict(source_sha256=getter.SHA, fragments=fragments, path_cases=path_cases, load_cases=load_cases,
        context_fields=dict(override_string='0x50', flag6='0x181', flag4='0x182', flag7='0x183'),
        limits=['Complete native wrappers only; provider/string copy/context construction/override/loader/destructor/free/cookie are fixtures.',
            'Argument5 is not consumed in this wrapper; actual source meaning of flags/objects unknown.',
            'Cookie fixture preserves incoming native EAX unchanged; real cookie machinery not executed.',
            'Provider fixture payloads do not establish actual path; loader fixture does not read files or establish precedence.',
            'No callback registration/UI application/persistence/active config proof.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists(): parser.error('Прежний отчёт не перезаписывается')
    result = run(json.loads(args.request.read_text('utf-8')))
    result['replay_sha256'] = getter.sha(Path(__file__).read_bytes())
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(path_cases=len(result['path_cases']), load_cases=len(result['load_cases']))))
