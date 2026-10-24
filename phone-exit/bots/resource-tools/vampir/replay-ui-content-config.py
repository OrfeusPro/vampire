"""Native initial config-reader prefix; lookup/string-copy are fixtures, callback setup excluded."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('config_refresh', HERE / 'replay-nktileview-refresh.py')
refresh = importlib.util.module_from_spec(spec); spec.loader.exec_module(refresh)
native, getter, unicorn, x = refresh.native, refresh.getter, refresh.unicorn, refresh.x


def run(request):
    if request['source_sha256'] != getter.SHA or request['question'] != 'ui-nktileview-property-schema':
        raise ValueError('Другой источник / вопрос')
    if '0x1445c2c30' not in {f['address'] for f in request['functions']}:
        raise ValueError('Нет явного config-reader root')
    if native.capstone.__version__ != '5.0.6' or unicorn.__version__ != '2.1.4':
        raise ValueError('Изменились закреплённые инструменты')
    raw = Path(request['source']).read_bytes()
    if getter.sha(raw) != getter.SHA: raise ValueError('Изменился EXE')
    image = native.Image(raw); root = image.containing(0x1445c2c30)
    if root is None or image.pe.base + image.roots[root][0] != 0x1445c2c30:
        raise ValueError('Изменилась unwind граница')
    fragments = native.decode_ranges(image, {image.roots[root]})
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    if rows[0x1445c2c91]['operands'] != 'qword ptr [rax + 0x58]' or rows[0x1445c2caf]['direct_target'] != 0x14142a250:
        raise ValueError('Изменились lookup / assignment calls')
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    pages = {p for f in fragments for p in range((image.pe.base + f['begin_rva']) & ~4095,
            (image.pe.base + f['end_rva'] + 4095) & ~4095, 4096)}
    pages.update(a & ~4095 for f in fragments for r in f['instructions'] for a in r['rip_references'])
    pages.add(0x14142a250 & ~4095)
    for page in pages:
        uc.mem_map(page, 4096)
        try: offset = image.offset(page - image.pe.base)
        except ValueError: continue
        uc.mem_write(page, raw[offset:offset + 4096])
    base = 0x20000000; uc.mem_map(base, 0x20000)
    config, vtable, lookup, dest, string, section, key, stack = [base + p for p in
        (0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x6100, 0x10008)]
    uc.mem_write(config, struct.pack('<Q', vtable)); uc.mem_write(vtable + 0x58, struct.pack('<Q', lookup))
    uc.mem_write(section, 'NnCoreSetting\0'.encode('utf-16le')); uc.mem_write(key, 'ContentSubName\0'.encode('utf-16le'))
    state = {}
    def ret(machine, result=0):
        sp = machine.reg_read(x.UC_X86_REG_RSP); machine.reg_write(x.UC_X86_REG_RAX, result)
        machine.reg_write(x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(x.UC_X86_REG_RSP, sp + 8)
    def hook(machine, address, size, unused):
        if address == 0x1445c2cb4:
            state['boundary_reached'] = True; machine.emu_stop()
        elif address == lookup:
            state['lookup_calls'] += 1
            if tuple(machine.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)) != (config, section, key):
                raise ValueError('Config lookup не использует ожидаемый global object / section / key')
            sp = machine.reg_read(x.UC_X86_REG_RSP)
            state['filename_arg'] = int.from_bytes(machine.mem_read(sp + 0x28, 8), 'little')
            output = machine.reg_read(x.UC_X86_REG_R9)
            if bytes(machine.mem_read(output, 16)) != bytes(16):
                raise ValueError('Временная строка не инициализирована нулём')
            text = state['value'].encode('utf-16le') + b'\0\0'
            if state['found']:
                machine.mem_write(string, text)
                machine.mem_write(output, struct.pack('<Qii', 0, 0, 0) if state['zero_length'] else
                    struct.pack('<Qii', string, len(text) // 2, len(text) // 2))
            ret(machine, int(state['found']))
        elif address == 0x14142a250:
            a, b, count = [machine.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
            if a != dest or b != (0 if state['zero_length'] else string) or count != len(state['value'].encode('utf-16le')) // 2:
                raise ValueError('Неверные аргументы назначения строки')
            state['assignments'].append(dict(destination=hex(a), utf16_units=count))
            # Record string helper arguments; do not emulate its allocation / destination writes.
            ret(machine, dest)
        elif not (0x1445c2c30 <= address and address + size <= 0x1445c2cb4):
            raise ValueError('Исполнение вне initial config prefix: ' + hex(address))
    uc.hook_add(unicorn.UC_HOOK_CODE, hook)
    cases = []
    for found in (False, True):
        for value, zero_length in [(s, False) for s in ('', 'RED', 'Other', 'Тест', 'A/B', 'A😀')] + ([('', True)] if found else []):
            for ignored_argument in (0, base + 0x9000):
                state.clear(); state.update(found=found, value=value, zero_length=zero_length,
                    lookup_calls=0, assignments=[], boundary_reached=False)
                uc.mem_write(dest, b'\xa5' * 32); uc.mem_write(stack - 0x400, bytes(0x800))
                uc.mem_write(0x14b564640, struct.pack('<i', 1)); uc.mem_write(0x14b564638, struct.pack('<Q', config))
                for reg, val in ((x.UC_X86_REG_RCX, ignored_argument), (x.UC_X86_REG_RDX, dest),
                        (x.UC_X86_REG_R8, section), (x.UC_X86_REG_R9, key), (x.UC_X86_REG_RSP, stack)):
                    uc.reg_write(reg, val)
                uc.emu_start(0x1445c2c30, base + 0x1f000, count=256)
                if not state['boundary_reached'] or state['lookup_calls'] != 1 or len(state['assignments']) != int(found):
                    raise ValueError('Неверная ветвь missing / present')
                if bytes(uc.mem_read(dest, 32)) != b'\xa5' * 32 or state['filename_arg'] != 0x14b2e5678:
                    raise ValueError('Посторонняя запись назначения или другой config filename object')
                cases.append(dict(found_fixture=found, value_fixture=value, ignored_first_argument=hex(ignored_argument),
                    zero_length_fstring_fixture=zero_length, lookup_calls=state['lookup_calls'],
                    assignment_calls=state['assignments'].copy(), stopped_before_callback_setup=True))
    return dict(source_sha256=getter.SHA, fragments=fragments, cases=cases,
        limits=['Only initial prefix to 1445c2cb4 executes; no callback registration / destructor / complete return.',
            'Global config presence is fixed nonzero. Absent global pointer and invalid engine state are not modeled.',
            'Virtual lookup and string assignment are fixtures; native config precedence and allocation not executed.',
            'Missing lookup bypasses assignment here, not a complete default/override or live settings proof.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists(): parser.error('Прежний отчёт не перезаписывается')
    result = run(json.loads(args.request.read_text('utf-8'))); result['replay_sha256'] = getter.sha(Path(__file__).read_bytes())
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(cases=len(result['cases'])), ensure_ascii=False))
