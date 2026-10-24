"""Native packing prefix and complete cached-count exits; downstream layout is excluded."""
import argparse
import importlib.util
import itertools
import json
import math
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
refresh = load('packing_refresh', 'replay-nktileview-refresh.py')
imports = load('packing_imports', 'build-object-zero-init-code.py')
native, getter, unicorn, x = refresh.native, refresh.getter, refresh.unicorn, refresh.x


def run(request):
    if request['source_sha256'] != getter.SHA or request['question'] != 'ui-nktileview-property-schema':
        raise ValueError('Другой источник / вопрос')
    if '0x144626640' not in {f['address'] for f in request['functions']}:
        raise ValueError('Нет явного packing root в задании')
    if native.capstone.__version__ != '5.0.6' or unicorn.__version__ != '2.1.4':
        raise ValueError('Изменился закреплённый декодер / emulator')
    raw = Path(request['source']).read_bytes()
    if getter.sha(raw) != getter.SHA:
        raise ValueError('Изменился EXE')
    image = native.Image(raw); root = image.containing(0x144626640)
    if root is None or image.pe.base + image.roots[root][0] != 0x144626640:
        raise ValueError('Изменилась граница root')
    fragments = native.decode_ranges(image, {image.roots[root]})
    # Import identity is established from PE tables, not assumed from call-site math.
    thunk = 0x1487f5ba3; off = image.offset(thunk - image.pe.base)
    if raw[off:off + 2] != b'\xff\x25':
        raise ValueError('Изменился import thunk')
    iat = thunk + 6 + struct.unpack_from('<i', raw, off + 2)[0]
    imported = imports.import_at(raw, image, iat)
    if (imported['dll'].lower(), imported['name']) != ('api-ms-win-crt-math-l1-1-0.dll', 'fmodf'):
        raise ValueError('Не подтверждён импорт fmodf')
    ranges = [(image.pe.base + f['begin_rva'], image.pe.base + f['end_rva']) for f in fragments]
    pages = {p for a, b in ranges for p in range(a & ~4095, (b + 4095) & ~4095, 4096)}
    pages.update(a & ~4095 for f in fragments for row in f['instructions'] for a in row['rip_references'])
    pages.update(a & ~4095 for a in (thunk, 0x14462f090, 0x1487e8ce0))
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    for page in pages:
        uc.mem_map(page, 4096); offset = image.offset(page - image.pe.base)
        uc.mem_write(page, raw[offset:offset + 4096])
    base = 0x20000000; uc.mem_map(base, 0x20000)
    obj, stack, stop = (base + p for p in (0x1000, 0x10000, 0x1f000))
    state = {}
    def float_reg(machine, reg):
        return struct.unpack('<f', (machine.reg_read(reg) & 0xffffffff).to_bytes(4, 'little'))[0]
    def ret(machine):
        sp = machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(x.UC_X86_REG_RSP, sp + 8)
    def hook(machine, address, size, unused):
        if address == thunk:
            a = float_reg(machine, x.UC_X86_REG_XMM0); b = float_reg(machine, x.UC_X86_REG_XMM1)
            result = struct.pack('<f', math.fmod(a, b))
            machine.reg_write(x.UC_X86_REG_XMM0, int.from_bytes(result, 'little')); state['fmod_calls'] += 1
            ret(machine)
        elif address == 0x1487e8ce0:
            # Stack-cookie validation is an explicit no-op fixture.
            ret(machine)
        elif address == 0x14462f090:
            state['entered_recalculation'] = True
            machine.emu_stop()  # Do not execute item enumeration or any downstream layout.
        elif address == 0x144626706:
            state['calculated_count'] = machine.reg_read(x.UC_X86_REG_ESI) & 0xffffffff
        elif not any(a <= address and address + size <= b for a, b in ranges):
            raise ValueError('Исполнение вне ограниченного prefix / exit: ' + hex(address))
    uc.hook_add(unicorn.UC_HOOK_CODE, hook)
    fixtures = [dict(view=(100, 150), size=(20, 30), gap=(5, 10), inset=(0, 2)),
                dict(view=(19, 29), size=(20, 30), gap=(5, 10), inset=(0, 0)),
                dict(view=(120, 150), size=(20, 30), gap=(5, 10), inset=(0, 0)),
                dict(view=(99, 139), size=(20, 30), gap=(5, 10), inset=(2, 3)),
                dict(view=(20, 30), size=(20, 30), gap=(0, 0), inset=(0, 0)),
                dict(view=(200, 300), size=(20, 30), gap=(0, 0), inset=(0, 0)),
                dict(view=(10, 10), size=(1, 2), gap=(1, 2), inset=(1, 1)),
                dict(view=(41, 61), size=(20, 30), gap=(1, 1), inset=(0, 0))]
    cases = []
    for data, axis, forced, same_cache, override in itertools.product(fixtures, (0, 1), (0, 1), (False, True), (0, 1)):
        dimension = 0 if axis else 1
        available = data['view'][dimension] - 2 * data['inset'][dimension]
        size = data['size'][dimension]; gap = data['gap'][dimension]
        # Independent positive-integer geometry oracle; not a general float32 implementation.
        expected = max(1, sum(k * size + (k - 1) * gap <= available for k in range(1, 64)))
        cached = expected if same_cache else expected + 5
        before = bytearray(0x1600)
        struct.pack_into('<ff', before, 0x12cc, *data['view'])
        for offset, pair in ((0x14b8, data['size']), (0x14d0, data['gap']), (0x14e0, data['inset'])):
            struct.pack_into('<dd', before, offset, *pair)
        before[0x14c8] = axis; before[0x14f7] = override
        struct.pack_into('<i', before, 0x14cc, cached); struct.pack_into('<i', before, 0x11d8, 23)
        uc.mem_write(obj, bytes(before)); uc.mem_write(stack, struct.pack('<Q', stop))
        state.clear(); state.update(fmod_calls=0, entered_recalculation=False)
        for reg, value in ((x.UC_X86_REG_RCX, obj), (x.UC_X86_REG_RDX, forced), (x.UC_X86_REG_RSP, stack)):
            uc.reg_write(reg, value)
        uc.emu_start(0x144626640, stop, count=1024)
        if state.get('calculated_count') != expected or state['fmod_calls'] != 1:
            raise ValueError('Native packing count не совпадает с положительным geometry fixture')
        recalc = bool(forced or not same_cache)
        if state['entered_recalculation'] != recalc:
            raise ValueError('Не совпадает gate пересчёта')
        if recalc:
            if uc.reg_read(x.UC_X86_REG_RIP) != 0x14462f090:
                raise ValueError('Prefix не остановлен до перечисления элементов')
        else:
            if uc.reg_read(x.UC_X86_REG_RIP) != stop or uc.reg_read(x.UC_X86_REG_RSP) != stack + 8:
                raise ValueError('Cached exit не вернулся полностью')
            struct.pack_into('<i', before, 0x14cc, 23 if override else expected)
        if bytes(uc.mem_read(obj, len(before))) != before:
            raise ValueError('Неожиданное изменение полей receiver')
        cases.append(dict(fixture=data, axis_flag=axis, force_flag=forced, same_cached_count=same_cache,
            override_flag=override, calculated_count=expected, entered_recalculation=recalc,
            complete_cached_exit=not recalc))
    return dict(source_sha256=getter.SHA, fragments=fragments, imported_math=imported, cases=cases,
        limits=['128 positive integer fixtures; no proof for arbitrary float32, NaN/Inf, negative sizes or zero denominators.',
            'fmodf and stack-cookie validation are fixtures; native arithmetic and control flow execute.',
            'Recalculation stops before item-count provider. Only cached exits execute through return.',
            'Offsets show numeric layout participation, not reflected names, units, orientation labels or DPI.',
            'Cached-count gate is not a general update scheduler or proof of performance across 50 windows.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists(): parser.error('Прежний отчёт не перезаписывается')
    result = run(json.loads(args.request.read_text('utf-8')))
    result['replay_sha256'] = getter.sha(Path(__file__).read_bytes())
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(cases=len(result['cases']), complete_exits=sum(c['complete_cached_exit'] for c in result['cases'])), ensure_ascii=False))
