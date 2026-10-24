"""Native fallback-style writes; environment, resolver, asset loading and setter are fixtures."""
import argparse
import importlib.util
import itertools
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('style_refresh', HERE / 'replay-nktileview-refresh.py')
refresh = importlib.util.module_from_spec(spec); spec.loader.exec_module(refresh)
native, getter, unicorn, x = refresh.native, refresh.getter, refresh.unicorn, refresh.x
KEYS = ('_Common/TEX_Scroll_Horizontal', '_Common/TEX_Scroll_Vertical')


def texture_candidates(root):
    path = root / 'archive-image-latest.json'; raw = path.read_bytes(); images = json.loads(raw)
    result = {}
    for key in KEYS:
        result[key] = []
        for image in images:
            if not image['asset_path'].endswith('/' + key): continue
            file = (root / image['file']).resolve()
            if not file.is_relative_to(root.resolve()) or getter.sha(file.read_bytes()) != image['sha256']:
                raise ValueError('Изменилась картинка кандидата / путь вне корня')
            result[key].append(dict(image, binding_status='suffix_candidate_not_native_resolver_proof'))
    if getter.sha(path.read_bytes()) != getter.sha(raw):
        raise ValueError('Каталог изображений изменился во время проверки')
    return dict(catalog='archive-image-latest.json', catalog_sha256=getter.sha(raw), candidates=result,
                limits='Historical catalog selection is not active client / brush / texture resolver validation')


def run(request):
    if request['source_sha256'] != getter.SHA or request['question'] != 'ui-nktileview-property-schema':
        raise ValueError('Другой источник / вопрос')
    if '0x144a8b800' not in {f['address'] for f in request['functions']}:
        raise ValueError('Нет явного root оформления')
    if native.capstone.__version__ != '5.0.6' or unicorn.__version__ != '2.1.4':
        raise ValueError('Нужны закреплённые версии emulator / decoder')
    raw = Path(request['source']).read_bytes()
    if getter.sha(raw) != getter.SHA: raise ValueError('Изменился EXE')
    image = native.Image(raw); root = image.containing(0x144a8b800)
    if root is None or image.pe.base + image.roots[root][0] != 0x144a8b800:
        raise ValueError('Изменилась unwind граница')
    fragments = native.decode_ranges(image, {image.roots[root]})
    ranges = [(image.pe.base + f['begin_rva'], image.pe.base + f['end_rva']) for f in fragments]
    fixtures = {0x14148ee40, 0x1445cf4f0, 0x144277e40, 0x1417e8fe0, 0x14191ab70,
                0x141483080, 0x1417f4140, 0x141409d30}
    pages = {p for a, b in ranges for p in range(a & ~4095, (b + 4095) & ~4095, 4096)}
    pages.update(a & ~4095 for f in fragments for row in f['instructions'] for a in row['rip_references'])
    pages.update(a & ~4095 for a in fixtures)
    # Translation may inspect a block across the page boundary before the fixture hook.
    pages.update((a & ~4095) + 4096 for a in fixtures)
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    for page in pages:
        uc.mem_map(page, 4096); off = image.offset(page - image.pe.base)
        uc.mem_write(page, raw[off:off + 4096])
    base = 0x20000000; uc.mem_map(base, 0x20000)
    owner, record, string, stack, stop = (base + p for p in (0x1000, 0x3000, 0x4000, 0x10000, 0x1f000))
    state = {}
    def u16(machine, pointer):
        value = bytearray()
        for i in range(256):
            pair = bytes(machine.mem_read(pointer + i * 2, 2))
            if pair == b'\0\0': return value.decode('utf-16le')
            value.extend(pair)
        raise ValueError('Незавершённая строка fixture')
    def hook(machine, address, size, unused):
        if address not in fixtures:
            if not any(a <= address and address + size <= b for a, b in ranges):
                raise ValueError('Исполнение вне style root: ' + hex(address))
            return
        rcx, rdx = machine.reg_read(x.UC_X86_REG_RCX), machine.reg_read(x.UC_X86_REG_RDX)
        result = 0
        if address == 0x14148ee40:
            state['gate_calls'] += 1; result = state['gate']
        elif address == 0x1445cf4f0:
            key = u16(machine, rdx)
            if key != KEYS[len(state['keys'])]: raise ValueError('Изменился key / порядок разрешения')
            state['keys'].append(key)
            text = ('fixture-resource-' + str(len(state['keys'])) + '\0').encode('utf-16le')
            machine.mem_write(string, text); machine.mem_write(record, struct.pack('<Qii', string, len(text) // 2, len(text) // 2))
            result = record
        elif address == 0x144277e40:
            result = base + 0x5000
        elif address == 0x1417e8fe0:
            text = u16(machine, machine.reg_read(x.UC_X86_REG_R8)); state['loads'].append(text)
            result = (base + 0x6000 + len(state['loads']) * 0x100) if state['load_present'] else 0
            state['loaded_results'].append(result)
        elif address == 0x14191ab70:
            state['setters'].append(dict(owner_offset=hex(rcx - owner), requested_resource=rdx))
            # No-op setter: resource pointer / engine internals are deliberately not emulated.
        elif address == 0x1417f4140:
            machine.mem_write(rcx, bytes(8))
        elif address == 0x141409d30:
            state['scheduled'] += 1
        sp = machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RAX, result)
        machine.reg_write(x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(x.UC_X86_REG_RSP, sp + 8)
    uc.hook_add(unicorn.UC_HOOK_CODE, hook)
    cases = []
    for horizontal, vertical, gate, load_present, poison in itertools.product((0, 1), (0, 1), (0, 1), (False, True), (0x11, 0xa5)):
        state.clear(); state.update(gate=gate, load_present=load_present, keys=[], loads=[], loaded_results=[], setters=[], scheduled=0, gate_calls=0)
        before = bytearray(b'\x5a' * 0x500)
        struct.pack_into('<Q', before, 0x2d8, horizontal * (base + 0x8000))
        struct.pack_into('<Q', before, 0x388, vertical * (base + 0x9000))
        uc.mem_write(owner, bytes(before)); uc.mem_write(stack - 0x400, bytes([poison]) * 0x800)
        uc.mem_write(stack, struct.pack('<Q', stop))
        uc.reg_write(x.UC_X86_REG_RCX, owner); uc.reg_write(x.UC_X86_REG_RSP, stack)
        try:
            uc.emu_start(0x144a8b800, stop, count=2048)
        except unicorn.UcError as error:
            raise ValueError('Emulator error at RIP=' + hex(uc.reg_read(x.UC_X86_REG_RIP)) +
                ', RSP=' + hex(uc.reg_read(x.UC_X86_REG_RSP)) + ', keys=' + repr(state['keys'])) from error
        if uc.reg_read(x.UC_X86_REG_RIP) != stop or uc.reg_read(x.UC_X86_REG_RSP) != stack + 8:
            raise ValueError('Style root не вернулся')
        missing = not (horizontal and vertical)
        if missing:
            struct.pack_into('<ff', before, 0x2c0, 9, 8); struct.pack_into('<ff', before, 0x370, 8, 9)
            if gate:
                for offset, flag in ((0x2a8, 0x2b8), (0x358, 0x368)):
                    struct.pack_into('<ffff', before, offset, 1, 1, 1, 1)
                    before[flag] = 0
                    # Upper three bytes come from stack, not a proved fully zero enum value.
                    before[flag + 1:flag + 4] = bytes([poison]) * 3
        expected_keys = list(KEYS) if missing and gate else []
        if state['keys'] != expected_keys or state['gate_calls'] != int(missing) or state['scheduled'] != int(missing and not gate):
            raise ValueError('Изменились fallback gate / resource keys / scheduling fixture calls')
        expected_setters = [dict(owner_offset=offset, requested_resource=value) for offset, value in
                            zip(('0x2a0', '0x350'), state['loaded_results'])]
        if state['setters'] != expected_setters or len(state['loads']) != len(expected_keys):
            raise ValueError('Изменился путь запроса ресурсов')
        if bytes(uc.mem_read(owner, len(before))) != before:
            raise ValueError('Native style writes / границы отличаются')
        cases.append(dict(horizontal_present=bool(horizontal), vertical_present=bool(vertical), gate=bool(gate),
            fixture_load_present=load_present, stack_poison=poison, requested_keys=state['keys'].copy(),
            setters=state['setters'].copy(), scheduled_fixture_calls=state['scheduled']))
    return dict(source_sha256=getter.SHA, fragments=fragments, cases=cases, keys=list(KEYS),
        limits=['Only preparation function executes natively. Gate, resolver, loader, setter, free and scheduling are fixtures.',
            'Requested keys and raw native writes do not prove a successful load, brush binding or render.',
            'Raw float4 ones has no proved color space; only low byte of adjacent flag is defined zero.',
            'Dimensions are literal float pairs; unit / DPI / active style and cooked compatibility remain unknown.',
            'No writes to owner430/440/450 found in this function; it is not their producer.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists(): parser.error('Прежний отчёт не перезаписывается')
    result = run(json.loads(args.request.read_text('utf-8')))
    result['texture_candidates'] = texture_candidates(native.ROOT)
    result['replay_sha256'] = getter.sha(Path(__file__).read_bytes())
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(cases=len(result['cases']), keys=result['keys']), ensure_ascii=False))
