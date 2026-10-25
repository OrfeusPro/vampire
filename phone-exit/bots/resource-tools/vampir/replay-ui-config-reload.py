"""Whole Reload-target wrapper: explicit config service, callback/iterator fixtures, native capture getter."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('reload_hash', HERE / 'replay-ui-config-hash.py')
hash_code = importlib.util.module_from_spec(spec); spec.loader.exec_module(hash_code)
native, getter, unicorn, x = hash_code.native, hash_code.getter, hash_code.unicorn, hash_code.x
ROOT = 0x1445d1cd0
REGISTRY = 0x14b1867f0
BITMAP = REGISTRY + 0x10
FIXTURES = {0x14157cf70: 'path_value', 0x141534f70: 'config_service',
            0x141483080: 'free_path', 0x14142e6f0: 'advance_bitmap'}


def run(request):
    if request['source_sha256'] != getter.SHA or request['question'] != 'ui-nktileview-property-schema':
        raise ValueError('Другой источник / вопрос')
    if hex(ROOT) not in {f['address'] for f in request['functions']}: raise ValueError('Нет явного Reload target')
    if native.capstone.__version__ != '5.0.6' or unicorn.__version__ != '2.1.4':
        raise ValueError('Изменились закреплённые инструменты')
    raw = Path(request['source']).read_bytes()
    if getter.sha(raw) != getter.SHA: raise ValueError('Изменился EXE')
    image = native.Image(raw); row = image.containing(ROOT)
    if row is None or image.pe.base + image.roots[row][0] != ROOT: raise ValueError('Изменился unwind root')
    fragments = native.decode_ranges(image, {image.roots[row]})
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    for at, target in ((0x1445d1cfc, 0x14157cf70), (0x1445d1d40, 0x141534f70), (0x1445d1e94, 0x14142e6f0)):
        if rows[at]['direct_target'] != target: raise ValueError('Изменилась цепочка target')
    refs = {0x1445d1cf1: 0x14b2e60f0, 0x1445d1d18: 0x1489f3bf0, 0x1445d1d2c: 0x14b2e5678,
            0x1445d1d53: REGISTRY + 0x28, 0x1445d1d5a: BITMAP, 0x1445d1dfd: REGISTRY}
    if any(rows[a]['rip_references'] != [b] for a, b in refs.items()): raise ValueError('Изменились глобальные объекты')
    off = image.offset(0x1489f3bf0 - image.pe.base)
    if raw[off:off + 10] != 'Game\0'.encode('utf-16le'): raise ValueError('Изменился config literal')
    if (rows[0x1445d1e61]['mnemonic'], rows[0x1445d1e61]['operands']) != ('shl', 'rcx, 5') or rows[0x1445d1e80]['operands'] != 'qword ptr [rax + 8]':
        raise ValueError('Изменились registry stride / capture getter')
    leaf = 0x14140e2f0; off = image.offset(leaf - image.pe.base)
    if image.containing(leaf) is not None or raw[off:off + 9] != bytes.fromhex('488d4108c3cccccccc'):
        raise ValueError('Изменился ранее проверенный capture-address leaf')
    table = hash_code.uniqueness.payload.TABLE; off = image.offset(table - image.pe.base)
    if struct.unpack_from('<Q', raw, off + 8)[0] != leaf: raise ValueError('Изменился getter slot')
    ranges = [(image.pe.base + f['begin_rva'], image.pe.base + f['end_rva']) for f in fragments] + [(leaf, leaf + 5)]
    pages = {p for a, b in ranges for p in range(a & ~4095, (b + 4095) & ~4095, 4096)}
    pages.update(a & ~4095 for f in fragments for r in f['instructions'] for a in r['rip_references'])
    pages.update(a & ~4095 for a in (*FIXTURES, table))
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    for page in pages:
        uc.mem_map(page, 4096)
        try: off = image.offset(page - image.pe.base)
        except ValueError: continue
        uc.mem_write(page, raw[off:off + 4096])
    base = 0x20000000; uc.mem_map(base, 0x30000)
    entries, bits, path_data, heap, invoke, stack, stop = [base + a for a in (0x1000, 0x6000, 0x7000, 0x8000, 0xc000, 0x20008, 0x2f000)]
    state = {}
    def integer(at): return int.from_bytes(uc.mem_read(at, 4), 'little', signed=True)
    def qword(at): return int.from_bytes(uc.mem_read(at, 8), 'little')
    def ret(result=0):
        sp = uc.reg_read(x.UC_X86_REG_RSP); uc.reg_write(x.UC_X86_REG_RAX, result)
        uc.reg_write(x.UC_X86_REG_RIP, qword(sp)); uc.reg_write(x.UC_X86_REG_RSP, sp + 8)
    def hook(machine, address, size, unused):
        if address not in FIXTURES and address != invoke:
            if not any(a <= address and address + size <= b for a, b in ranges):
                raise ValueError('Исполнение вне Reload wrapper / capture getter: ' + hex(address))
            return
        rcx, rdx, r8, r9 = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        name = 'callback' if address == invoke else FIXTURES[address]; state['events'].append(name)
        if name == 'path_value':
            data = ('Demo/Config' + '\0').encode('utf-16le'); uc.mem_write(path_data, data)
            uc.mem_write(rcx, struct.pack('<Qii', path_data if state['path_present'] else 0,
                len(data) // 2 if state['path_present'] else 0, len(data) // 2 if state['path_present'] else 0)); ret(rcx)
        elif name == 'config_service':
            sp = uc.reg_read(x.UC_X86_REG_RSP)
            args = [qword(sp + n) for n in (0x28, 0x30, 0x38, 0x40, 0x48)]
            # Three boolean stack args occupy only their low byte; high stack bytes are unspecified.
            if (rcx, rdx, r8, r9 & 255, *[a & 255 for a in args[:3]], args[3], args[4]) != (
                    0x14b2e5678, 0x1489f3bf0, 0, 1, 0, 1, 1,
                    path_data if state['path_present'] else 0x1489e1b34, state['global_value']):
                raise ValueError('Неверные config service arguments')
            ret(int(state['service_result']))
        elif name == 'free_path':
            if rcx != path_data or not state['path_present']: raise ValueError('Неверный path free')
            ret()
        elif name == 'callback':
            position = len(state['visited']); index = state['active'][position]
            capture = (heap + index * 16 if state['external'] else entries + index * 0x60 + 0x30) + 8
            if rcx != capture or qword(rcx) != 0x12340000 + index: raise ValueError('Неверный callback capture / порядок')
            if 'config_service' not in state['events'][:-1]: raise ValueError('Callback до config service')
            state['visited'].append(index); ret()
        else:
            if qword(rcx + 8) != BITMAP: raise ValueError('Другой bitmap owner')
            current = integer(rcx + 20)
            if not state['visited'] or current != state['visited'][-1]: raise ValueError('Неверный advance current index')
            following = next((a for a in state['active'] if a > current), state['total'])
            word = following // 32; mask = 1 << (following & 31)
            uc.mem_write(rcx, struct.pack('<iI', word, mask))
            uc.mem_write(rcx + 16, struct.pack('<Iii', 0xffffffff, following, word * 32)); ret()
    uc.hook_add(unicorn.UC_HOOK_CODE, hook)
    shapes = [(0, []), (1, []), (1, [0]), (4, [1, 3]), (33, [0, 31, 32]), (65, [0, 32, 64])]
    cases = []
    for total, active in shapes:
        for external in (False, True):
            for path_present in (False, True):
                for service_result in (False, True):
                    state.clear(); state.update(total=total, active=active, external=external,
                        path_present=path_present, service_result=service_result,
                        global_value=base + 0x500, events=[], visited=[])
                    uc.mem_write(0x14b2e60f0, struct.pack('<Q', state['global_value']))
                    uc.mem_write(REGISTRY, bytes(0x60)); uc.mem_write(REGISTRY, struct.pack('<Qii', entries, total, total))
                    masks = [sum(1 << (a & 31) for a in active if a // 32 == word) for word in range(3)]
                    uc.mem_write(BITMAP, struct.pack('<4I', *masks, 0))
                    uc.mem_write(BITMAP + 0x10, struct.pack('<Q', bits if external else 0))
                    uc.mem_write(BITMAP + 0x18, struct.pack('<ii', total, 96)); uc.mem_write(bits, struct.pack('<4I', *masks, 0))
                    uc.mem_write(entries - 8, b'\xa5' * (0x60 * 65 + 16))
                    for a in active:
                        node = entries + a * 0x60; uc.mem_write(node + 0x10, struct.pack('<Q', invoke))
                        uc.mem_write(node + 0x20, struct.pack('<Q', heap + a * 16 if external else 0))
                        uc.mem_write(node + 0x30, struct.pack('<QQ', table, 0x12340000 + a))
                        uc.mem_write(heap + a * 16, struct.pack('<QQ', table, 0x12340000 + a))
                    before = bytes(uc.mem_read(REGISTRY, 0x60)), bytes(uc.mem_read(entries - 8, 0x60 * 65 + 16)), bytes(uc.mem_read(bits, 16))
                    uc.mem_write(stack - 0x1000, b'\x91' * 0x1100); uc.mem_write(stack, struct.pack('<Q', stop))
                    uc.reg_write(x.UC_X86_REG_RSP, stack); uc.emu_start(ROOT, stop, count=4096)
                    if uc.reg_read(x.UC_X86_REG_RIP) != stop or uc.reg_read(x.UC_X86_REG_RSP) != stack + 8:
                        raise ValueError('Нет полного Reload wrapper return')
                    expected_events = ['path_value', 'config_service'] + (['free_path'] if path_present else []) + ['callback', 'advance_bitmap'] * len(active)
                    if state['events'] != expected_events or state['visited'] != active: raise ValueError('Неверный порядок callbacks / services')
                    after = bytes(uc.mem_read(REGISTRY, 0x60)), bytes(uc.mem_read(entries - 8, 0x60 * 65 + 16)), bytes(uc.mem_read(bits, 16))
                    if before != after: raise ValueError('Wrapper изменил registry / bitmap / guard')
                    cases.append(dict(total_slots=total, occupied=active, external_storage=external,
                        path_fixture_present=path_present, service_result_fixture=service_result,
                        events=expected_events, callbacks=state['visited'].copy(), complete_return=True))
    return dict(source_sha256=getter.SHA, fragments=fragments, cases=cases,
        registry=dict(address=hex(REGISTRY), stride='0x60', distinct_from_binding_registry='0x14b186130'),
        limits=['Complete native wrapper and capture-address getter; path/config/free/iterator-advance/callback bodies are fixtures.',
            'Initial occupied-bit selection native; later stepping synthetic, no proof of full iterator or callback behavior.',
            'Config helper boolean return does not gate this wrapper callback traversal; helper failure contract unknown.',
            'Global path/object pointers synthetic; literal Game and ABI do not establish file access, precedence or active config.',
            'No connection from callback registry to binding reader/setter established; no UI application/persistence proof.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists(): parser.error('Прежний отчёт не перезаписывается')
    result = run(json.loads(args.request.read_text('utf-8')))
    result['replay_sha256'] = getter.sha(Path(__file__).read_bytes())
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(cases=len(result['cases']), callbacks=sum(len(c['callbacks']) for c in result['cases']))))
