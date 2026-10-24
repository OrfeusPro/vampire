"""Native resource setter identity / invalidation paths with explicit ownership fixtures."""
import argparse
import importlib.util
import itertools
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('setter_refresh', HERE / 'replay-nktileview-refresh.py')
refresh = importlib.util.module_from_spec(spec); spec.loader.exec_module(refresh)
native, getter, unicorn, x = refresh.native, refresh.getter, refresh.unicorn, refresh.x


def run(request):
    if request['source_sha256'] != getter.SHA or request['question'] != 'ui-nktileview-property-schema':
        raise ValueError('Другой источник / вопрос')
    if '0x14191ab70' not in {f['address'] for f in request['functions']}:
        raise ValueError('Нет явного setter в задании')
    if native.capstone.__version__ != '5.0.6' or unicorn.__version__ != '2.1.4':
        raise ValueError('Изменились закреплённые зависимости')
    raw = Path(request['source']).read_bytes()
    if getter.sha(raw) != getter.SHA: raise ValueError('Изменился EXE')
    image = native.Image(raw); root = image.containing(0x14191ab70)
    if root is None or image.pe.base + image.roots[root][0] != 0x14191ab70:
        raise ValueError('Изменилась unwind граница')
    fragments = native.decode_ranges(image, {image.roots[root]})
    resolver = None
    if '0x1445cf4f0' in {f['address'] for f in request['functions']}:
        resolver_root = image.containing(0x1445cf4f0)
        resolver_parts = native.decode_ranges(image, {image.roots[resolver_root]})
        rows = {row['address']: row for part in resolver_parts for row in part['instructions']}
        for at, expected in {0x1445cf510: ('cmp', 'word ptr [rdx], 0x2f'),
                             0x1445cf516: ('call', '0x141426b30'),
                             0x1445cf533: ('call', '0x141433340'),
                             0x1445cf547: ('call', '0x14142bc30')}.items():
            if (rows[at]['mnemonic'], rows[at]['operands']) != expected:
                raise ValueError('Изменился resolver branch')
        at = rows[0x1445cf52c]['rip_references'][0]; off = image.offset(at - image.pe.base)
        template = '/UI/Resource/Texture/%s'; expected = (template + '\0').encode('utf-16le')
        if raw[off:off + len(expected)] != expected: raise ValueError('Изменился path template')
        resolver = dict(fragments=resolver_parts, template=template, template_address=hex(at),
            global_prefix_address=hex(rows[0x1445cf540]['rip_references'][0]),
            global_prefix_value=None, status='static_call_arguments_not_full_native_string_execution')
    ranges = [(image.pe.base + f['begin_rva'], image.pe.base + f['end_rva']) for f in fragments]
    fixture_entries = {0x1414734e0, 0x1416e2a20}
    pages = {p for a, b in ranges for p in range(a & ~4095, (b + 4095) & ~4095, 4096)}
    pages.update(a & ~4095 for f in fragments for row in f['instructions'] for a in row['rip_references'])
    pages.update(a & ~4095 for a in fixture_entries)
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    for page in pages:
        uc.mem_map(page, 4096)
        try: off = image.offset(page - image.pe.base)
        except ValueError: continue  # zero-backed data page; explicit gate is set below
        uc.mem_write(page, raw[off:off + 4096])
    base = 0x20000000; uc.mem_map(base, 0x20000)
    obj, control, table, destroy, deallocate, stack, stop = (base + p for p in (0x1000, 0x3000, 0x4000, 0x5000, 0x5010, 0x10000, 0x1f000))
    fixture_entries.update((destroy, deallocate)); calls = []
    def hook(machine, address, size, unused):
        if address not in fixture_entries:
            if not any(a <= address and address + size <= b for a, b in ranges):
                raise ValueError('Исполнение вне resource setter: ' + hex(address))
            return
        rcx, rdx = machine.reg_read(x.UC_X86_REG_RCX), machine.reg_read(x.UC_X86_REG_RDX)
        if address == 0x1414734e0:
            old = bytes(machine.mem_read(rcx, 8)); new = bytes(machine.mem_read(rdx, 8))
            machine.mem_write(rcx, new); machine.mem_write(rdx, old)
            calls.append('swap_fixture')
        elif address == 0x1416e2a20:
            calls.append('resource_side_effect_fixture:' + hex(rcx))
        elif address == destroy:
            if rcx != control: raise ValueError('Не тот control destructor')
            calls.append('destroy_fixture')
        else:
            if rcx != control or rdx != 1: raise ValueError('Не тот deallocate аргумент')
            calls.append('deallocate_fixture')
        sp = machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(x.UC_X86_REG_RSP, sp + 8)
    uc.hook_add(unicorn.UC_HOOK_CODE, hook)
    uc.mem_write(table, struct.pack('<QQ', destroy, deallocate))
    cases = []
    for old, new, gate, count in itertools.product((0, base + 0x6000, base + 0x7000),
            (0, base + 0x6000, base + 0x7000), (0, 1), (0, 1, 2)):
        calls.clear(); before = bytearray(b'\xa5' * 0xc0)
        struct.pack_into('<Q', before, 0x38, old)
        struct.pack_into('<QQ', before, 0x98, base + 0x8000 if count else 0, control if count else 0)
        control_before = bytearray(struct.pack('<Qii', table, count, 1) + b'\x5a' * 16)
        uc.mem_write(obj, bytes(before)); uc.mem_write(control, bytes(control_before))
        uc.mem_write(0x14b3cb8c0, bytes([gate])); uc.mem_write(stack, struct.pack('<Q', stop))
        for reg, value in ((x.UC_X86_REG_RCX, obj), (x.UC_X86_REG_RDX, new), (x.UC_X86_REG_RSP, stack)):
            uc.reg_write(reg, value)
        uc.emu_start(0x14191ab70, stop, count=1024)
        changed = old != new; expected_calls = []
        if changed:
            if gate and new: expected_calls.append('resource_side_effect_fixture:' + hex(new))
            expected_calls.append('swap_fixture')
            struct.pack_into('<Q', before, 0x38, new); before[0x98:0xa8] = bytes(16)
            if count:
                struct.pack_into('<i', control_before, 8, count - 1)
                if count == 1:
                    expected_calls += ['destroy_fixture', 'deallocate_fixture']
                    struct.pack_into('<i', control_before, 12, 0)
        if calls != expected_calls or bytes(uc.mem_read(obj, len(before))) != before or bytes(uc.mem_read(control, 32)) != control_before:
            raise ValueError('Не совпадает identity gate / invalidation / ownership path')
        if uc.reg_read(x.UC_X86_REG_RIP) != stop or uc.reg_read(x.UC_X86_REG_RSP) != stack + 8:
            raise ValueError('Setter не завершился полным возвратом')
        cases.append(dict(old_pointer=hex(old), new_pointer=hex(new), gate=gate, fixture_refcount=count,
                          changed=changed, calls=calls.copy()))
    return dict(source_sha256=getter.SHA, fragments=fragments, cases=cases, resolver=resolver,
        limits=['Only resource setter executes natively; swap, resource side effect, destructor and deallocation are fixtures.',
            'Synthetic reference counters and pointers; no actual UObject/Brush creation, render or concurrent ownership.',
            'Identity equality preserves cached fields here; this is not proof of every UI cache or update scheduler.',
            'Named reflected fields, full resolver prefix, active texture and nine-slice remain unverified.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists(): parser.error('Прежний отчёт не перезаписывается')
    result = run(json.loads(args.request.read_text('utf-8')))
    result['replay_sha256'] = getter.sha(Path(__file__).read_bytes())
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(cases=len(result['cases']), unchanged=sum(not c['changed'] for c in result['cases'])), ensure_ascii=False))
