"""Source-context native harness; explicit exports and memcpy binding only."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent



def runtime_inputs():
    import importlib.metadata
    result={}
    for name in ('capstone','unicorn'):
        found=[d for d in importlib.metadata.distributions(path=[str(HERE.parents[2]/'.tools/vampir-analysis')])
            if d.metadata['Name'].lower()==name]
        if len(found)!=1:raise ValueError('Missing or ambiguous native runtime')
        result[name]=dict(version=found[0].version,
            record_sha256=hashlib.sha256((found[0].read_text('RECORD') or '').encode()).hexdigest())
    return result


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_harness(context, exports, functions, leaves=None, root=None):
    import re
    SHA=context['source_sha256']
    if not isinstance(SHA,str) or not re.fullmatch('[0-9a-f]{64}',SHA):
        raise ValueError('Explicit full source SHA required')
    native = load('request_native', HERE/'build-native-entry-code.py')
    sys.path.insert(0, str(HERE.parents[2]/'.tools/vampir-analysis'))
    import unicorn
    from unicorn import x86_const as x
    if unicorn.__version__ != '2.1.4' or native.capstone.__version__ != '5.0.6':
        raise ValueError('Pinned request runtime required')
    root = Path(root) if root else native.ROOT
    source = root/'client-code-snapshots'/SHA/'ProjectRED-Win64-Shipping.exe'
    if Path(context['source']).resolve()!=source.resolve():
        raise ValueError('Context source path differs')
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA:
        raise ValueError('Request source SHA changed')
    image = native.Image(raw)
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    decoder.detail = True
    pages, allowed, found, evidence = set(), set(), set(), []
    h = SimpleNamespace(uc=uc, x=x, raw=raw, image=image, source=source, sha=SHA,
                        root=root, scratch=0x28000000, fixtures={}, fragments=[])

    def map_page(address):
        page = address & ~4095
        if page in pages:
            return
        uc.mem_map(page, 4096)
        pages.add(page)
        try:
            off = image.offset(page-image.pe.base)
        except ValueError:
            return
        uc.mem_write(page, raw[off:off+4096])

    def instruction(address, data):
        off = image.offset(address-image.pe.base)
        if raw[off:off+len(data)] != data:
            raise ValueError('Request instruction differs from source')
        decoded = list(decoder.disasm(data, address))
        if len(decoded) != 1 or decoded[0].size != len(data):
            raise ValueError('Request instruction boundary differs')
        allowed.add(address)
        map_page(address)
        map_page(address+len(data)-1)
        for operand in decoded[0].operands:
            if operand.type == native.X86_OP_MEM and operand.mem.base == native.X86_REG_RIP:
                target = address+len(data)+operand.mem.disp
                map_page(target)
                map_page(target+511)

    # Reviewed integrations only; no call-tree discovery or arbitrary budget increase.
    budget = context.get('function_budget', 16)
    buffer_scope = (budget == 20 and context.get('budget_scope') == 'login-result-buffer'
                    and len(functions) == 20
                    and context.get('functions', {}).get('reader') == '0x1456dc140'
                    and context.get('native_input', {}).get('functions', {}).get('constructor') == '0x144aacb40'
                    and context.get('native_input', {}).get('functions', {}).get('buffer_constructor') == '0x144aac130')
    handler_scope = (budget == 22 and context.get('budget_scope') == 'login-result-body-handler'
                     and len(functions) == 22
                     and context.get('functions', {}).get('reader') == '0x1456dc140'
                     and context.get('native_input', {}).get('functions', {}).get('constructor') == '0x144aacb40'
                     and context.get('native_input', {}).get('functions', {}).get('buffer_constructor') == '0x144aac130'
                     and context.get('native_handler', {}).get('functions') == dict(handler='0x14679aec0', gate='0x1467cd7b0'))
    login_11318_roots = {int(at, 16) for at in (
        '14143b9a0 14143bd30 1414466a0 14144c440 144aac430 144aac550 '
        '144aac5a0 144aac690 144aac770 144aac7a0 144aac7f0 144aac8c0 '
        '144aace40 144aad2d0 1456d7a70 1456dc520 1457a2780 1457a38e0 '
        '1457a5c00 1457fe0c0').split()}
    if SHA == 'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c':
        buffer_scope = (budget == 20 and context.get('budget_scope') == 'login-result-buffer'
                        and set(functions) == login_11318_roots)
        handler_scope = (budget == 22 and context.get('budget_scope') == 'login-result-body-handler'
                         and set(functions) == login_11318_roots | {0x14679b390, 0x1467cdc80}
                         and context.get('native_handler', {}).get('functions') ==
                         dict(handler='0x14679b390', gate='0x1467cdc80'))
    if SHA == '544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c':
        login_11320_roots = {int(at, 16) for at in (
            '14143ba00 14143bd90 141446700 14144c4a0 144aac1f0 144aac310 '
            '144aac360 144aac450 144aac530 144aac560 144aac5b0 144aac680 '
            '144aacc00 144aad090 1456d7660 1456dc140 1457a2710 1457a3870 '
            '1457a5b90 1457fe090').split()}
        buffer_scope = (budget == 20 and context.get('budget_scope') == 'login-result-buffer'
                        and set(functions) == login_11320_roots
                        and context.get('native_strings') is True)
    record_scope = (budget == 22 and context.get('budget_scope') == 'character-record'
                    and len(functions) == 22
                    and context.get('functions') == dict(constructor='0x145783840', reader='0x145788500',
                        time_constructor='0x1457a3500', time_reader='0x1457fdce0',
                        appearance_reader='0x145787a30', optional_reader='0x1456c3000',
                        vector='0x144aac530', u16_quad_reader='0x145794bc0')
                    and context.get('native_input', {}).get('functions', {}).get('constructor') == '0x144aacb40'
                    and context.get('native_input', {}).get('functions', {}).get('buffer_constructor') == '0x144aac130')
    list_scope = (budget == 34 and context.get('budget_scope') == 'character-list-records'
                  and len(functions) == 34 and SHA == 'd00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
                  and all(context.get('functions', {}).get(key) == value for key, value in dict(
                      list_reader='0x1456dbc30', list_resize='0x1456e6a20', list_record_thunk='0x1456dcdc0',
                      constructor='0x145783840', reader='0x145788500', optional_insert='0x1456bd7a0',
                      appearance_callback='0x14573b9c0', input_constructor='0x144aacb40',
                      input_buffer_constructor='0x144aac130').items()))
    if SHA == 'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c':
        # Fixed source-linked CharacterList package. These allowlists only bound
        # the harness; exports, bytes, calls and native scenarios still verify it.
        record_11318_roots = {int(at, 16) for at in (
            '14143b9a0 14143bd30 1414466a0 14144c440 144aac430 144aac550 '
            '144aac5a0 144aac690 144aac770 144aac7a0 144aac7f0 144aac830 '
            '144aac8c0 144aace40 144aad2d0 1456c33e0 145783c20 145787e10 '
            '1457888e0 145794fa0 1457a38e0 1457fe0c0').split()}
        list_11318_roots = record_11318_roots | {int(at, 16) for at in (
            '1456ba840 1456bbfb0 1456bdb80 1456c7250 1456d2640 1456dc010 '
            '1456dd1a0 1456e6e00 14573bda0 1457845a0 145786770 145789790').split()}
        record_scope = (budget == 22 and context.get('budget_scope') == 'character-record'
                        and set(functions) == record_11318_roots
                        and context.get('functions') == dict(
                            constructor='0x145783c20', reader='0x1457888e0',
                            time_constructor='0x1457a38e0', time_reader='0x1457fe0c0',
                            appearance_reader='0x145787e10', optional_reader='0x1456c33e0',
                            vector='0x144aac830', u16_quad_reader='0x145794fa0')
                        and context.get('native_input', {}).get('functions', {}).get('constructor') == '0x144aace40'
                        and context.get('native_input', {}).get('functions', {}).get('buffer_constructor') == '0x144aac430')
        list_scope = (budget == 34 and context.get('budget_scope') == 'character-list-records'
                      and set(functions) == list_11318_roots
                      and set(functions) == {int(at, 16) for at in context.get('functions', {}).values()}
                      and all(context.get('functions', {}).get(key) == value for key, value in dict(
                          list_reader='0x1456dc010', list_resize='0x1456e6e00', list_record_thunk='0x1456dd1a0',
                          constructor='0x145783c20', reader='0x1457888e0', optional_insert='0x1456bdb80',
                          appearance_callback='0x14573bda0', input_constructor='0x144aace40',
                          input_buffer_constructor='0x144aac430').items()))
    npc_scope = (budget == 54 and context.get('budget_scope') == 'npc-create-record'
                 and len(functions) == 54 and SHA == 'd00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
                 and all(context.get('functions', {}).get(key) == value for key, value in dict(
                     packet_constructor='0x1456c01c0', reader='0x1456c5180', create_constructor='0x14579a5a0',
                     create_reader='0x14579e590', npc_reader='0x14579e350', effect_reader='0x145792250',
                     optional_insert='0x1456bd7a0', appearance_callback='0x14573b9c0',
                     input_constructor='0x144aacb40', input_buffer_constructor='0x144aac130',
                     trig_sse2='0x1487ea130').items()))
    projectile_scope = (budget == 21 and context.get('budget_scope') == 'sight-projectile-array'
                        and len(functions) == 21 and set(functions) == {int(v,16) for v in context.get('functions',{}).values()}
                        and context.get('functions') == dict(
                            input_constructor='0x144aacb40',input_buffer_constructor='0x144aac130',
                            input_u64='0x144aac4a0',input_u32='0x144aac2a0',input_float='0x144aac2f0',
                            input_bool='0x144aac4f0',input_raw='0x144aac5c0',input_u16='0x144aac250',
                            xyz='0x144aacf40',yaw='0x1458220f0',yaw_to_vector='0x14150d330',
                            vector_to_yaw='0x14150b060',trig_sse2='0x1487ea130',vector='0x144aac530',
                            reader='0x1456c2f60',resize='0x1456d1f70',callback='0x1456c64b0',
                            constructor='0x1457a2590',circle_reader='0x1457a5c80',record_reader='0x1457a5cd0',
                            cleanup='0x1457a38a0'))
    social_scope = (budget == 21 and context.get('budget_scope') == 'sight-social-records'
                    and len(functions) == 21 and set(functions) == {int(v,16) for v in context.get('functions',{}).values()}
                    and context.get('functions') == dict(
                        input_constructor='0x144aacb40',input_buffer_constructor='0x144aac130',
                        input_u16='0x144aac250',input_u32='0x144aac2a0',input_u64='0x144aac4a0',
                        input_bool='0x144aac4f0',input_raw='0x144aac5c0',input_string='0x144aacfd0',
                        input_std_string='0x144aac390',input_utf8_length='0x14144c440',
                        input_utf8_convert='0x1414466a0',input_utf8_core='0x14143bd30',input_utf8_scalar='0x14143b9a0',
                        input_time='0x144aac470',guild_constructor='0x145799940',guild_reader='0x14579c6b0',
                        emblem_reader='0x145794bc0',time_constructor='0x1457a3500',time_reader='0x1457fdce0',
                        party_reader='0x1457a5770',option_reader='0x1457a5520'))
    gadget_scope = (budget == 26 and context.get('budget_scope') == 'sight-gadget-record'
                    and len(functions) == 26 and set(functions) == {int(v,16) for v in context.get('functions',{}).values()}
                    and context.get('functions') == dict(
                        input_constructor='0x144aacb40',input_buffer_constructor='0x144aac130',
                        input_u16='0x144aac250',input_u32='0x144aac2a0',input_u64='0x144aac4a0',
                        input_bool='0x144aac4f0',input_raw='0x144aac5c0',input_string='0x144aacfd0',
                        input_std_string='0x144aac390',input_utf8_length='0x14144c440',
                        input_utf8_convert='0x1414466a0',input_utf8_core='0x14143bd30',input_utf8_scalar='0x14143b9a0',
                        input_float='0x144aac2f0',xyz='0x144aacf40',yaw='0x1458220f0',
                        yaw_to_vector='0x14150d330',vector_to_yaw='0x14150b060',trig_sse2='0x1487ea130',
                        vector='0x144aac530',keys_callback='0x1456c6960',keys_wrapper='0x1456bb710',
                        optional_wrapper='0x1456b7060',owner_reader='0x145786290',
                        constructor='0x14578fe30',reader='0x1457938b0'))
    other_roots = {int(at,16) for at in (
        '14143b9a0 14143bd30 1414466a0 14144c440 14150b060 14150d330 144aac130 144aac250 '
        '144aac2a0 144aac2f0 144aac390 144aac470 144aac4a0 144aac4f0 144aac530 144aac5c0 '
        '144aacb40 144aacf40 144aacfd0 1456b7060 1456ba460 1456bbbd0 1456bd7a0 1456c3000 '
        '1456c6e70 1456d2260 145734dd0 14573b9c0 14573d240 145781ac0 145783670 1457841c0 '
        '145786190 145786390 145787a30 145788180 1457893b0 145789c10 14578a310 14578aff0 '
        '14578f6b0 1457909e0 145792250 145794bc0 145799940 14579c6b0 1457a2530 1457a3500 '
        '1457a3830 1457a5520 1457a5770 1457a5b60 1457a7f70 1457fdce0 145821d00 1458220f0 '
        '1487ea130').split()}
    other_scope = (budget == 57 and context.get('budget_scope') == 'sight-character-other'
                   and set(functions) == other_roots == {int(v,16) for v in context.get('functions',{}).values()}
                   and context.get('functions',{}).get('constructor') == '0x145783670'
                   and context.get('functions',{}).get('reader') == '0x145788180')
    lifecycle_roots = other_roots | {int(at,16) for at in (
        '1414266a0 14143b910 1456b5990 1456b59c0 1456bbc50 1456bc920 1456bcc10 '
        '1456beaa0 1456bedd0 1456bfad0 1456c08d0 145784630 145785200 14579ac40 1457a3700').split()}
    lifecycle_scope = (budget == 72 and context.get('budget_scope') == 'sight-character-other-lifecycle'
                       and set(functions) == lifecycle_roots == {int(v,16) for v in context.get('functions',{}).values()}
                       and context.get('functions',{}).get('reader') == '0x145788180'
                       and context.get('functions',{}).get('copy') == '0x1456bedd0'
                       and context.get('functions',{}).get('destroy') == '0x145785200')
    sight_roots = lifecycle_roots | {int(at,16) for at in (
        '144aac190 1456bb710 1456bf7a0 1456bfe20 1456c2f60 1456c5390 1456c5e60 '
        '1456c6270 1456c62f0 1456c6400 1456c64b0 1456c67a0 1456c68d0 1456c6960 '
        '1456d1d30 1456d1eb0 1456d1ef0 1456d1f30 1456d1f70 1456d1ff0 1457846a0 '
        '145784e20 145786290 14578fe30 14578fef0 1457911d0 145791230 1457938b0 '
        '145793a90 14579a5a0 14579b720 14579b810 14579e350 14579e590 14579e690 '
        '14579e6f0 1457a2590 1457a3480 1457a38a0 1457a44c0 1457a5c80 1457a5cd0 '
        '1457a6850 1457a83c0 145821cb0').split()}
    sight_scope = (budget == 117 and context.get('budget_scope') == 'sight-enter-whole'
                   and set(functions) == sight_roots == {int(v,16) for v in context.get('functions',{}).values()}
                   and context.get('functions',{}).get('reader') == '0x1456c5390')
    admitted=None
    if context.get('native_admission'):
        admitted=load('reviewed_native_adapters',HERE/'update-native-contexts.py').admitted_instructions(
            context,root,set(functions),leaves or {})
        if exports or budget!=16:raise ValueError('Generated native adapter export/budget scope differs')
        evidence.extend(admitted['evidence'])
    if type(budget) is not int or (budget not in (16, 19) and not buffer_scope and not handler_scope and not record_scope and not list_scope and not npc_scope and not projectile_scope and not social_scope and not gadget_scope and not other_scope and not lifecycle_scope and not sight_scope) or not 1 <= len(functions) <= budget or (admitted is None and not 1 <= len(exports) <= (39 if sight_scope else (31 if lifecycle_scope else (25 if other_scope else (20 if npc_scope else (16 if gadget_scope else (12 if projectile_scope else (10 if list_scope or social_scope else (9 if handler_scope or record_scope else 8))))))))):
        raise ValueError('Request function/export budget exceeded')
    for run, expected in exports.items():
        path = root/'ghidra/request-exports'/SHA/run/'details.json'
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != expected:
            raise ValueError('Request export SHA changed')
        report = json.loads(payload)
        if report['new_source_sha256'] != SHA:
            raise ValueError('Request export source differs')
        evidence.append(dict(path=str(path), sha256=expected))
        for function in report['functions']:
            address = int(function['address'],16)
            if address not in functions:
                continue
            if not function['decompilation_completed']:
                raise ValueError('Incomplete request export')
            for row in function['instructions']:
                instruction(int(row['address'],16), bytes.fromhex(row['bytes']))
            found.add(address)
            h.fragments.append(function)
    for function in (admitted or {}).get('functions',[]):
        address=int(function['address'],16)
        if address not in functions:raise ValueError('Generated native adapter root differs')
        for row in function['instructions']:instruction(int(row['address'],16),bytes.fromhex(row['bytes']))
        found.add(address);h.fragments.append(function)
    if found != set(functions):
        raise ValueError('Requested function absent from supplied exports')
    if context.get('verify_whole_exports'):
        shapes = load('wire_source_shapes', HERE/'audit-launcher-shape-11318.py')
        for function in h.fragments:
            shapes.normalize_function(native, image, function)
    for address, expected in (leaves or {}).items():
        data = bytes.fromhex(expected)
        decoded = list(decoder.disasm(data,address))
        if sum(row.size for row in decoded) != len(data):
            raise ValueError('Request leaf has an instruction gap')
        for row in decoded:
            instruction(row.address,bytes(row.bytes))
    copy = int(context['helpers']['memcpy'],16)
    off = image.offset(copy-image.pe.base)
    if raw[off:off+2] != b'\xff\x25':
        raise ValueError('Request copy import thunk differs')
    imports = load('request_imports', HERE/'build-object-zero-init-code.py')
    slot = copy+6+struct.unpack_from('<i',raw,off+2)[0]
    h.copy_import = imports.import_at(raw,image,slot)
    if (h.copy_import['dll'].lower(),h.copy_import['name']) != ('vcruntime140.dll','memcpy'):
        raise ValueError('Request copy import identity differs')
    uc.mem_map(h.scratch,0x40000)
    pages.update(range(h.scratch,h.scratch+0x40000,4096))
    stop = h.scratch+0x3f000
    uc.mem_write(stop,b'\xc3')

    def finish(value=0):
        stack = uc.reg_read(x.UC_X86_REG_RSP)
        uc.reg_write(x.UC_X86_REG_RAX,value)
        uc.reg_write(x.UC_X86_REG_RIP,int.from_bytes(uc.mem_read(stack,8),'little'))
        uc.reg_write(x.UC_X86_REG_RSP,stack+8)

    def add_fixture(address, handler):
        map_page(address)
        uc.mem_write(address,b'\xc3')
        h.fixtures[address] = handler

    def copy_fixture(machine):
        a,b,count = [machine.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8)]
        if count > 4096 or not all(h.scratch <= p <= h.scratch+0x40000-count for p in (a,b)):
            raise ValueError('Request copy fixture bound')
        if count:
            machine.mem_write(a,bytes(machine.mem_read(b,count)))
        finish(a)

    def hook(machine,address,size,unused):
        if address == stop:
            machine.emu_stop()
        elif address in h.fixtures:
            h.fixtures[address](machine)
        elif address not in allowed:
            raise ValueError('Unreviewed request target '+hex(address))
    uc.hook_add(unicorn.UC_HOOK_CODE,hook)
    add_fixture(copy,copy_fixture)

    def call(address, receiver=0, budget=30000):
        stack = h.scratch+0x38000
        uc.reg_write(x.UC_X86_REG_RSP,stack)
        uc.mem_write(stack,struct.pack('<Q',stop))
        uc.reg_write(x.UC_X86_REG_RCX,receiver)
        uc.emu_start(address,0,count=budget)
        if uc.reg_read(x.UC_X86_REG_RIP) != stop:
            raise ValueError('Request instruction budget exhausted')
        return uc.reg_read(x.UC_X86_REG_RAX)

    h.finish, h.add_fixture, h.call = finish, add_fixture, call
    h.evidence = evidence
    return h
