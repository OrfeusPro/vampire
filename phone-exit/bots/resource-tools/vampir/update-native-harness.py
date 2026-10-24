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
    if type(budget) is not int or (budget not in (16, 19) and not buffer_scope and not handler_scope and not record_scope and not list_scope) or not 1 <= len(functions) <= budget or not 1 <= len(exports) <= (10 if list_scope else (9 if handler_scope or record_scope else 8)):
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
    if found != set(functions):
        raise ValueError('Requested function absent from supplied exports')
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
