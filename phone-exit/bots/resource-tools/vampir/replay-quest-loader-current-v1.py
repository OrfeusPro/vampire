"""Current whole QuestTask load, Russian override and projection on native-built maps.

Every address is an explicit source-bound context binding. Storage, headers,
allocation, settings and engine string providers remain bounded fixtures.
"""
import csv
import ctypes
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def load(name, path=None):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), path or HERE/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module



SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
TASK_IDS = ['110120005','110120010','110120020','110120030','110120040','110120070']
RUSSIAN_NAMES = ['Идите ко входу','Идите ко входу','Идите ко входу',
    'Подойдите к связанному','Подойдите к связанному','Преследуйте врага']
NATIVE_ENTRIES = {
    '0x145b736a0': 4, '0x145b73280': 2, '0x1416169f0': 4, '0x141437580': 2,
    '0x141436d70': 6, '0x14142e750': 20, '0x145b4afa0': 12, '0x145b4b110': 12,
    '0x145b4a830': 12, '0x145b48f60': 2, '0x145b48c70': 12, '0x145b4c130': 12,
    '0x145b5f680': 2, '0x1445f6680': 28, '0x145a4d700': 12, '0x1445f5fc0': 48,
    '0x1445f1650': 48, '0x145b6a0b0': 2, '0x14585e470': 12, '0x145de7870': 36,
    '0x145b4c280': 36, '0x141491e00': 6, '0x141403bd0': 204, '0x140bb4a10': 2,
    '0x1445f6030': 48, '0x1445f61a0': 24, '0x1445f6070': 48, '0x1445f1610': 48,
    '0x1445f1cd0': 24, '0x1445f6010': 48, '0x1445f1630': 96, '0x1445e4d90': 192,
    '0x1487f8de3': 48, '0x141500740': 108, '0x145b55eb0': 36,
}


def checked_blob(root, pointer):
    if not isinstance(pointer,dict) or set(pointer)!={'path','sha256'}:
        raise ValueError('Current loader needs an exact CSV pointer')
    path = Path(pointer['path']).resolve()
    if (not path.is_relative_to(Path(root).resolve()/'knowledge/resource-csv-blobs-v3')
            or path.name != pointer['sha256']+'.csv'):
        raise ValueError('Current loader CSV is outside immutable decoded blobs')
    raw = path.read_bytes()
    if len(raw)>16*1024*1024 or hashlib.sha256(raw).hexdigest()!=pointer['sha256']:
        raise ValueError('Current loader CSV bytes changed')
    return raw


def install_guards(h,context):
    """Keep the completed harness unchanged; require whole current exports and ABI."""
    if h.sha != SOURCE:
        raise ValueError('Current loader source SHA is not qualified')
    native,bindings = load('build-native-entry-code'),load('update-bindings')
    roots = {int(at,16) for at in context['functions']}
    leaves = {int(at,16):bytes.fromhex(raw) for at,raw in context['leaves'].items()}
    fragments = {int(f['address'],16):f for f in h.fragments}
    if len(fragments)!=len(h.fragments) or set(fragments)!=roots or roots & set(leaves):
        raise ValueError('Current loader native root scope differs')
    native_bytes = set()
    direct_targets = set()
    for at,function in fragments.items():
        if (function.get('block_coverage_complete') is not True
                or function.get('direct_flow_coverage_complete') is not True):
            raise ValueError('Current loader export flow coverage is incomplete')
        whole = bindings.rows(native,h.image,at)
        actual = [(int(row['address'],16),row['bytes'].lower()) for row in function['instructions']]
        if actual != [(row['address'],row['bytes'].lower()) for row in whole]:
            raise ValueError('Current loader export is not the whole unwind range')
        for row in whole:
            native_bytes.update(range(row['address'],row['address']+len(bytes.fromhex(row['bytes']))))
            if row['direct_target'] is not None:
                direct_targets.add(row['direct_target'])
    decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64)
    decoder.detail=True
    for at,raw in leaves.items():
        addresses=set(range(at,at+len(raw)))
        if native_bytes & addresses:
            raise ValueError('Current loader leaf overlaps native code')
        native_bytes.update(addresses)
        for instruction in decoder.disasm(raw,at):
            if (instruction.group(native.capstone.CS_GRP_JUMP)
                    or instruction.group(native.capstone.CS_GRP_CALL)):
                if instruction.operands[0].type==native.X86_OP_IMM:
                    direct_targets.add(instruction.operands[0].imm)
    metrics = dict(call_counts=0,abi_checks=0,entry_counts={},fixture_calls=0)
    import unicorn
    uc,x,base = h.uc,h.x,h.scratch
    entries = roots | set(leaves)
    def entry(machine,address,size,unused):
        if address in entries or address in h.fixtures:
            key=hex(address);metrics['entry_counts'][key]=metrics['entry_counts'].get(key,0)+1
        if address in h.fixtures:metrics['fixture_calls']+=1
    uc.hook_add(unicorn.UC_HOOK_CODE,entry)
    original_fixture = h.add_fixture
    # The generic harness installs memcpy by default; replace it below with
    # this replay's bounded provider before any native execution.
    h.fixtures.clear()
    def fixture(at,callback):
        if at in native_bytes or at in h.fixtures:
            raise ValueError('Current loader fixture overlaps native entry or another fixture')
        if at>=h.image.pe.base and at not in direct_targets:
            raise ValueError('Current loader fixture lacks an exact source call or tail edge '+hex(at))
        original_fixture(at,callback)
    # memcpy was installed by make_harness before this overlap barrier.
    h.add_fixture=fixture
    nonvolatile=('RBX','RBP','RSI','RDI','R12','R13','R14','R15')
    registers=[getattr(x,'UC_X86_REG_'+name) for name in nonvolatile]
    xmm=[getattr(x,'UC_X86_REG_XMM'+str(i)) for i in range(6,16)]
    def call(at,receiver=0,budget=30000):
        if at not in entries:raise ValueError('Current loader call outside native roots/leaves')
        values={r:(0x5a5a000000000000+i*0x100000101) for i,r in enumerate(registers)}
        values.update({r:((1<<120)+i*0x10000000000010001) for i,r in enumerate(xmm)})
        for r,value in values.items():uc.reg_write(r,value)
        stack=base+0x38008;stop=base+0x3f000
        uc.mem_write(base+0x34000,b'G'*16);uc.mem_write(base+0x3bff0,b'H'*16)
        uc.mem_write(stack,struct.pack('<Q',stop));uc.reg_write(x.UC_X86_REG_RSP,stack)
        uc.reg_write(x.UC_X86_REG_RCX,receiver);uc.reg_write(x.UC_X86_REG_EFLAGS,2)
        uc.reg_write(x.UC_X86_REG_MXCSR,0x1f80)
        uc.emu_start(at,0,count=budget)
        if (uc.reg_read(x.UC_X86_REG_RIP)!=stop or uc.reg_read(x.UC_X86_REG_RSP)!=stack+8
                or any(uc.reg_read(r)!=value for r,value in values.items())
                or bytes(uc.mem_read(base+0x34000,16))!=b'G'*16
                or bytes(uc.mem_read(base+0x3bff0,16))!=b'H'*16):
            raise ValueError('Current loader native Win64 ABI/stack guard differs')
        metrics['call_counts']+=1;metrics['abi_checks']+=1
        return uc.reg_read(x.UC_X86_REG_RAX)
    h.call=call
    return metrics


def install_runtime(h,read_input,A,callback_base):
    """Actual Windows CRT through exact current PE import slots; no old slot reuse."""
    audit=load('audit-client-release')
    directory=ctypes.create_unicode_buffer(32768);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    if not 0<kernel.GetSystemDirectoryW(directory,len(directory))<len(directory):
        raise ValueError('Current loader system directory unavailable')
    path=Path(directory.value)/'ucrtbase.dll';sha=audit.sha256(path);crt=ctypes.CDLL(str(path))
    crt.atoi.argtypes,crt.atoi.restype=[ctypes.c_char_p],ctypes.c_int
    crt._atoi64.argtypes,crt._atoi64.restype=[ctypes.c_char_p],ctypes.c_longlong
    crt.strtoul.argtypes,crt.strtoul.restype=[ctypes.c_char_p,ctypes.c_void_p,ctypes.c_int],ctypes.c_ulong
    crt.pow.argtypes,crt.pow.restype=[ctypes.c_double,ctypes.c_double],ctypes.c_double
    crt.setlocale.argtypes,crt.setlocale.restype=[ctypes.c_int,ctypes.c_char_p],ctypes.c_char_p
    locale=crt.setlocale(0,None);uc,x=h.uc,h.x;calls=[];imported=[]
    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def atoi(machine):calls.append('atoi');h.finish(crt.atoi(read_input())&0xffffffff)
    def atoi64(machine):calls.append('_atoi64');h.finish(crt._atoi64(read_input())&0xffffffffffffffff)
    def strtoul(machine):
        if reg('RDX') or reg('R8'):raise ValueError('Current loader enum CRT arguments differ')
        calls.append('strtoul');h.finish(crt.strtoul(read_input(),None,0))
    def power(machine):
        a,b=[struct.unpack('<d',(reg(name)&0xffffffffffffffff).to_bytes(8,'little'))[0] for name in ('XMM0','XMM1')]
        if a!=10.0 or not 0<=b<=129:raise ValueError('Current loader decimal power arguments differ')
        calls.append('pow');uc.reg_write(x.UC_X86_REG_XMM0,int.from_bytes(struct.pack('<d',crt.pow(a,b)),'little'));h.finish(reg('RAX'))
    imports=load('build-object-zero-init-code')
    for i,(old,name,dll,callback) in enumerate((
            (0x14899bbf8,'atoi','api-ms-win-crt-convert-l1-1-0.dll',atoi),
            (0x14899bb78,'_atoi64','api-ms-win-crt-convert-l1-1-0.dll',atoi64),
            (0x14899bb98,'strtoul','api-ms-win-crt-convert-l1-1-0.dll',strtoul),
            (0x14899be00,'pow','api-ms-win-crt-math-l1-1-0.dll',power))):
        slot=A(old);item=imports.import_at(h.raw,h.image,slot)
        if (item['dll'].lower(),item['name'])!=(dll,name):raise ValueError('Current loader CRT import differs')
        imported.append(item);at=callback_base+i*16;h.add_fixture(at,callback)
        uc.mem_write(slot,struct.pack('<Q',at))
    def verify():
        if audit.sha256(path)!=sha or crt.setlocale(0,None)!=locale:
            raise ValueError('Current loader CRT changed during replay')
    return dict(calls=calls,imported=imported,system_runtime=dict(path=str(path),sha256=sha,locale=locale.decode()),verify=verify)


def validate(report,context=None):
    flags=dict(source_sha256=SOURCE,native_scalars=True,native_override=True,native_projection=True,
        network_used=False,order_admitted=False,runtime_admitted=False,action_admitted=False,
        full_catalog_verified=False,active_task_verified=False)
    if not isinstance(report,dict) or any(report.get(k)!=v or (type(v) is bool and type(report.get(k)) is not bool) for k,v in flags.items()):
        raise ValueError('Current loader result source or scope differs')
    runs=report.get('runs',[])
    if len(runs)!=2 or [r.get('reverse') for r in runs]!=[False,True]:
        raise ValueError('Current loader order matrix differs')
    for row in runs:
        ids=list(reversed(TASK_IDS)) if row['reverse'] else TASK_IDS
        if (row.get('task_ids')!=ids or row.get('records')!=6 or row.get('group_count')!=1
                or row.get('group_order_matches_records') is not True
                or len(row.get('native_projections',[]))!=18
                or len(row.get('native_base_headers',[]))!=6
                or row.get('russian_task_names')!=(list(reversed(RUSSIAN_NAMES)) if row['reverse'] else RUSSIAN_NAMES)):
            raise ValueError('Current loader actual loaded records/projection coverage differs')
        projections=row['native_projections']
        if [(p['index'],p['task_id'],p['first'],p['second']) for p in projections] != [
                (i,task,a,b) for i,task in enumerate(ids) for a,b in
                ((0,0),(1,2),(0x1234567800000001,0x8765432100000002))]:
            raise ValueError('Current loader projection scenarios differ')
        kinds=dict(zip(TASK_IDS,(6,5,6,5,6,6)))
        for projection in projections:
            if projection.get('quest_id')!='110120' or projection.get('kind')!=kinds[projection['task_id']]:
                raise ValueError('Current loader task group/type differs')
            expected=bytearray(b'\xcc'*32)
            struct.pack_into('<QBB',expected,0,int(projection['task_id']),projection['kind'],projection['index'])
            struct.pack_into('<II',expected,12,projection['first']&0xffffffff,projection['second']&0xffffffff)
            struct.pack_into('<Q',expected,24,0)
            if projection.get('progress_hex')!=expected.hex():
                raise ValueError('Current loader projection output bytes differ')
        if row['native_base_headers'] != [dict(task_id=task,base08=0,base10=0,base14=0) for task in ids]:
            raise ValueError('Current loader native constructor headers differ')
        callbacks=row.get('callbacks',{})
        if (callbacks!=dict(file_load=2, column=19, node_resize=3, override_file=1,
                            untranslated=6, task_name_store=6, group_array_resize=2)
                or row.get('bytes_read')!=1220 or row.get('override_bytes_read')!=423
                or row.get('scalar_import_calls')!={'atoi':48, '_atoi64':24, 'strtoul':12, 'pow':24}):
            raise ValueError('Current loader native override coverage differs')
    metrics=report.get('metrics',{})
    entry_counts=metrics.get('entry_counts')
    if (metrics.get('call_counts')!=38 or metrics.get('abi_checks')!=38
            or metrics.get('fixture_calls')!=4582 or not isinstance(entry_counts,dict)
            or any(type(count) is not int or count<=0 for count in entry_counts.values())
            or sum(entry_counts.values())!=1256+4582
            or any(entry_counts.get(at)!=count for at,count in NATIVE_ENTRIES.items())):
        raise ValueError('Current loader ABI/native entry coverage differs')
    if context is not None:
        roots=set(context['functions']) | set(context['leaves'])
        if roots!=NATIVE_ENTRIES.keys():
            raise ValueError('Current loader requested native root was not executed')
        if (context.get('task_ids')!=TASK_IDS
                or report.get('csv_sha256')!=context['csv']['sha256']
                or report.get('override_sha256')!=context['override_csv']['sha256']):
            raise ValueError('Current loader input/projection binding differs')


def run(context_path=None, *, root=None):
    audit = load('audit-client-release')
    path = Path(context_path) if context_path else HERE/'knowledge/native-contexts/quest-loader-current.json'
    context_raw = path.read_bytes()
    context_sha = hashlib.sha256(context_raw).hexdigest()
    context = json.loads(context_raw)
    if (context.get('schema') != 1 or context.get('recipe') != 'quest-loader-current-v1'
            or context.get('source_sha256')!=SOURCE or context.get('task_ids')!=TASK_IDS):
        raise ValueError('Current loader context schema/recipe differs')
    bindings = context['addresses']
    if any(not isinstance(old,str) or not isinstance(new,str) for old,new in bindings.items()):
        raise ValueError('Current loader exact address bindings required')
    def A(old):
        if hex(old) not in bindings:
            raise ValueError('Current loader unbound source address '+hex(old))
        return int(bindings[hex(old)],16)
    h = load('native-request-harness-11316').make_harness(context['exports'],
            {int(a, 16) for a in context['functions']}, leaves={int(a, 16):b for a, b in context['leaves'].items()},
            root=root,source_sha256=context['source_sha256'],copy_thunk=A(0x1487f5ab9))
    metrics = install_guards(h,context)
    if h.sha != context['source_sha256'] or not all(f.get('block_coverage_complete') for f in h.fragments):
        raise ValueError('Loader source/coverage differs')
    def source_qword(at):
        return struct.unpack_from('<Q',h.raw,h.image.offset(at-h.image.pe.base))[0]
    if any(source_qword(A(0x1499f67f8)+offset)!=A(0x141403b70) for offset in range(0x68,0xf0,8)):
        raise ValueError('Record setter callbacks differ')
    if source_qword(A(0x1499f6948)+0x30)!=A(0x140bb4a10) or source_qword(A(0x1499f69e8)+0x40)!=A(0x145b69ca0):
        raise ValueError('Manager post-load/override slots differ')
    off = h.image.offset(A(0x1487f5ac5)-h.image.pe.base)
    if h.raw[off:off+2]!=b'\xff\x25':
        raise ValueError('Temporary memset thunk differs')
    slot = A(0x1487f5ac5)+6+struct.unpack_from('<i',h.raw,off+2)[0]
    imported = load('build-object-zero-init-code').import_at(h.raw,h.image,slot)
    if (imported['dll'].lower(),imported['name'])!=('vcruntime140.dll','memset'):
        raise ValueError('Temporary memset import differs')
    payload = checked_blob(h.root,context['csv'])
    override_payload = checked_blob(h.root,context['override_csv'])
    inputs = {path.resolve():context_sha,
              Path(context['csv']['path']).resolve():hashlib.sha256(payload).hexdigest(),
              Path(context['override_csv']['path']).resolve():hashlib.sha256(override_payload).hexdigest(),
              **{Path(item['path']).resolve():item['sha256'] for item in h.evidence}}
    lines = payload.splitlines(keepends=True)
    parsed = csv.reader(io.StringIO(payload.decode('utf-8-sig'), newline=''))
    columns = next(parsed)
    previous = parsed.line_num
    rows = []
    for row in parsed:
        end = parsed.line_num
        if row[0] in context['task_ids']:
            rows.append((row, b''.join(lines[previous:end])))
        previous = end
    if [r[0][0] for r in rows] != context['task_ids'] or len(columns) != 17:
        raise ValueError('Selected source rows/schema changed')
    if any(row[16] for row,_ in rows):
        raise ValueError('Subset projection requires empty source service groups')
    override_rows = []
    physical = override_payload.splitlines(keepends=True)
    parsed_override = csv.reader(io.StringIO(override_payload.decode('utf-8-sig'),newline=''))
    override_columns = next(parsed_override); previous_line = parsed_override.line_num
    if override_columns!=['Id','TaskName','L10NOrder','L10NRegistrationDate','Untranslated']:
        raise ValueError('Russian override schema differs')
    for row in parsed_override:
        end_line = parsed_override.line_num
        if row[0] in context['task_ids']:
            override_rows.append((row,b''.join(physical[previous_line:end_line])))
        previous_line = end_line
    if len(override_rows)!=context.get('override_row_count',6): raise ValueError('Russian selected rows differ')
    uc, x, base = h.uc, h.x, h.scratch
    manager, primary, group, cells = base+0x1000, base+0x1018, base+0x1068, base+0x3000
    stream_object, stream_table, read_callback, hash_callback = [base+n for n in (0x2000,0x2100,0x2200,0x2300)]
    state = {}
    blocks = {}
    counts = {}
    cursor = [base+0x8000]

    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_'+name))

    def get(at, size=8):
        return int.from_bytes(uc.mem_read(at, size), 'little')

    def put(at, value, size=8):
        uc.mem_write(at, (int(value) % (1 << (size*8))).to_bytes(size, 'little'))

    def count(name):
        counts[name] = counts.get(name, 0)+1

    def allocate(size):
        if not 0 < size <= 16384:
            raise ValueError('Allocation size budget')
        at = (cursor[0]+31) & ~15
        cursor[0] = at+((size+15) & ~15)+16
        if cursor[0] >= base+0x33000:
            raise ValueError('Allocation arena budget')
        uc.mem_write(at-16, b'L'*16+bytes(size)+b'R'*16)
        blocks[at] = size
        return at

    def free(at):
        if at not in blocks:
            raise ValueError('Free outside fixture allocations '+hex(at))
        size = blocks.pop(at)
        if bytes(uc.mem_read(at-16,16)) != b'L'*16 or bytes(uc.mem_read(at+size,16)) != b'R'*16:
            raise ValueError('Heap guard differs')

    def zero(machine):
        at, value, size = reg('RCX'), reg('RDX'), reg('R8')
        if value or size != 0xa0 or not base+0x35000 < at < base+0x38000-size:
            raise ValueError('Temporary memset differs')
        uc.mem_write(at, bytes(size))
        h.finish(at)

    def raw_string(ptr):
        out = bytearray()
        for i in range(2048):
            value = bytes(uc.mem_read(ptr+i,1))
            if value == b'\0':
                return bytes(out)
            out += value
        raise ValueError('CString budget')

    def string(at):
        size, capacity = get(at+16), get(at+24)
        if size > capacity or capacity > 2047:
            raise ValueError('Cell string size/capacity')
        ptr = at if capacity <= 15 else get(at)
        data = bytes(uc.mem_read(ptr, size+1))
        if data[-1:] != b'\0':
            raise ValueError('Cell terminator')
        return data[:-1]

    def assign(at, data, capacity=None):
        capacity = max(15, len(data), capacity or 0)
        uc.mem_write(at, bytes(32))
        ptr = at if capacity == 15 else allocate(capacity+1)
        uc.mem_write(ptr, data+b'\0')
        if ptr != at:
            put(at, ptr)
        put(at+16,len(data)); put(at+24,capacity)

    def clear_cells():
        parser = state['parser']
        for at in range(get(parser+0x28), get(parser+0x30), 32):
            string(at)
            if get(at+24) > 15:
                free(get(at))
        put(parser+0x30, cells)

    def csv_init(machine):
        state['parser'] = reg('RCX')
        state.setdefault('parsers',[]).append(reg('RCX'))
        uc.mem_write(reg('RCX'), bytes(64))
        h.finish(reg('RCX'))

    def file_load(machine):
        if reg('RCX') != manager+8 or reg('RDX') != state['parser']:
            raise ValueError('File loader scope differs')
        parser = state['parser']
        if counts.get('file_load',0):
            # Main parser has reached EOF; nested override has its own stack object.
            state['main_bytes_read'] = state['position']
            state['raw'] = state['override_raw']; state['position'] = 0; state['override_active'] = True
            count('override_file')
        put(parser+8,stream_object); put(parser+0x20,5 if state.get('override_active') else 17)
        put(parser+0x28,cells); put(parser+0x30,cells); put(parser+0x38,cells+17*32)
        put(manager+16,16,2)  # ServerServiceGroupId column in the secondary interface.
        count('file_load'); h.finish(1)

    def read_byte(machine):
        if reg('RCX') != stream_object or reg('R8') != 1:
            raise ValueError('Byte stream contract')
        p = state['position']
        if p == len(state['raw']):
            h.finish(0)
        else:
            uc.mem_write(reg('RDX'),state['raw'][p:p+1]); state['position'] += 1; h.finish(1)

    def cell_copy(machine):
        if not cells <= reg('RCX') < cells+17*32:
            raise ValueError('Cell destination')
        assign(reg('RCX'),string(reg('RDX'))); h.finish(reg('RCX'))

    def cell_grow(machine):
        at = reg('RCX'); old = get(at) if get(at+24)>15 else 0
        if reg('RDX') != 1:
            raise ValueError('Cell growth count')
        data = string(at)+bytes([reg('R9') & 255])
        assign(at,data,min(2047,max(len(data),get(at+24)*2)))
        if old: free(old)
        h.finish(at)

    def cell_clear(machine):
        if (reg('RCX'),reg('RDX'),reg('R8')) != (cells,get(state['parser']+0x30),state['parser']+0x28):
            raise ValueError('Cell reset scope')
        clear_cells(); h.finish()

    def cell_value():
        if reg('RCX') != state['parser'] or reg('RDX') >= 17:
            raise ValueError('Column getter scope')
        return string(cells+reg('RDX')*32).decode('utf-8')

    def cell_pointer(machine):
        cell_value(); h.finish(cells+reg('RDX')*32)

    def column(machine):
        if reg('RCX') != state['parser']:
            raise ValueError('Header lookup receiver')
        name = string(reg('RDX')).decode('ascii')
        names = override_columns if state.get('override_active') else columns
        count('column'); h.finish(names.index(name) if name in names else 0xffffffff)

    def wide_read(ptr):
        if not ptr: return b''
        data = bytearray()
        for i in range(2048):
            value = bytes(uc.mem_read(ptr+i*2,2))
            if value == b'\0\0': return bytes(data)
            data += value
        raise ValueError('Wide string budget')

    def wide_init(machine):
        at, source = reg('RCX'), reg('RDX')
        data = wide_read(source) if source else b''
        uc.mem_write(at,bytes(16))
        if data:
            ptr = allocate(len(data)+2); uc.mem_write(ptr,data+b'\0\0')
            put(at,ptr); put(at+8,len(data)//2+1,4); put(at+12,len(data)//2+1,4)
        h.finish(at)

    def wide_copy(machine):
        if bytes(uc.mem_read(reg('RDX'),16)) != bytes(16):
            raise ValueError('Constructor wide source not empty')
        uc.mem_write(reg('RCX'),bytes(16)); h.finish(reg('RCX'))

    def wide_count(machine):
        data = raw_string(reg('RDX'))
        if reg('RCX') or reg('R8') != len(data): raise ValueError('UTF8 count contract')
        h.finish(len(data.decode('utf-8').encode('utf-16le'))//2)

    def wide_convert(machine):
        data = raw_string(reg('R8'))
        wide = data.decode('utf-8').encode('utf-16le')+b'\0\0'
        if reg('RDX')*2 < len(wide) or reg('R9') != len(data)+1: raise ValueError('UTF8 conversion contract')
        uc.mem_write(reg('RCX'),wide); h.finish(len(wide)//2)

    def array_resize(machine):
        at, n = reg('RCX'), reg('RDX')
        if n > 2048: raise ValueError('FString array budget')
        old = get(at); ptr = allocate(n*2) if n else 0
        if old: free(old)
        put(at,ptr); put(at+12,n,4); h.finish()

    def node_resize(machine):
        old,size = reg('RCX'),reg('RDX')
        if reg('R8') != 8 or old and old not in blocks: raise ValueError('Node resize contract')
        at = allocate(size)
        if old: uc.mem_write(at,bytes(uc.mem_read(old,min(size,blocks[old]))))
        count('node_resize'); h.finish(at)

    def map_clear(machine):
        at = reg('RCX')
        if at not in (primary,group) or reg('RDX') or get(at+8,4): raise ValueError('Fresh map clear contract')
        uc.mem_write(at,bytes(80)); put(at+0x2c,128,4); put(at+0x30,-1,4); h.finish()

    def bit_append(machine):
        at = reg('RCX')-0x10
        if at not in (primary,group) or reg('RDX'): raise ValueError('Bit append scope')
        n = get(at+0x28,4)
        if n >= 128: raise ValueError('Inline bit budget')
        put(at+0x28,n+1,4); h.finish(n)

    def bucket_alloc(machine):
        at = reg('RCX')-0x38
        if at not in (primary,group) or reg('RDX') or reg('R9')!=4: raise ValueError('Bucket allocate contract')
        n = reg('R8'); put(at+0x40,allocate(n*4) if n>2 else 0); h.finish()

    def buffer_resize(machine):
        at,n,size = reg('RCX'),reg('R8'),reg('R9')
        if reg('RDX'): raise ValueError('Buffer resize old size')
        if at in (primary+0x40,group+0x40) and n==0 and size==4: put(at,0)
        elif size==2 and n<=2048: put(at,allocate(n*2) if n else 0)
        else: raise ValueError('Buffer resize contract')
        h.finish()

    def group_array(machine):
        at = reg('RCX'); n = get(at+8,4)
        if n != reg('RDX')+1 or n>128: raise ValueError('Group append contract')
        old = get(at); cap = max(4,n*2)
        ptr = allocate(cap*8)
        if old: uc.mem_write(ptr,bytes(uc.mem_read(old,(n-1)*8)))
        put(at,ptr); put(at+12,cap,4); count('group_array_resize'); h.finish()

    def copy(machine):
        a,b,n = reg('RCX'),reg('RDX'),reg('R8')
        if n>4096 or not base<=a<=base+0x40000-n: raise ValueError('Copy fixture destination')
        uc.mem_write(a,bytes(uc.mem_read(b,n))); h.finish(a)

    def destroy_parser(machine):
        if reg('RCX') != state['parser']:
            if reg('RCX') not in state.get('parsers',[]):
                raise ValueError('Parser cleanup scope')
            # Both parsers have consumed EOF and cleared the shared cell vector.
            if get(reg('RCX')+0x30)!=cells: raise ValueError('Parent parser not empty')
            h.finish(); return
        clear_cells(); h.finish()

    def locale_get(machine):
        uc.mem_write(base+0x2400,bytes(16))
        h.finish(base+0x2400)

    def utf_wrapper(machine):
        data = raw_string(reg('RDX')).decode('utf-8').encode('utf-16le')+b'\0\0'
        if len(data)>2048: raise ValueError('Override UTF buffer budget')
        uc.mem_write(base+0x5000,data)
        put(reg('RCX')+0x108,base+0x5000); put(reg('RCX')+0x100,0)
        h.finish(reg('RCX'))

    def named_untranslated(machine):
        if reg('RCX')!=state['parser'] or not state.get('override_active'):
            raise ValueError('Untranslated read scope')
        value = string(cells+4*32)
        if value: raise ValueError('Selected source Untranslated unexpectedly nonempty')
        uc.mem_write(reg('RDX'),bytes(16))
        count('untranslated'); h.finish(reg('RDX'))

    def settings_get(machine):
        # Current localization override reads +0x1ec/+0x1ed. Exercise only zero flags.
        uc.mem_write(base+0x2600,bytes(512))
        h.finish(base+0x2600)

    def prefix_extract(machine):
        if reg('R8')!=3: raise ValueError('Override prefix length')
        text = wide_read(reg('RDX')).decode('utf-16le')[:3].encode('utf-16le')+b'\0\0'
        ptr = allocate(len(text)); uc.mem_write(ptr,text)
        put(reg('RCX'),ptr); put(reg('RCX')+8,4,4); put(reg('RCX')+12,4,4)
        h.finish(reg('RCX'))

    def compare_prefix(machine):
        if reg('RDX')!=A(0x14996c9c0): raise ValueError('Unexpected override string comparison')
        h.finish(0 if wide_read(reg('RCX'))==wide_read(reg('RDX')) else 1)

    def assign_override(machine):
        at,source = reg('RCX'),reg('RDX')
        nodes = get(primary); n = get(primary+8,4)
        if not nodes<=at<nodes+n*200 or (at-nodes-8)%200!=0x78:
            raise ValueError('Override tried to change a field other than TaskName')
        raw = wide_read(get(source)); old = get(at)
        uc.mem_write(at,bytes(16))
        if raw:
            ptr = allocate(len(raw)+2); uc.mem_write(ptr,raw+b'\0\0')
            put(at,ptr); put(at+8,len(raw)//2+1,4); put(at+12,len(raw)//2+1,4)
        if old: free(old)
        count('task_name_store'); h.finish(at)

    def hash_key(machine):
        if reg('RDX')!=8: raise ValueError('Hash length')
        h.finish(1)

    def free_callback(machine):
        free(reg('RCX')); h.finish()

    callbacks = {
        A(0x1445f5a40):csv_init, A(0x145a6e600):file_load, read_callback:read_byte, hash_callback:hash_key,
        A(0x1421e7340):cell_grow, A(0x1445df320):cell_copy, A(0x1445de2a0):cell_clear,
        A(0x1445f6840):column, A(0x1445f5fc0):cell_pointer,
        A(0x141426950):wide_init, A(0x141426b30):wide_init, A(0x1414266a0):wide_copy,
        A(0x14144c440):wide_count, A(0x1414466a0):wide_convert, A(0x141436ed0):array_resize,
        A(0x145b53b10):map_clear, A(0x141448fd0):map_clear, A(0x1414923d0):node_resize,
        A(0x141429680):bit_append, A(0x141436bc0):bucket_alloc, A(0x141436cc0):buffer_resize,
        A(0x14141c080):group_array, A(0x1487f5ab9):copy, A(0x1487f5ac5):zero,
        A(0x141431f80):free_callback, A(0x141483080):free_callback,
        A(0x1445f5b40):destroy_parser, A(0x145a4dc20):locale_get,
        A(0x145b74820):lambda machine:h.finish(0), A(0x143b7f400):lambda machine:h.finish(0),
        A(0x1414aeff0):lambda machine:(uc.mem_write(reg('RCX'),bytes(24)),h.finish(reg('RCX'))),
        A(0x1445df5a0):lambda machine:(uc.mem_write(reg('RCX'),bytes(40)),h.finish(reg('RCX'))),
        A(0x1445df7c0):lambda machine:h.finish(),
        A(0x146908950):lambda machine:h.finish(allocate(reg('RCX'))),
        A(0x1487e8ce0):lambda machine:h.finish(reg('RAX')),
    }
    callbacks.update({A(0x1415c0820):utf_wrapper,A(0x1445f6060):named_untranslated,A(0x14563dd10):settings_get,
        A(0x14142c4b0):prefix_extract,A(0x14145f1e0):compare_prefix,A(0x141441d60):assign_override,
        A(0x141404ac0):lambda machine:h.finish()})
    def numeric_input():
        ptr = reg('RCX')
        if not cells<=ptr<cells+17*32 and ptr not in blocks:
            raise ValueError('Loader CRT pointer outside current cells/allocations')
        data = raw_string(ptr)
        if len(data)>128: raise ValueError('Loader numeric input budget')
        return data
    runtime = install_runtime(h,numeric_input,A,base+0x7000)
    callbacks[A(0x145b547a0)] = lambda machine:h.finish(manager)
    for address, callback in callbacks.items(): h.add_fixture(address,callback)
    put(A(0x14b0c2b00),hash_callback)
    heap_provider=A(0x14b2f01c8)
    provider_rva=heap_provider-h.image.pe.base
    if not any(section['name']=='.data'
               and section['raw_size']<=provider_rva-section['rva']<=section['size']-8
               for section in h.image.pe.sections) or get(heap_provider)!=0:
        raise ValueError('Current loader alternate heap provider is not virtual zero')
    runs = []
    for reverse in (False,True):
        uc.mem_write(base+0x1000,bytes(0x32000)); blocks.clear(); counts.clear(); cursor[0]=base+0x8000
        ordered = list(reversed(rows)) if reverse else rows
        state.clear(); state.update(raw=b''.join(r[1] for r in ordered),position=0)
        ordered_override=list(reversed(override_rows)) if reverse else override_rows
        state['override_raw'] = b''.join(r[1] for r in ordered_override)
        override_names={r[0]:r[1] for r,_ in ordered_override}
        runtime['calls'].clear()
        put(manager,A(0x1499f6948)); put(manager+8,A(0x1499f69e8))
        put(primary+0x48,2,4); put(group+0x48,2,4)
        put(stream_object,stream_table); put(stream_table+0x20,read_callback)
        h.call(A(0x145b5f270),manager+8,budget=1000000)
        group_ids=list(dict.fromkeys(r[0][1] for r in ordered))
        if state['position'] != len(state['raw']) or get(primary+8,4)!=len(rows) or get(group+8,4)!=len(group_ids):
            raise ValueError('Loader stream/record/group counts differ')
        records = []
        for slot,(row,raw) in enumerate(ordered):
            at = get(primary)+slot*200+8
            if get(at)!=A(0x1499f67f8) or get(at+0x40)!=int(row[0]) or get(at+0x48)!=int(row[1]):
                raise ValueError('Loaded record key/vtable differs')
            for col,offset,size in ((2,0x58,4),(3,0x68,4),(4,0x88,1),(5,0x89,1),(6,0x8a,1),(7,0x8b,1),
                                    (8,0x8c,1),(10,0xa0,4),(11,0xa4,1)):
                if get(at+offset,size)!=int(row[col] or '0'): raise ValueError('Loaded scalar differs')
            if wide_read(get(at+0x78)).decode('utf-16le')!=override_names.get(row[0],''):
                raise ValueError('Russian TaskName differs')
            if wide_read(get(at+0x90)).decode('utf-16le') != row[9].replace('\r',''):
                raise ValueError('Loaded Param differs')
            for col,offset in ((12,0xa8),(13,0xac),(14,0xb0),(15,0xb4)):
                if bytes(uc.mem_read(at+offset,4))!=struct.pack('<f',float(row[col] or '0')):
                    raise ValueError('Loaded coordinate/radius differs')
            records.append(at)
        for group_slot,group_id in enumerate(group_ids):
            node = get(group)+group_slot*32
            expected_records=[at for at,(r,_) in zip(records,ordered) if r[1]==group_id]
            if get(node)!=int(group_id) or get(node+16,4)!=len(expected_records):
                raise ValueError('Loaded group key/count differs')
            actual = [get(get(node+8)+i*8) for i in range(len(expected_records))]
            if actual != expected_records: raise ValueError('Group pointer order differs')
        if counts.get('column')!=19 or counts.get('node_resize',0)<3:
            raise ValueError('Loader path coverage differs')
        applied=sum(r[0] in context['task_ids'] for r,_ in override_rows)
        if counts.get('override_file')!=1 or counts.get('task_name_store')!=applied or counts.get('untranslated')!=applied:
            raise ValueError('Native override coverage differs')
        for at,size in blocks.items():
            if bytes(uc.mem_read(at-16,16))!=b'L'*16 or bytes(uc.mem_read(at+size,16))!=b'R'*16:
                raise ValueError('Final heap guards differ')
        runs.append(dict(reverse=reverse,task_ids=[r[0][0] for r in ordered],records=len(rows),group_count=len(group_ids),
                         bytes_read=state.get('main_bytes_read',state['position']),callbacks=counts.copy(),group_order_matches_records=True))
        runs[-1]['override_bytes_read']=state['position']
        runs[-1]['russian_task_names']=[override_names.get(r[0][0],'') for r in ordered]
        default_at=A(0x1496706e0)
        default_offset=h.image.offset(default_at-h.image.pe.base)
        default_bytes=h.raw[default_offset:default_offset+4]
        if default_bytes!=bytes(4):raise ValueError('QuestTask constructor default changed')
        headers=[dict(task_id=row[0],base08=get(at+8),base10=get(at+0x10,4),base14=get(at+0x14,4)) for at,(row,_) in zip(records,ordered)]
        if any(any(header[field]!=0 for field in ('base08','base10','base14')) for header in headers):
            raise ValueError('Loaded QuestTask base constructor fields differ')
        runs[-1]['native_base_headers']=headers
        runs[-1]['base_default_source']=dict(address=hex(default_at),bytes=default_bytes.hex(),value=0)
        projections=[]; result,progress=base+0x6000,base+0x6100
        immutable=[(manager,bytes(uc.mem_read(manager,256)))]+[(at,bytes(uc.mem_read(at,size))) for at,size in blocks.items()]
        if source_qword(A(0x1499f67f8)+0x30)!=A(0x145b55aa0):
            raise ValueError('Loaded record Type getter changed')
        for i,(row,raw) in enumerate(ordered):
            for first,second in ((0,0),(1,2),(0x1234567800000001,0x8765432100000002)):
                uc.mem_write(result-16,b'A'*16+b'\xcc'*32+b'B'*16)
                uc.mem_write(progress-16,b'C'*16+bytes(32)+b'D'*16)
                put(progress+8,i,1);put(progress+0x10,first);put(progress+0x18,second)
                progress_before=bytes(uc.mem_read(progress-16,64))
                uc.reg_write(x.UC_X86_REG_RDX,int(row[1]));uc.reg_write(x.UC_X86_REG_R8,progress)
                if h.call(A(0x145de4610),result)!=result:raise ValueError('Loaded projection result differs')
                expected=bytearray(b'\xcc'*32);struct.pack_into('<QBB',expected,0,int(row[0]),int(row[8]),i)
                struct.pack_into('<II',expected,12,first&0xffffffff,second&0xffffffff);struct.pack_into('<Q',expected,24,0)
                if bytes(uc.mem_read(result,32))!=expected:raise ValueError('Native loaded task projection differs')
                if bytes(uc.mem_read(result-16,16))!=b'A'*16 or bytes(uc.mem_read(result+32,16))!=b'B'*16:
                    raise ValueError('Loaded projection output guard changed')
                if bytes(uc.mem_read(progress-16,64))!=progress_before:raise ValueError('Loaded projection input changed')
                if any(bytes(uc.mem_read(at,len(value)))!=value for at,value in immutable):
                    raise ValueError('Projection changed native loaded manager/records/allocations')
                projections.append(dict(index=i,quest_id=row[1],task_id=row[0],kind=int(row[8]),
                    first=first,second=second,progress_hex=bytes(uc.mem_read(result,32)).hex()))
        runs[-1]['native_projections']=projections
        runs[-1]['scalar_import_calls']={name:runtime['calls'].count(name) for name in ('atoi','_atoi64','strtoul','pow')}
    if any(hashlib.sha256(selected.read_bytes()).hexdigest()!=sha for selected,sha in inputs.items()):
        raise ValueError('Current loader input changed during replay')
    if hashlib.sha256(h.source.read_bytes()).hexdigest()!=h.sha:
        raise ValueError('Current loader source changed during replay')
    report = dict(source_sha256=h.sha,tool_sha256=audit.sha256(Path(__file__)),context_sha256=context_sha,
                  exports=h.evidence,csv_sha256=context['csv']['sha256'],memset_import=imported,runs=runs,
                  network_used=False,order_admitted=False,runtime_admitted=False,action_admitted=False,
                  full_catalog_verified=False,active_task_verified=False,metrics=metrics,limits=context['limits'])
    runtime['verify']()
    report.update(native_scalars=True, native_projection=True, native_override=True,
                  system_runtime=runtime['system_runtime'], scalar_imports=runtime['imported'],
                  override_sha256=context['override_csv']['sha256'])
    validate(report,context)
    target = audit.save_snapshot(h.root/'code-clues/quest-loader-current-native-v1',report)
    return target,report


if __name__ == '__main__':
    target,report = run()
    print(json.dumps(dict(artifact=str(target),runs=len(report['runs']),
        projections=sum(len(run['native_projections']) for run in report['runs']),
        abi_checks=report['metrics']['abi_checks']),ensure_ascii=False))
