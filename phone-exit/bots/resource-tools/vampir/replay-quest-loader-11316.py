"""Whole QuestTask loader with native row/record/maps and explicit IO/storage fixtures."""
import csv
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


def run(context_path=None):
    audit = load('audit-client-release')
    path = Path(context_path) if context_path else HERE/'knowledge/native-contexts/quest-loader-11316.json'
    context = json.loads(path.read_text('utf-8'))
    native_scalars = context.get('native_scalars') is True
    native_override = context.get('native_override') is True
    override_edges = context.get('override_edges') is True
    native_projection = context.get('native_projection') is True
    h = load('native-request-harness-11316').make_harness(context['exports'],
            {int(a, 16) for a in context['functions']}, leaves={int(a, 16):b for a, b in context['leaves'].items()})
    if h.sha != context['source_sha256'] or not all(f.get('block_coverage_complete') for f in h.fragments):
        raise ValueError('Loader source/coverage differs')
    def source_qword(at):
        return struct.unpack_from('<Q',h.raw,h.image.offset(at-h.image.pe.base))[0]
    if any(source_qword(0x1499f67f8+offset)!=0x141403b70 for offset in range(0x68,0xf0,8)):
        raise ValueError('Record setter callbacks differ')
    if source_qword(0x1499f6948+0x30)!=0x140bb4a10 or source_qword(0x1499f69e8+0x40)!=0x145b69ca0:
        raise ValueError('Manager post-load/override slots differ')
    off = h.image.offset(0x1487f5ac5-h.image.pe.base)
    if h.raw[off:off+2]!=b'\xff\x25':
        raise ValueError('Temporary memset thunk differs')
    slot = 0x1487f5ac5+6+struct.unpack_from('<i',h.raw,off+2)[0]
    imported = load('build-object-zero-init-code').import_at(h.raw,h.image,slot)
    if (imported['dll'].lower(),imported['name'])!=('vcruntime140.dll','memset'):
        raise ValueError('Temporary memset import differs')
    index_path = h.root/context['record_index']
    if audit.sha256(index_path) != index_path.parent.name:
        raise ValueError('CSV index changed')
    index = json.loads(index_path.read_text('utf-8'))
    archive = Path(index['source']['path'])
    before = archive.stat()
    if index['source']['sha256'] != context['pak_sha256'] or audit.sha256(archive) != context['pak_sha256']:
        raise ValueError('Current PAK changed')
    reader_path = HERE.parent/'rfnext/scan-pak.py'
    reader = load('quest_loader_reader', reader_path)
    if audit.sha256(reader_path) != index['dependencies']['reader_sha256'] or audit.sha256(
            reader.ROOT/'tools/oodle-data-shared.dll') != index['dependencies']['oodle_sha256']:
        raise ValueError('CSV decoder changed')
    entry = next(e for e in index['entries'] if e['entry'] == context['csv_entry'])
    with archive.open('rb') as stream:
        header = reader.header(stream, entry['offset'], index['index_offset'])
        if header is None or header['end'] != entry['end']:
            raise ValueError('CSV entry changed')
        payload = reader.decode(stream, header)
    if hashlib.sha256(payload).hexdigest() != context['csv_sha256']:
        raise ValueError('CSV bytes changed')
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
    if native_projection and any(row[16] for row,_ in rows):
        raise ValueError('Subset projection requires empty source service groups')
    override_rows = []
    if native_override:
        override_entry = next(e for e in index['entries'] if e['entry']==context['override_entry'])
        with archive.open('rb') as stream:
            header = reader.header(stream,override_entry['offset'],index['index_offset'])
            if header is None or header['end']!=override_entry['end']: raise ValueError('Russian override header differs')
            override_payload = reader.decode(stream,header)
        if hashlib.sha256(override_payload).hexdigest()!=context['override_sha256']:
            raise ValueError('Russian override bytes differ')
        physical = override_payload.splitlines(keepends=True)
        parsed_override = csv.reader(io.StringIO(override_payload.decode('utf-8-sig'),newline=''))
        override_columns = next(parsed_override); previous_line = parsed_override.line_num
        if override_columns!=['Id','TaskName','L10NOrder','L10NRegistrationDate','Untranslated']:
            raise ValueError('Russian override schema differs')
        for row in parsed_override:
            end_line = parsed_override.line_num
            if row[0] in context['task_ids'] or override_edges and not override_rows and row[0] not in context['task_ids']:
                override_rows.append((row,b''.join(physical[previous_line:end_line])))
            previous_line = end_line
        if len(override_rows)!=context.get('override_row_count',6): raise ValueError('Russian selected rows differ')
        override_names = {r[0]:r[1] for r,_ in override_rows}
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
        if native_override and counts.get('file_load',0):
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

    def scalar(machine):
        value = cell_value()
        h.finish(int(value or '0') & 0xffffffffffffffff)

    def scalar_float(machine):
        value = float(cell_value() or '0')
        uc.reg_write(x.UC_X86_REG_XMM0,int.from_bytes(struct.pack('<f',value),'little')); h.finish()

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

    def skip_override(machine):
        if reg('RCX') != manager+8 or reg('RDX'): raise ValueError('Override fixture scope')
        count('override_fixture'); h.finish()

    def destroy_parser(machine):
        if reg('RCX') != state['parser']:
            if not native_override or reg('RCX') not in state.get('parsers',[]):
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
        if value and not override_edges: raise ValueError('Selected source Untranslated unexpectedly nonempty')
        text=value.decode('utf-8').encode('utf-16le')
        uc.mem_write(reg('RDX'),bytes(16))
        if text:
            ptr=allocate(len(text)+2); uc.mem_write(ptr,text+b'\0\0')
            put(reg('RDX'),ptr); put(reg('RDX')+8,len(text)//2+1,4); put(reg('RDX')+12,len(text)//2+1,4)
        count('untranslated'); h.finish(reg('RDX'))

    def settings_get(machine):
        # Explicit flags: localized text enabled by Untranslated=0, no debug bypass.
        uc.mem_write(base+0x2600,bytes(512))
        if override_edges: put(base+0x2600+0x1e4,1,1); put(base+0x2600+0x1e5,1,1)
        h.finish(base+0x2600)

    def prefix_extract(machine):
        if reg('R8')!=3: raise ValueError('Override prefix length')
        text = wide_read(reg('RDX')).decode('utf-16le')[:3].encode('utf-16le')+b'\0\0'
        ptr = allocate(len(text)); uc.mem_write(ptr,text)
        put(reg('RCX'),ptr); put(reg('RCX')+8,4,4); put(reg('RCX')+12,4,4)
        h.finish(reg('RCX'))

    def compare_prefix(machine):
        if reg('RDX')!=0x14996c9c0 and not override_edges: raise ValueError('Unexpected override string comparison')
        h.finish(0 if wide_read(reg('RCX'))==wide_read(reg('RDX')) else 1)

    def split_untranslated(machine):
        if reg('R9')!=1: raise ValueError('Split fixture flag differs')
        text=wide_read(get(reg('RCX'))).decode('utf-16le')
        if text!='TaskName': raise ValueError('Unexpected source Untranslated value')
        destination=reg('RDX'); ptr=allocate(16); uc.mem_write(ptr,bytes(16))
        data=text.encode('utf-16le')+b'\0\0'; string_ptr=allocate(len(data)); uc.mem_write(string_ptr,data)
        put(ptr,string_ptr); put(ptr+8,len(data)//2,4); put(ptr+12,len(data)//2,4)
        put(destination,ptr); put(destination+8,1,4); put(destination+12,1,4)
        count('split_untranslated'); h.finish(destination)

    def destroy_split(machine):
        at,n=reg('RCX'),reg('RDX')
        for index in range(n):
            ptr=get(at+index*16)
            if ptr: free(ptr)
        h.finish()

    def empty_fallback_cell(machine):
        if string(reg('RDX'))!=b'L10NRegistrationDate': raise ValueError('Unexpected fallback column')
        assign(base+0x5800,b''); h.finish(base+0x5800)

    def diagnostic(machine):
        count('missing_id_diagnostic'); h.finish()

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
        0x1445f5a40:csv_init, 0x145a6e600:file_load, read_callback:read_byte, hash_callback:hash_key,
        0x1421e7340:cell_grow, 0x1445df320:cell_copy, 0x1445de2a0:cell_clear,
        0x1445f6840:column, 0x1445f5ed0:scalar, 0x1445f5eb0:scalar, 0x1445f5e60:scalar,
        0x1445f6040:scalar, 0x1445f5f10:scalar_float, 0x1445f5fc0:cell_pointer,
        0x141426950:wide_init, 0x141426b30:wide_init, 0x1414266a0:wide_copy,
        0x14144c440:wide_count, 0x1414466a0:wide_convert, 0x141436ed0:array_resize,
        0x145b53b10:map_clear, 0x141448fd0:map_clear, 0x1414923d0:node_resize,
        0x141429680:bit_append, 0x141436bc0:bucket_alloc, 0x141436cc0:buffer_resize,
        0x14141c080:group_array, 0x1487f5ab9:copy, 0x1487f5ac5:zero,
        0x141431f80:free_callback, 0x141483080:free_callback,
        0x145b69ca0:skip_override, 0x1445f5b40:destroy_parser,
        0x145a4dc20:lambda machine:h.finish(0),
        0x145b74820:lambda machine:h.finish(0), 0x143b7f400:lambda machine:h.finish(0),
        0x1414aeff0:lambda machine:(uc.mem_write(reg('RCX'),bytes(24)),h.finish(reg('RCX'))),
        0x1445df5a0:lambda machine:(uc.mem_write(reg('RCX'),bytes(40)),h.finish(reg('RCX'))),
        0x1445df7c0:lambda machine:h.finish(),
        0x146908950:lambda machine:h.finish(allocate(reg('RCX'))),
        0x1487e8ce0:lambda machine:h.finish(reg('RAX')),
    }
    runtime = None
    if native_override:
        callbacks.pop(0x145b69ca0)
        callbacks[0x145a4dc20] = locale_get
        callbacks.update({0x1415c0820:utf_wrapper,0x1445f6060:named_untranslated,0x14563dd10:settings_get,
            0x14142c4b0:prefix_extract,0x14145f1e0:compare_prefix,0x141441d60:assign_override,
            0x141404ac0:lambda machine:h.finish()})
        if override_edges:
            callbacks.update({0x141432310:split_untranslated,0x141404ac0:destroy_split,
                0x1445f5f30:empty_fallback_cell,0x1414277b0:wide_init,0x1445e0bb0:diagnostic})
    if native_scalars:
        for address in (0x1445f5ed0,0x1445f5eb0,0x1445f5e60,0x1445f6040,0x1445f5f10):
            callbacks.pop(address)
        def numeric_input():
            ptr = reg('RCX')
            if not cells<=ptr<cells+17*32 and ptr not in blocks:
                raise ValueError('Loader CRT pointer outside current cells/allocations')
            data = raw_string(ptr)
            if len(data)>128: raise ValueError('Loader numeric input budget')
            return data
        runtime = load('replay-quest-scalars-11316').install_runtime(h,numeric_input,base+0x7000)
    if native_projection:
        callbacks[0x145b547a0] = lambda machine:h.finish(manager)
    for address, callback in callbacks.items(): h.add_fixture(address,callback)
    put(0x14b0c2b00,hash_callback); put(0x14b2f01c8,0)
    runs = []
    for reverse in (False,True):
        uc.mem_write(base+0x1000,bytes(0x32000)); blocks.clear(); counts.clear(); cursor[0]=base+0x8000
        ordered = list(reversed(rows)) if reverse else rows
        state.clear(); state.update(raw=b''.join(r[1] for r in ordered),position=0)
        if native_override:
            ordered_override=list(reversed(override_rows)) if reverse else override_rows
            state['override_raw'] = b''.join(r[1] for r in ordered_override)
            override_names={r[0]:r[1] for r,_ in ordered_override}
        if runtime: runtime['calls'].clear()
        put(manager,0x1499f6948); put(manager+8,0x1499f69e8)
        put(primary+0x48,2,4); put(group+0x48,2,4)
        put(stream_object,stream_table); put(stream_table+0x20,read_callback)
        h.call(0x145b5f270,manager+8,budget=1000000)
        group_ids=list(dict.fromkeys(r[0][1] for r in ordered))
        if state['position'] != len(state['raw']) or get(primary+8,4)!=len(rows) or get(group+8,4)!=len(group_ids):
            raise ValueError('Loader stream/record/group counts differ')
        records = []
        for slot,(row,raw) in enumerate(ordered):
            at = get(primary)+slot*200+8
            if get(at)!=0x1499f67f8 or get(at+0x40)!=int(row[0]) or get(at+0x48)!=int(row[1]):
                raise ValueError('Loaded record key/vtable differs')
            for col,offset,size in ((2,0x58,4),(3,0x68,4),(4,0x88,1),(5,0x89,1),(6,0x8a,1),(7,0x8b,1),
                                    (8,0x8c,1),(10,0xa0,4),(11,0xa4,1)):
                if get(at+offset,size)!=int(row[col] or '0'): raise ValueError('Loaded scalar differs')
            if native_override and wide_read(get(at+0x78)).decode('utf-16le')!=override_names.get(row[0],''):
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
        if counts.get('column')!=(19 if native_override else 16) or counts.get('node_resize',0)<3:
            raise ValueError('Loader path coverage differs')
        if native_override:
            applied=sum(r[0] in context['task_ids'] for r,_ in override_rows)
            if counts.get('override_file')!=1 or counts.get('task_name_store')!=applied or counts.get('untranslated')!=applied:
                raise ValueError('Native override coverage differs')
        elif counts.get('override_fixture')!=1: raise ValueError('Override fixture coverage differs')
        for at,size in blocks.items():
            if bytes(uc.mem_read(at-16,16))!=b'L'*16 or bytes(uc.mem_read(at+size,16))!=b'R'*16:
                raise ValueError('Final heap guards differ')
        runs.append(dict(reverse=reverse,task_ids=[r[0][0] for r in ordered],records=len(rows),group_count=len(group_ids),
                         bytes_read=state.get('main_bytes_read',state['position']),callbacks=counts.copy(),group_order_matches_records=True))
        if native_override:
            runs[-1]['override_bytes_read']=state['position']
            runs[-1]['russian_task_names']=[override_names.get(r[0][0],'') for r in ordered]
            if override_edges:
                runs[-1]['override_ids']=[r[0] for r,_ in ordered_override]
                runs[-1]['missing_translation_ids']=[r[0][0] for r in ordered if r[0][0] not in override_names]
        if native_projection:
            projections=[]; result,progress=base+0x6000,base+0x6100
            immutable=[(manager,bytes(uc.mem_read(manager,256)))]+[(at,bytes(uc.mem_read(at,size))) for at,size in blocks.items()]
            if source_qword(0x1499f67f8+0x30)!=0x145b55aa0:
                raise ValueError('Loaded record Type getter changed')
            for i,(row,raw) in enumerate(ordered):
                for first,second in ((0,0),(1,2),(0x1234567800000001,0x8765432100000002)):
                    uc.mem_write(result-16,b'A'*16+b'\xcc'*32+b'B'*16)
                    uc.mem_write(progress-16,b'C'*16+bytes(32)+b'D'*16)
                    put(progress+8,i,1);put(progress+0x10,first);put(progress+0x18,second)
                    progress_before=bytes(uc.mem_read(progress-16,64))
                    uc.reg_write(x.UC_X86_REG_RDX,int(row[1]));uc.reg_write(x.UC_X86_REG_R8,progress)
                    if h.call(0x145de4610,result)!=result:raise ValueError('Loaded projection result differs')
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
        if runtime:
            runs[-1]['scalar_import_calls']={name:runtime['calls'].count(name) for name in ('atoi','_atoi64','strtoul','pow')}
    after = archive.stat()
    if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns) or audit.sha256(archive)!=context['pak_sha256']:
        raise ValueError('PAK changed during replay')
    report = dict(source_sha256=h.sha,tool_sha256=audit.sha256(Path(__file__)),context_sha256=audit.sha256(path),
                  exports=h.evidence,csv_sha256=context['csv_sha256'],memset_import=imported,runs=runs,
                  network_used=False,order_admitted=False,limits=context['limits'])
    if runtime:
        runtime['verify'](); report['native_scalars']=True; report['system_runtime']=runtime['system_runtime']
        report['scalar_imports']=runtime['imported']
    if native_projection:report['native_projection']=True
    if native_override:
        report['native_override']=True; report['override_sha256']=context['override_sha256']
    target = audit.save_snapshot(h.root/('code-clues/quest-loader-projection-11316' if native_projection else 'code-clues/quest-override-edges-11316' if override_edges else
            'code-clues/quest-loader-override-11316' if native_override else
            'code-clues/quest-loader-scalars-11316' if runtime else 'code-clues/quest-loader-11316'),report)
    return target,report


if __name__ == '__main__':
    target,report = run()
    print(json.dumps(dict(artifact=str(target),runs=report['runs']),ensure_ascii=False))
