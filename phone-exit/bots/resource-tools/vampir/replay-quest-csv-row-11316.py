"""Execute the exported CSV tokenizer on source bytes; storage/IO are fixtures."""
import csv
import ctypes
import hashlib
import importlib.util
import io
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name, path=None):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), path or HERE/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run():
    audit = load('audit-client-release')
    context_path = HERE/'knowledge/native-contexts/quest-csv-row-11316.json'
    context = json.loads(context_path.read_text('utf-8'))
    h = load('native-request-harness-11316').make_harness(context['exports'], {0x1445f6520, 0x145a4d2f0},
            leaves={int(a, 16):b for a, b in context['leaves'].items()})
    if h.sha != context['source_sha256'] or not all(
            f.get('block_coverage_complete') and f.get('direct_flow_coverage_complete') for f in h.fragments):
        raise ValueError('Tokenizer coverage/source differs')
    index_path = h.root/context['record_index']
    if audit.sha256(index_path) != index_path.parent.name:
        raise ValueError('CSV index changed')
    index = json.loads(index_path.read_text('utf-8'))
    archive = Path(index['source']['path'])
    before = archive.stat()
    if index['source']['sha256'] != context['pak_sha256'] or audit.sha256(archive) != context['pak_sha256']:
        raise ValueError('Current PAK changed')
    reader_path = HERE.parent/'rfnext/scan-pak.py'
    reader = load('quest_csv_row_reader', reader_path)
    if audit.sha256(reader_path) != index['dependencies']['reader_sha256'] or audit.sha256(
            reader.ROOT/'tools/oodle-data-shared.dll') != index['dependencies']['oodle_sha256']:
        raise ValueError('CSV decoder changed')
    entry = next(e for e in index['entries'] if e['entry'] == context['csv_entry'])
    if entry.get('decoded_sha256') != context['csv_sha256']:
        raise ValueError('Task entry changed')
    with archive.open('rb') as stream:
        header = reader.header(stream, entry['offset'], index['index_offset'])
        if header is None or header['end'] != entry['end']:
            raise ValueError('Task entry header changed')
        payload = reader.decode(stream, header)
    if hashlib.sha256(payload).hexdigest() != context['csv_sha256']:
        raise ValueError('Task CSV changed')

    # Slice original physical lines, including quoted newlines and CRs. No csv.writer roundtrip.
    lines = payload.splitlines(keepends=True)
    parsed = csv.reader(io.StringIO(payload.decode('utf-8-sig'), newline=''))
    columns = next(parsed)
    if len(columns) != 17 or columns[-1] != 'ServerServiceGroupId':
        raise ValueError('Task schema changed')
    previous = parsed.line_num
    samples = []
    for row in parsed:
        end = parsed.line_num
        if row[1] == '110120':
            samples.append(dict(name=row[0], raw=b''.join(lines[previous:end]), expected=row, source=True))
        previous = end
    if [s['name'] for s in samples] != context['task_ids']:
        raise ValueError('Selected quest rows changed')
    samples += [dict(name=name, raw=raw, expected=expected, source=False) for name, raw, expected in (
        ('empty-final', b'a,b,\r\n', ['a', 'b', '']),
        ('empty-all', b',,\n', ['', '', '']),
        ('quoted-delimiter', b'"a,b","c""d",end\r\n', ['a,b', 'c"d', 'end']),
        ('quoted-newline', b'"a\r\nb",x\n', ['a\nb', 'x']),
        ('unquoted-cr', b'a\rb,c\n', ['ab', 'c']),
        ('quoted-empty', b'"",""\n', ['', '']),
        ('inline-boundary', b'123456789012345,1234567890123456\n', ['123456789012345', '1234567890123456']),
        ('last-without-newline', b'one,two', ['one', 'two']),
    )]

    directory = ctypes.create_unicode_buffer(32768)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    if not 0 < kernel.GetSystemDirectoryW(directory, len(directory)) < len(directory):
        raise ValueError('System directory unavailable')
    crt_path = Path(directory.value)/'ucrtbase.dll'
    crt_hash = audit.sha256(crt_path)
    crt = ctypes.CDLL(str(crt_path))
    crt.atoi.argtypes, crt.atoi.restype = [ctypes.c_char_p], ctypes.c_int
    crt.setlocale.argtypes, crt.setlocale.restype = [ctypes.c_int, ctypes.c_char_p], ctypes.c_char_p
    locale = crt.setlocale(0, None)
    slot = 0x14899bbf8
    imported = load('build-object-zero-init-code').import_at(h.raw, h.image, slot)
    if (imported['dll'].lower(), imported['name']) != ('api-ms-win-crt-convert-l1-1-0.dll', 'atoi'):
        raise ValueError('CSV CRT import differs')
    uc, x, base = h.uc, h.x, h.scratch
    parser, stream_object, table, callback, cells = [base+n for n in (0x1000, 0x1100, 0x1200, 0x1300, 0x2000)]
    current = {}
    allocations = {}
    allocation_cursor = base+0x6000
    stats = dict(read=0, grow=0, copy=0, clear=0, free=0, atoi=0)

    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_'+name))

    def put(at, value, size=8):
        uc.mem_write(at, int(value).to_bytes(size, 'little'))

    def get(at):
        return int.from_bytes(uc.mem_read(at, 8), 'little')

    def alloc(size):
        nonlocal allocation_cursor
        if not 1 <= size <= 2048 or allocation_cursor+size+32 >= base+0x30000:
            raise ValueError('String allocation budget exceeded')
        at = allocation_cursor+16
        allocation_cursor += (size+47)//16*16
        uc.mem_write(at-16, b'L'*16+bytes(size)+b'R'*16)
        allocations[at] = size
        return at

    def release(at):
        size = allocations.pop(at, None)
        if size is None or bytes(uc.mem_read(at-16, 16)) != b'L'*16 or bytes(uc.mem_read(at+size, 16)) != b'R'*16:
            raise ValueError('String allocation/free guard differs')

    def string(at):
        size, capacity = get(at+16), get(at+24)
        if size > capacity or capacity > 2047:
            raise ValueError('String size/capacity differs')
        ptr = at if capacity <= 15 else get(at)
        if capacity > 15 and allocations.get(ptr) != capacity+1:
            raise ValueError('String pointer outside live fixture allocation')
        if bytes(uc.mem_read(ptr+size, 1)) != b'\0':
            raise ValueError('String terminator missing')
        return bytes(uc.mem_read(ptr, size))

    def assign(at, data):
        uc.mem_write(at, bytes(32))
        if len(data) <= 15:
            uc.mem_write(at, data+b'\0')
            put(at+24, 15)
        else:
            ptr = alloc(len(data)+1)
            uc.mem_write(ptr, data+b'\0')
            put(at, ptr)
            put(at+24, len(data))
        put(at+16, len(data))

    def read_byte(machine):
        if reg('RCX') != stream_object or reg('R8') != 1 or not base+0x37000 < reg('RDX') < base+0x38000:
            raise ValueError('Stream read contract differs')
        stats['read'] += 1
        raw, position = current['raw'], current['position']
        if position == len(raw):
            h.finish(0)
        else:
            uc.mem_write(reg('RDX'), raw[position:position+1])
            current['position'] += 1
            h.finish(1)

    def grow(machine):
        at = reg('RCX')
        if reg('RDX') != 1 or not base+0x37000 < at < base+0x38000:
            raise ValueError('String growth contract differs')
        data = string(at)
        old = get(at) if get(at+24) > 15 else None
        assign(at, data+bytes([reg('R9') & 255]))
        if old is not None:
            release(old)
        stats['grow'] += 1
        h.finish(at)

    def copy(machine):
        at, source = reg('RCX'), reg('RDX')
        if not cells <= at < cells+17*32 or (at-cells) % 32 or not base+0x37000 < source < base+0x38000:
            raise ValueError('Cell copy bounds differ')
        assign(at, string(source))
        stats['copy'] += 1
        h.finish(at)

    def clear(machine):
        begin, end = reg('RCX'), reg('RDX')
        if begin != cells or end != get(parser+0x30) or reg('R8') != parser+0x28:
            raise ValueError('Cell clear contract differs')
        for at in range(begin, end, 32):
            string(at)
            if get(at+24) > 15:
                release(get(at))
        uc.mem_write(begin, bytes(end-begin))
        stats['clear'] += 1
        h.finish(end)

    def free(machine):
        release(reg('RCX'))
        stats['free'] += 1
        h.finish()

    def atoi(machine):
        if reg('RCX') != cells+16*32 or string(reg('RCX')) != b'':
            raise ValueError('Created blank service cell differs')
        value = crt.atoi(b'')
        stats['atoi'] += 1
        h.finish(value & 0xffffffff)

    h.add_fixture(callback, read_byte)
    h.add_fixture(0x1421e7340, grow)
    h.add_fixture(0x1445df320, copy)
    h.add_fixture(0x1445de2a0, clear)
    h.add_fixture(0x141431f80, free)
    h.add_fixture(0x1487e8ce0, lambda machine: h.finish(reg('RAX')))
    h.add_fixture(base+0x1500, atoi)
    put(slot, base+0x1500)
    # Fixed vector capacity: reaching the grow-vector target is an unreviewed-target failure.
    put(stream_object, table)
    put(table+0x20, callback)
    cases = []
    for sample in samples:
        uc.mem_write(parser, bytes(64))
        uc.mem_write(cells-16, b'A'*16+bytes(17*32)+b'B'*16)
        current.update(raw=sample['raw'], position=0)
        put(parser+8, stream_object)
        put(parser+0x20, len(sample['expected']))
        put(parser+0x28, cells)
        put(parser+0x30, cells)
        put(parser+0x38, cells+17*32)
        if not h.call(0x1445f6520, parser, budget=300000) & 255:
            raise ValueError('Tokenizer rejected '+sample['name'])
        count = (get(parser+0x30)-cells)//32
        actual = [string(cells+i*32).decode('utf-8') for i in range(count)]
        expected = [v.replace('\r', '') for v in sample['expected']]
        if actual != expected or current['position'] != len(current['raw']):
            raise ValueError('Tokenizer cell/stream differs for '+sample['name'])
        zero_gate = False
        if sample['source']:
            put(base+0x1408, 16, 2)
            uc.reg_write(x.UC_X86_REG_RDX, parser)
            if h.call(0x145a4d2f0, base+0x1400) & 255:
                raise ValueError('Created blank service cell was rejected')
            zero_gate = True
        # EOF call exercises clearing of previous cells, not merely a fresh parser.
        if h.call(0x1445f6520, parser) & 255 or get(parser+0x30) != cells or allocations:
            raise ValueError('EOF/reset differs')
        if bytes(uc.mem_read(cells-16, 16)) != b'A'*16 or bytes(uc.mem_read(cells+17*32, 16)) != b'B'*16:
            raise ValueError('Cell vector guards differ')
        allocation_cursor = base+0x6000
        cases.append(dict(name=sample['name'], source=sample['source'], input_sha256=hashlib.sha256(sample['raw']).hexdigest(),
                          byte_count=len(sample['raw']), cells=actual, eof_cleared=True, zero_gate=zero_gate))
    after = archive.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or audit.sha256(archive) != context['pak_sha256']:
        raise ValueError('PAK changed during replay')
    if audit.sha256(crt_path) != crt_hash or crt.setlocale(0, None) != locale:
        raise ValueError('CRT changed during replay')
    report = dict(source_sha256=h.sha, tool_sha256=audit.sha256(Path(__file__)), context_sha256=audit.sha256(context_path),
                  exports=h.evidence, csv_sha256=context['csv_sha256'], cases=cases, fixtures=stats, imported=imported,
                  system_runtime=dict(path=str(crt_path), sha256=crt_hash, locale=locale.decode()),
                  native_execution=True, network_used=False, order_admitted=False, limits=context['limits'])
    target = audit.save_snapshot(h.root/'code-clues/quest-csv-row-11316', report)
    return target, report


if __name__ == '__main__':
    target, report = run()
    print(json.dumps(dict(artifact=str(target), cases=len(report['cases']), fixtures=report['fixtures']), ensure_ascii=False))
