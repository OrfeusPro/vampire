"""Native URI/default context -> full GET header block, no transport."""
import ctypes
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('headers_uri', HERE / 'build-headless-cdn-uri.py')
uri = importlib.util.module_from_spec(spec)
spec.loader.exec_module(uri)
BUILD = 0x1445e4b20
FORMAT_CALL, FORMAT_OPTIONS = 0x1445da2bf, 0x141435030


class HeaderEmulator(uri.UriEmulator):
    def __init__(self, raw, image, fragments):
        super().__init__(raw, image, fragments)
        addresses = [BUILD, 0x1445ec230, 0x1445ebbc0, 0x1445eb970, 0x1445ebed0,
                     0x1445ec3d0, 0x1445d8240, 0x1445d49a0, 0x1445da240, 0x1445ddd10]
        roots = {image.roots[image.containing(a)][0] for a in addresses}
        extra = [(image.pe.base + f['begin_rva'], image.pe.base + f['end_rva'])
                 for f in fragments if f['root_begin_rva'] in roots]
        extra.append((FORMAT_OPTIONS, FORMAT_OPTIONS + 8))
        self.allowed.extend(extra)
        pages = {a & ~4095 for lo, hi in extra for a in range(lo, hi + 4095, 4096)}
        pages.add(0x14b248d30 & ~4095)
        for f in fragments:
            for row in f['instructions']:
                if any(lo <= row['address'] < hi for lo, hi in extra):
                    pages.update(a & ~4095 for a in row['rip_references'])
        regions = list(self.uc.mem_regions())
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in regions):
                continue
            self.uc.mem_map(page, 4096)
            try:
                off = image.offset(page - image.pe.base)
            except ValueError:
                continue
            self.uc.mem_write(page, raw[off:off + 4096])
        self.vsprintf = getattr(self.crt, '__stdio_common_vsprintf')
        self.vsprintf.restype = ctypes.c_int
        self.vsprintf.argtypes = [ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t,
                                ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p]

    def cstring(self, address, limit=512):
        data = bytearray()
        for index in range(limit):
            value = bytes(self.uc.mem_read(address + index, 1))
            if value == b'\0':
                return bytes(data)
            data.extend(value)
        raise ValueError('Header CString fixture exceeds bound')

    def hook(self, machine, address, size, user):
        x = self.x
        if address == FORMAT_CALL:
            buffer = machine.reg_read(x.UC_X86_REG_RDX)
            capacity = machine.reg_read(x.UC_X86_REG_R8)
            fmt = self.cstring(machine.reg_read(x.UC_X86_REG_R9))
            if fmt not in (b'User-Agent: %s\r\n', b'Referer: %s\r\n') or not 1 <= capacity <= 2048:
                raise ValueError('Unreviewed header formatting fixture')
            self.bounded(buffer, capacity)
            rsp = machine.reg_read(x.UC_X86_REG_RSP)
            va_list = struct.unpack('<Q', bytes(machine.mem_read(rsp + 0x28, 8)))[0]
            self.bounded(va_list, 8)
            argument = struct.unpack('<Q', bytes(machine.mem_read(va_list, 8)))[0]
            self.bounded(argument, 1)
            text = self.cstring(argument)
            output = ctypes.create_string_buffer(capacity)
            text_buffer = ctypes.create_string_buffer(text)
            native_args = (ctypes.c_void_p * 1)(ctypes.addressof(text_buffer))
            options = machine.reg_read(x.UC_X86_REG_RCX)
            if options != 2:
                raise ValueError('Unreviewed native CRT formatting options')
            result = self.vsprintf(options, output, capacity, fmt, None, native_args)
            if result < 0 or result >= capacity:
                raise ValueError('Unexpected header format truncation')
            machine.mem_write(buffer, output.raw[:result + 1])
            machine.reg_write(x.UC_X86_REG_RAX, result)
            machine.reg_write(x.UC_X86_REG_RIP, address + 6)
            self.calls.append(dict(kind='actual_system_crt_format', format=fmt.decode('ascii')))
            return
        if address in (uri.http.preparation.url.COPY, uri.http.preparation.url.MOVE):
            a, b, c = [machine.reg_read(reg) for reg in [x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8]]
            if not self.scratch <= b <= self.scratch + 0x80000 - c:
                self.bounded(a, c)
                if not 0 < c <= 64:
                    raise ValueError('Static header copy exceeds fixture bound')
                off = self.image.offset(b - self.image.pe.base)
                data = self.raw[off:off + c]
                if data not in (b'GET /', b' HTTP/', b'\r\n', b'Host: ', b':'):
                    raise ValueError('Unexpected static header literal copy')
                machine.mem_write(a, data)
                rsp = machine.reg_read(x.UC_X86_REG_RSP)
                ret = struct.unpack('<Q', bytes(machine.mem_read(rsp, 8)))[0]
                machine.reg_write(x.UC_X86_REG_RAX, a)
                machine.reg_write(x.UC_X86_REG_RSP, rsp + 8)
                machine.reg_write(x.UC_X86_REG_RIP, ret)
                self.calls.append(dict(kind='static_header_literal_copy'))
                return
        return super().hook(machine, address, size, user)

    def header(self, value, keep_alive=False, user_agent=None, referer=None):
        parsed = self.parse(value)
        context, output, parsed_uri = [self.scratch + off for off in (0x8320, 0xa000, 0x6000)]
        self.uc.mem_write(context + 0xa8, bytes([keep_alive]))
        if user_agent is not None:
            self.put(context + 0x58, user_agent)
        if referer is not None:
            self.put(context + 0x38, referer)
        self.run(BUILD, rcx=context, rdx=output, r8=parsed_uri)
        return dict(url_fixture=value, fields=parsed['fields'], keep_alive_fixture=keep_alive,
                    user_agent_fixture=user_agent, referer_fixture=referer, header=self.text(output),
                    calls=list(self.calls), query_collection_empty=True, body_empty=True, network_used=False)


def build():
    prior_path = uri.http.preparation.url.settings.config.native.ROOT / 'code-clues/headless-cdn-uri.json'
    prior = json.loads(prior_path.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('EXE changed')
    native = uri.http.preparation.url.settings.config.native
    image = native.Image(raw)
    addresses = [uri.PARSE, uri.CONSTRUCT, uri.http.preparation.STRING_COPY, uri.http.REQUEST_LINE,
                 uri.http.STRING_APPEND, uri.http.preparation.url.APPEND, uri.http.CTOR_START,
                 BUILD, 0x1445ec230, 0x1445ebbc0, 0x1445eb970, 0x1445ebed0,
                 0x1445ec3d0, 0x1445d8240, 0x1445d49a0, 0x1445da240, 0x1445ddd10]
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in addresses})
    rows = {i['address']: i for f in fragments for i in f['instructions']}
    imports = uri.http.preparation.url.settings.load('header_imports', HERE / 'build-object-zero-init-code.py')
    imported = imports.import_at(raw, image, rows[FORMAT_CALL]['rip_references'][0])
    if imported['name'] != '__stdio_common_vsprintf':
        raise ValueError('Native header format import changed')
    inputs = ['https://cdn.invalid/window/real/1_2_3/config.json', 'https://cdn.invalid/',
              'http://cdn.invalid/a', 'https://cdn.invalid:8443/a', 'https://CDN.INVALID//a',
              'https://127.0.0.1:00443/a%20b', 'https://cdn.invalid/' + 'x' * 180]
    cases = [HeaderEmulator(raw, image, fragments).header(value) for value in inputs]
    cases += [HeaderEmulator(raw, image, fragments).header(inputs[0], keep_alive=True),
              HeaderEmulator(raw, image, fragments).header(inputs[0], user_agent=''),
              HeaderEmulator(raw, image, fragments).header(inputs[0], user_agent='TestAgent/2.0'),
              HeaderEmulator(raw, image, fragments).header(inputs[0], referer='https://ref.invalid/')]
    off = image.offset(FORMAT_OPTIONS - image.pe.base)
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                uri_report_sha256=hashlib.sha256(prior_path.read_bytes()).hexdigest(),
                fragments=fragments, format_import=imported,
                format_options_leaf=dict(address=FORMAT_OPTIONS, file_offset=off, bytes=raw[off:off + 8].hex()),
                system_crt=prior['system_crt'], cases=cases, network_ready=False,
                limitations=['Native URI/context/request line/full header builder and field builders executed on empty query/body/cookie/range fixtures.',
                    'Allocator/memory/search/compare/cookie are bounded shims; formatted strings forwarded to actual recorded Windows CRT.',
                    'CRT va_list pointers translated for known single-string formats only; not general variadic emulation.',
                    'Nonempty body/query/cookie/range/custom raw header paths and later overrides/transport/response remain unverified.',
                    'No actual source settings or real HTTP/TLS/network used.'])


if __name__ == '__main__':
    report = build()
    target = uri.http.preparation.url.settings.config.native.ROOT / 'code-clues/headless-cdn-headers.json'
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                          native_cases=len(report['cases']), header=report['cases'][0]['header']), indent=2))
