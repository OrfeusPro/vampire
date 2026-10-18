"""Native response header boundary/status/body-available probes; no HTTP IO."""
import ctypes
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('response_headers', HERE / 'build-headless-cdn-headers.py')
headers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(headers)
HEAD_SIZE, STATUS, AVAILABLE = 0x1445e74f0, 0x1445e75e0, 0x1445e7440
DATA, SIZE, SCAN, OPTIONS = 0x1445da5d0, 0x1445da610, 0x1418732e0, 0x141872810
SCAN_CALL = 0x141873324
STRSTR = 0x1487a2e31


class ResponseHeadEmulator(headers.HeaderEmulator):
    def __init__(self, raw, image, fragments):
        super().__init__(raw, image, fragments)
        roots = {image.roots[image.containing(a)][0] for a in [HEAD_SIZE, STATUS, AVAILABLE, SCAN]}
        extra = [(image.pe.base + f['begin_rva'], image.pe.base + f['end_rva'])
                 for f in fragments if f['root_begin_rva'] in roots]
        extra += [(DATA, DATA + 15), (SIZE, SIZE + 9), (OPTIONS, OPTIONS + 8)]
        self.allowed.extend(extra)
        pages = {a & ~4095 for lo, hi in extra for a in range(lo, hi + 4095, 4096)}
        pages.add(STRSTR & ~4095)
        self.scan_options_address = OPTIONS + 7 + struct.unpack_from('<i', raw, image.offset(OPTIONS - image.pe.base) + 3)[0]
        pages.add(self.scan_options_address & ~4095)
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
        self.vsscanf = getattr(self.crt, '__stdio_common_vsscanf')
        self.vsscanf.argtypes = [ctypes.c_uint64, ctypes.c_char_p, ctypes.c_size_t,
                               ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p]
        self.vsscanf.restype = ctypes.c_int

    def hook(self, machine, address, size, user):
        x = self.x
        if address == STRSTR:
            a, b = [machine.reg_read(reg) for reg in [x.UC_X86_REG_RCX, x.UC_X86_REG_RDX]]
            self.bounded(a, 1)
            needle = self.cstring(b, 8)
            if needle != b'\r\n\r\n':
                raise ValueError('Unexpected native response delimiter')
            haystack = self.cstring(a, 4096)
            offset = haystack.find(needle)
            result = a + offset if offset >= 0 else 0
            rsp = machine.reg_read(x.UC_X86_REG_RSP)
            ret = struct.unpack('<Q', bytes(machine.mem_read(rsp, 8)))[0]
            machine.reg_write(x.UC_X86_REG_RAX, result)
            machine.reg_write(x.UC_X86_REG_RSP, rsp + 8)
            machine.reg_write(x.UC_X86_REG_RIP, ret)
            self.calls.append(dict(kind='bounded_strstr_response_delimiter'))
            return
        if address == SCAN_CALL:
            source, count, fmt_address = [machine.reg_read(reg) for reg in [x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9]]
            self.bounded(source, 13)
            text, fmt = self.cstring(source, 13), self.cstring(fmt_address, 16)
            if fmt != b'%*s %d' or count != 0xffffffffffffffff:
                raise ValueError('Unexpected native response scan format')
            rsp = machine.reg_read(x.UC_X86_REG_RSP)
            va_list = struct.unpack('<Q', bytes(machine.mem_read(rsp + 0x28, 8)))[0]
            self.bounded(va_list, 8)
            destination = struct.unpack('<Q', bytes(machine.mem_read(va_list, 8)))[0]
            self.bounded(destination, 4)
            output = ctypes.c_int(0)
            native_args = (ctypes.c_void_p * 1)(ctypes.addressof(output))
            options = machine.reg_read(x.UC_X86_REG_RCX)
            if options != 0:
                raise ValueError('Unexpected native scan options')
            result = self.vsscanf(options, text, ctypes.c_size_t(-1).value, fmt, None, native_args)
            machine.mem_write(destination, struct.pack('<i', output.value))
            machine.reg_write(x.UC_X86_REG_RAX, result & 0xffffffff)
            machine.reg_write(x.UC_X86_REG_RIP, address + 6)
            self.calls.append(dict(kind='actual_system_crt_scan', scanned_prefix=text.decode('ascii'), assigned=output.value))
            return
        return super().hook(machine, address, size, user)

    def probe(self, payload):
        if not isinstance(payload, bytes) or len(payload) > 2048:
            raise ValueError('Response fixture exceeds local budget')
        obj, data = self.scratch + 0x1000, self.scratch + 0x2000
        self.uc.mem_write(data, payload + b'\0')
        self.uc.mem_write(obj + 0x18, struct.pack('<QQ', data, data + len(payload)))
        values = []
        for target in (HEAD_SIZE, STATUS, AVAILABLE):
            self.run(target, rcx=obj)
            values.append(self.uc.reg_read(self.x.UC_X86_REG_EAX))
        return dict(payload_hex=payload.hex(), header_bytes=values[0], status=values[1],
                    available_body_bytes=values[2], calls=list(self.calls), nul_terminated_fixture=True)


def build():
    root = headers.uri.http.preparation.url.settings.config.native.ROOT
    prior_path = root / 'code-clues/headless-cdn-headers.json'
    prior = json.loads(prior_path.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('EXE changed')
    native = headers.uri.http.preparation.url.settings.config.native
    image = native.Image(raw)
    addresses = [HEAD_SIZE, STATUS, AVAILABLE, SCAN, 0x1445e95f0, 0x1445edb30, 0x145642a30]
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in addresses})
    rows = {i['address']: i for f in fragments for i in f['instructions']}
    imports = headers.uri.http.preparation.url.settings.load('response_imports', HERE / 'build-object-zero-init-code.py')
    imported = imports.import_at(raw, image, rows[SCAN_CALL]['rip_references'][0])
    if imported['name'] != '__stdio_common_vsscanf':
        raise ValueError('Response scanner import changed')
    anchors = []
    for address, count in [(DATA, 15), (SIZE, 9), (OPTIONS, 8)]:
        off = image.offset(address - image.pe.base)
        content = raw[off:off + count]
        anchors.append(dict(address=address, file_offset=off, bytes=content.hex(), sha256=hashlib.sha256(content).hexdigest()))
    complete = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}'
    inputs = [complete[:n] for n in range(len(complete) + 1)]
    inputs += [b'HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n',
               b'HTTP/1.1 301 Moved\r\nLocation: /a\r\n\r\n', b'HTTP/1.1 500 Error\r\n\r\n',
               b'HTTP/1.1 200\r\n\r\n', b'HTTP/2 200 OK\r\n\r\n', b'anything 201 OK\r\n\r\n',
               b'HTTP/1.1 nope\r\n\r\n', b'HTTP/1.1 -1 X\r\n\r\n',
               b'HTTP/1.1 200 OK\n\n{}', b'HTTP/1.1 200 OK\x00\r\n\r\n{}',
               b'HTTP/1.1 200 OK\r\n\r\n\x00{}']
    cases = [ResponseHeadEmulator(raw, image, fragments).probe(payload) for payload in inputs]
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                headers_report_sha256=hashlib.sha256(prior_path.read_bytes()).hexdigest(),
                fragments=fragments, anchors=anchors, scan_import=imported, system_crt=prior['system_crt'],
                cases=cases, network_ready=False,
                limitations=['Native boundary/status/available-body functions executed on explicit NUL-terminated contiguous buffer fixtures.',
                    'strstr bounded shim; scanner forwarded to actual recorded Windows CRT for fixed12-byte prefix/%*s %d.',
                    'Buffer accumulation/terminator lifecycle/header field semantics/Content-Length/chunked/decoding/JSON not executed.',
                    'Available body count is bytes present, not proof of complete declared body or response acceptance.',
                    'Static receive/CDN callback roots are evidence only, not whole callbacks; no network/process/accounts used.'])


if __name__ == '__main__':
    report = build()
    target = headers.uri.http.preparation.url.settings.config.native.ROOT / 'code-clues/headless-cdn-response-head.json'
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                          native_cases=len(report['cases'])), indent=2))
