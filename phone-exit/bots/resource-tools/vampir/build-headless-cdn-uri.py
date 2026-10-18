"""Native ASCII URI parser -> actual GET request line; no network IO."""
import ctypes
import hashlib
import importlib.util
import json
import os
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('uri_http', HERE / 'build-headless-cdn-http.py')
http = importlib.util.module_from_spec(spec)
spec.loader.exec_module(http)
PARSE, CONSTRUCT = 0x1445e6460, 0x1421e1620
ATOI_CALL = 0x1445e6b96


class UriEmulator(http.HttpLineEmulator):
    def __init__(self, raw, image, fragments):
        super().__init__(raw, image, fragments)
        roots = {image.roots[image.containing(a)][0] for a in (PARSE, CONSTRUCT)}
        extra = [(image.pe.base + f['begin_rva'], image.pe.base + f['end_rva'])
                 for f in fragments if f['root_begin_rva'] in roots]
        self.allowed.extend(extra)
        pages = {a & ~4095 for lo, hi in extra for a in range(lo, hi + 4095, 4096)}
        for f in fragments:
            for row in f['instructions']:
                if any(lo <= row['address'] < hi for lo, hi in extra):
                    pages.update(a & ~4095 for a in row['rip_references'])
        regions = list(self.uc.mem_regions())
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in regions):
                continue
            self.uc.mem_map(page, 4096)
            off = image.offset(page - image.pe.base)
            self.uc.mem_write(page, raw[off:off + 4096])
        self.crt_path = Path(os.environ['SystemRoot']) / 'System32/ucrtbase.dll'
        self.crt = ctypes.CDLL(str(self.crt_path))
        self.atoi = self.crt.atoi
        self.atoi.argtypes = [ctypes.c_char_p]
        self.atoi.restype = ctypes.c_int

    def hook(self, machine, address, size, user):
        x = self.x
        if address == ATOI_CALL:
            pointer = machine.reg_read(x.UC_X86_REG_RCX)
            data = bytearray()
            for index in range(64):
                self.bounded(pointer + index, 1)
                value = bytes(machine.mem_read(pointer + index, 1))
                if value == b'\0':
                    break
                data.extend(value)
            else:
                raise ValueError('Port conversion fixture exceeds bound')
            data.decode('ascii')
            result = self.atoi(bytes(data))
            machine.reg_write(x.UC_X86_REG_RAX, result & 0xffffffff)
            machine.reg_write(x.UC_X86_REG_RIP, address + 6)
            self.calls.append(dict(kind='system_crt_atoi', result=result))
            return
        if address == http.preparation.MEMCMP:
            a, b, c = [machine.reg_read(reg) for reg in [x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8]]
            if not self.scratch <= b <= self.scratch + 0x80000 - c:
                self.bounded(a, c)
                if c not in (4, 5):
                    raise ValueError('Unexpected static scheme comparison length')
                offset = self.image.offset(b - self.image.pe.base)
                right = self.raw[offset:offset + c]
                if right not in (b'http', b'https'):
                    raise ValueError('Unexpected static scheme comparison')
                left = bytes(machine.mem_read(a, c))
                result = next((p - q for p, q in zip(left, right) if p != q), 0) & 0xffffffff
                rsp = machine.reg_read(x.UC_X86_REG_RSP)
                ret = struct.unpack('<Q', bytes(machine.mem_read(rsp, 8)))[0]
                machine.reg_write(x.UC_X86_REG_RAX, result)
                machine.reg_write(x.UC_X86_REG_RSP, rsp + 8)
                machine.reg_write(x.UC_X86_REG_RIP, ret)
                self.calls.append(dict(kind='static_scheme_memcmp'))
                return
        return super().hook(machine, address, size, user)

    def parse(self, value):
        source, uri, owner, context, output = [self.scratch + off for off in [0x5000, 0x6000, 0x8000, 0x8320, 0x9000]]
        self.put(source, value)
        self.run(PARSE, rcx=uri, rdx=source)
        fields = dict(scheme=self.text(uri + 8), host=self.text(uri + 0x28),
                      port=struct.unpack('<H', bytes(self.uc.mem_read(uri + 0x48, 2)))[0], path=self.text(uri + 0x50))
        self.run(http.CTOR_START, stop=http.CTOR_STOP, rcx=context)
        self.uc.mem_write(context, struct.pack('<Q', owner))
        self.uc.mem_write(owner + 0x408, bytes(16))
        self.run(http.REQUEST_LINE, rcx=context, rdx=output, r8=uri)
        return dict(url_fixture=value, fields=fields, request_line=self.text(output), calls=list(self.calls),
                    query_collection_empty=True, network_used=False)


def build():
    prior_path = http.preparation.url.settings.config.native.ROOT / 'code-clues/headless-cdn-http.json'
    prior = json.loads(prior_path.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('EXE changed')
    native = http.preparation.url.settings.config.native
    image = native.Image(raw)
    addresses = [PARSE, CONSTRUCT, http.preparation.STRING_COPY, http.REQUEST_LINE, http.STRING_APPEND,
                 http.preparation.url.APPEND, http.CTOR_START, 0x1445e2d80, 0x1445e3d00, 0x14563f080]
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in addresses})
    rows = {i['address']: i for f in fragments for i in f['instructions']}
    if rows[0x1445e2dfd]['direct_target'] != PARSE:
        raise ValueError('URL constructor parser anchor changed')
    imports = http.preparation.url.settings.load('uri_imports', HERE / 'build-object-zero-init-code.py')
    imported = imports.import_at(raw, image, rows[ATOI_CALL]['rip_references'][0])
    if imported['name'] != 'atoi':
        raise ValueError('Port conversion import changed')
    inputs = ['https://cdn.invalid/window/real/1_2_3/config.json', 'https://cdn.invalid/',
              'https://cdn.invalid', 'http://cdn.invalid/a', 'https://cdn.invalid:8443/a',
              'https://cdn.invalid:443/a', 'https://cdn.invalid//a', 'https://cdn.invalid/a%20b',
              'https://cdn.invalid/a?x=1', 'https://cdn.invalid/a#frag', 'HTTPS://cdn.invalid/a',
              'https://CDN.INVALID/A', 'https://cdn.invalid:65535/a', 'https://cdn.invalid:65536/a',
              'https://cdn.invalid:abc/a', 'https://cdn.invalid/' + 'x' * 180]
    inputs += ['https://127.0.0.1:00443/a', 'https://cdn.invalid/a%2Fb',
               'https://cdn.invalid/a/../b', 'https://cdn.invalid/a%3Fb',
               'https://cdn.invalid///a', 'https://cdn.invalid:0/a']
    cases = [UriEmulator(raw, image, fragments).parse(value) for value in inputs]
    emulator = UriEmulator(raw, image, fragments)
    crt = dict(path=str(emulator.crt_path), sha256=hashlib.sha256(emulator.crt_path.read_bytes()).hexdigest(),
               usage='Actual Windows ucrtbase atoi on artificial bounded ASCII port strings; not game/network IO')
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                http_report_sha256=hashlib.sha256(prior_path.read_bytes()).hexdigest(),
                fragments=fragments, atoi_import=imported, system_crt=crt, cases=cases, network_ready=False,
                limitations=['Native parser/string constructors/copies/request line executed, external memory/search/compare/cookie bounded shims.',
                    'Port atoi forwarded to actual recorded Windows CRT on synthetic ASCII; overflow inputs outside fixture range untested.',
                    'Empty request query collection, not full HTTP header/body or response lifecycle.',
                    'Non-ASCII, IPv6/userinfo/other malformed URI classes and real settings/HTTP/TLS remain unverified.'])


if __name__ == '__main__':
    report = build()
    target = http.preparation.url.settings.config.native.ROOT / 'code-clues/headless-cdn-uri.json'
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                          native_cases=len(report['cases']), examples=[c['fields'] for c in report['cases'][:3]]), indent=2))
