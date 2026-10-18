"""Native default request context -> GET request line, without network IO."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('http_preparation', HERE / 'build-headless-cdn-preparation.py')
preparation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preparation)
REQUEST_LINE, STRING_APPEND = 0x1445ec6f0, 0x1445ddc80
CTOR_START, CTOR_STOP = 0x1445e25d0, 0x1445e26ac


class HttpLineEmulator(preparation.PreparationEmulator):
    def __init__(self, raw, image, fragments):
        super().__init__(raw, image, fragments)
        roots = {image.roots[image.containing(a)][0] for a in
                 [REQUEST_LINE, STRING_APPEND, preparation.url.APPEND]}
        extra = [(image.pe.base + f['begin_rva'], image.pe.base + f['end_rva'])
                 for f in fragments if f['root_begin_rva'] in roots]
        extra.append((CTOR_START, CTOR_STOP))
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

    def hook(self, machine, address, size, user):
        x = self.x
        if address in (preparation.url.COPY, preparation.url.MOVE):
            a, b, c = [machine.reg_read(reg) for reg in [x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8]]
            if not self.scratch <= b <= self.scratch + 0x80000 - c:
                self.bounded(a, c)
                if not 0 <= c <= 64:
                    raise ValueError('Static HTTP literal copy exceeds fixture bound')
                off = self.image.offset(b - self.image.pe.base)
                data = self.raw[off:off + c]
                if data not in (b'GET /', b' HTTP/', b'\r\n'):
                    raise ValueError('Unexpected static HTTP literal')
                machine.mem_write(a, data)
                rsp = machine.reg_read(x.UC_X86_REG_RSP)
                ret = struct.unpack('<Q', bytes(machine.mem_read(rsp, 8)))[0]
                machine.reg_write(x.UC_X86_REG_RAX, a)
                machine.reg_write(x.UC_X86_REG_RSP, rsp + 8)
                machine.reg_write(x.UC_X86_REG_RIP, ret)
                self.calls.append(dict(kind='static_http_literal_copy'))
                return
        return super().hook(machine, address, size, user)

    def request_line(self, path, poison):
        owner, context, uri, output = [self.scratch + offset for offset in [0x1000, 0x1320, 0x3000, 0x4000]]
        self.uc.mem_write(context, bytes([poison]) * 0x100)
        self.run(CTOR_START, stop=CTOR_STOP, rcx=context)
        method = struct.unpack('<I', bytes(self.uc.mem_read(context + 8, 4)))[0]
        version, user_agent = self.text(context + 0x10), self.text(context + 0x58)
        self.uc.mem_write(context, struct.pack('<Q', owner))
        # Empty request query collection; URI parsing and query encoding are not fixtures here.
        self.uc.mem_write(owner + 0x408, bytes(16))
        self.put(uri + 0x50, path)
        self.run(REQUEST_LINE, rcx=context, rdx=output, r8=uri)
        return dict(path_fixture=path, poison=poison, method_code=method, http_version=version,
                    default_user_agent_field=user_agent, request_line=self.text(output),
                    calls=list(self.calls), query_collection_empty=True, network_used=False)


def build():
    prior_path = preparation.url.settings.config.native.ROOT / 'code-clues/headless-cdn-preparation.json'
    prior = json.loads(prior_path.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('EXE changed')
    native = preparation.url.settings.config.native
    image = native.Image(raw)
    addresses = [REQUEST_LINE, STRING_APPEND, preparation.url.APPEND, CTOR_START, 0x1445e21f0,
                 0x14563f080, 0x1445ea140, 0x1445e4870, 0x1445e4b20, 0x1445ee470,
                 0x145636d00, 0x145642a30]
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in addresses})
    rows = {i['address']: i for f in fragments for i in f['instructions']}
    if rows[0x1445e234b]['direct_target'] != CTOR_START or rows[0x1445e4b67]['direct_target'] != REQUEST_LINE:
        raise ValueError('Request context/header builder callsite changed')
    literals = []
    for row in rows.values():
        for address in row['rip_references']:
            literal = preparation.url.settings.config.read_literal(raw, image, address)
            if literal:
                literals.append(dict(instruction=row['address'], **literal))
    paths = ['', 'window/real/1_2_3/config.json', 'a', '/a', 'a//b', 'x' * 15, 'x' * 16, 'x' * 200]
    cases = [HttpLineEmulator(raw, image, fragments).request_line(path, poison)
             for path in paths for poison in [0, 0xa5]]
    for case in cases:
        if (case['method_code'], case['http_version'], case['request_line']) != (
                1, '1.0', 'GET /' + case['path_fixture'] + ' HTTP/1.0\r\n'):
            raise ValueError('Native default request line differs')
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                preparation_report_sha256=hashlib.sha256(prior_path.read_bytes()).hexdigest(),
                fragments=fragments, literals=literals, cases=cases, network_ready=False,
                limitations=['Native context constructor prefix and request line executed; external allocator/CRT/cookie are bounded shims.',
                    'Empty query collection and explicit parsed-path fixtures, not URI parser or query encoder execution.',
                    'Full headers/body/transport/TLS/redirect/status/decode/callback lifecycle remain unverified.',
                    'Static CDN queue handoff evidence does not prove no later method/version/header overrides.',
                    'No actual source settings/server address acquired and no network requests made.'])


if __name__ == '__main__':
    report = build()
    target = preparation.url.settings.config.native.ROOT / 'code-clues/headless-cdn-http.json'
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                          native_cases=len(report['cases'])), indent=2))
