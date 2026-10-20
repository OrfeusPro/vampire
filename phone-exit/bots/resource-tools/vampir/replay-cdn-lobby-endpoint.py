"""Native CDN selection -> same globals -> lobby endpoint/connect capture."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('cdn_lobby_source', HERE / 'build-headless-cdn-server-list.py')
cdn = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cdn)
native = cdn.body.head.headers.uri.http.preparation.url.settings.config.native
CONNECT = 0x144aa90c0


class Emulator(cdn.ServerListEmulator):
    def bounded(self, address, size):
        if getattr(self, 'global_host', None) == address and size == 16: return
        return super().bounded(address, size)

    def __init__(self, raw, image, fragments, document, connected):
        super().__init__(raw, image, fragments, document)
        self.connect_phase = False
        self.connected_fixture = connected
        self.endpoint = None
        self.events = []
        self.peer = self.scratch + 0x6000
        self.connect_hooks = {0x141435320, 0x1443fca20, 0x141424870, 0x14142d840,
            0x141424430, 0x14147d580, 0x14142c480, 0x1468e4100, 0x1445d8e60,
            0x1445d9550, 0x1445ea1b0, 0x148796040, 0x1487a2e19}
        roots = {image.roots[image.containing(a)][0] for a in (CONNECT, 0x1445e2a50)}
        for f in fragments:
            if f['root_begin_rva'] in roots:
                self.allowed.append((image.pe.base + f['begin_rva'], image.pe.base + f['end_rva']))
        pages = {p for lo, hi in self.allowed for p in range(lo & ~4095, (hi + 4095) & ~4095, 4096)}
        pages.update(a & ~4095 for a in self.connect_hooks)
        pages.update(a & ~4095 for f in fragments if f['root_begin_rva'] in roots
            for r in f['instructions'] for a in r['rip_references'])
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()): continue
            self.uc.mem_map(page, 4096)
            try: off = image.offset(page - image.pe.base)
            except ValueError: continue
            self.uc.mem_write(page, raw[off:off + 4096])

    def hook(self, uc, address, size, user):
        a, b, c, d = [uc.reg_read(getattr(self.x, 'UC_X86_REG_' + name)) for name in ('RCX', 'RDX', 'R8', 'R9')]
        if not self.connect_phase:
            if address == cdn.COPY_GLOBAL:
                if a != self.global_host or c > 512: raise ValueError('CDN global copy changed')
                text = bytes(uc.mem_read(b, c * 2)).decode('utf-16le') if c else ''
                # Bounded FString assignment fixture now materializes the descriptor.
                self.put_fstring(a, text)
                self.global_host_value = text
                self.shim_return(a, 'global_host_assignment_fixture')
                return
            return super().hook(uc, address, size, user)
        if address == 0x1445e2a50:
            self.endpoint = a
        if address not in self.connect_hooks: return super().hook(uc, address, size, user)
        result = 0
        if address == 0x141424870:
            if a != self.peer + 0x250 or b != int.from_bytes(uc.mem_read(self.global_host, 8), 'little'):
                raise ValueError('Connect did not consume CDN host global')
            if c > 512: raise ValueError('Connect FString bound')
            self.put_fstring(a, bytes(uc.mem_read(b, c * 2)).decode('utf-16le') if c else '')
            result = a
        elif address == 0x141435320:
            # Used for both diagnostics and endpoint conversion. ASCII fixtures only.
            text = self.wide_pointer(b)
            data = text.encode('ascii') + b'\0'
            pointer = self.allocate(len(data))
            uc.mem_write(pointer, data)
            uc.mem_write(a, bytes(0x90))
            uc.mem_write(a + 0x88, struct.pack('<Q', pointer))
        elif address == 0x14142d840: self.put_fstring(a, '')
        elif address in (0x1443fca20, 0x141424430, 0x14147d580, 0x14142c480, 0x1445d9550): pass
        elif address == 0x1468e4100:
            if not 1 <= a <= 2048: raise ValueError('Connect allocation bound')
            result = self.allocate(a)
        elif address == 0x1487a2e19:
            if c > 2048: raise ValueError('Connect memcpy bound')
            uc.mem_write(a, bytes(uc.mem_read(b, c)))
            result = a
        elif address == 0x1445d8e60:
            uc.mem_write(a, bytes(uc.mem_read(b, 32)))
            result = a
        elif address == 0x1445ea1b0:
            if (a, b, c) != (self.peer, self.endpoint, 0): raise ValueError('Lobby endpoint connect arguments changed')
            n, capacity = struct.unpack('<QQ', bytes(uc.mem_read(b + 0x18, 16)))
            # Endpoint string starts at +8; std::string size/capacity are +0x18/+0x20.
            pointer = int.from_bytes(uc.mem_read(b + 8, 8), 'little') if capacity > 15 else b + 8
            if not 0 <= n <= 512: raise ValueError('Endpoint string bound')
            host = bytes(uc.mem_read(pointer, n)).decode('ascii')
            self.events.append(dict(action='lower_connect_capture', host=host,
                port=int.from_bytes(uc.mem_read(b + 0x28, 2), 'little'), returned=self.connected_fixture))
            result = int(self.connected_fixture)
        elif address == 0x148796040: result = uc.reg_read(self.x.UC_X86_REG_RAX)
        else: raise ValueError('Unknown lobby endpoint fixture')
        self.shim_return(result, 'lobby_connect_backend_fixture')

    def replay_endpoint(self):
        selected = self.replay()
        if not selected.get('success'): raise ValueError('Fixture CDN selection failed')
        self.connect_phase = True
        self.uc.mem_write(self.peer, bytes(0x2c0))
        self.run(CONNECT, rcx=self.peer)
        if len(self.events) != 1: raise ValueError('Expected one connect capture')
        return dict(document_fixture=self.document, selected_index=selected['selected_index'],
            config_fields=selected['fields'], global_host=self.get_fstring(self.global_host),
            global_port_uint32=selected['global_port_uint32'], endpoint=self.events[0],
            peer_host=self.get_fstring(self.peer + 0x250),
            peer_port=int.from_bytes(self.uc.mem_read(self.peer + 0x260, 2), 'little'))


def build():
    path = native.ROOT / 'code-clues/headless-cdn-server-list.json'
    upstream = json.loads(path.read_text('utf-8'))
    raw = Path(upstream['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != upstream['sha256']: raise ValueError('Client changed')
    image = native.Image(raw)
    roots = {image.roots[image.containing(a)] for a in (CONNECT, 0x1445e2a50)}
    extra = native.decode_ranges(image, roots)
    fragments = list({f['begin_rva']: f for f in upstream['fragments'] + extra}.values())
    cases = []
    for host in ('lobby.invalid', 'long-host-for-endpoint-fixture.invalid'):
        for port in ('12000', '0', '-1', '65536', '2junk'):
            detail = dict(lobbyAddress=host, lobbyPort=port, patchURL='https://patch.invalid/', dataURL='https://data.invalid/')
            document = dict(select_server=dict(type='real'), server_list=[dict(type='REAL', detail=detail)])
            for accepted in (False, True):
                em = Emulator(raw, image, fragments, document, accepted)
                case = em.replay_endpoint()
                if (em.global_host, em.global_port) != (0x14b520cd0, 0x14b520cb0):
                    raise ValueError('CDN endpoint globals changed')
                if (case['endpoint']['host'], case['peer_host']) != (host, host): raise ValueError('Lobby host handoff mismatch')
                if case['endpoint']['port'] != case['global_port_uint32'] & 65535 or case['peer_port'] != case['endpoint']['port']:
                    raise ValueError('Lobby port narrowing changed')
                cases.append(case)
    return dict(schema_version=1, source=upstream['source'], source_sha256=upstream['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        inherited_tool_sha256=hashlib.sha256((HERE / 'build-headless-cdn-server-list.py').read_bytes()).hexdigest(),
        upstream_sha256=hashlib.sha256(path.read_bytes()).hexdigest(), fragments=extra,
        global_host=0x14b520cd0, global_port=0x14b520cb0, cases=cases,
        limitations=['Whole native CDN selection then whole lobby connect on the same machine/globals.',
            'Inherited JSON/string/allocator/CRT fixtures; global FString assignment materializes a bounded descriptor.',
            'UTF16-to-narrow conversion is an ASCII fixture; endpoint constructor executes with std::string copy fixture.',
            'Lower connect returns explicit bool fixtures; no socket, DNS, server response, startup or config precedence proof.'])


if __name__ == '__main__':
    report = build()
    output = native.ROOT / 'code-clues/cdn-lobby-endpoint-replay.json'
    output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(output), sha256=hashlib.sha256(output.read_bytes()).hexdigest(), cases=len(report['cases']))))
