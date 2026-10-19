"""Native select_server/type load and whole SetServerList with JSON/FString shims."""
import ctypes
import hashlib
import importlib.util
import itertools
import json
import os
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('server_body', HERE / 'build-headless-cdn-body.py')
body = importlib.util.module_from_spec(spec)
spec.loader.exec_module(body)
SET_LIST, CMP = 0x145661a70, 0x1414596e0
TYPE_START, TYPE_END, TYPE_MISSING = 0x14565a6b8, 0x14565a753, 0x14565f6a2
CTOR, LOOKUP, TOP_LOOKUP, CONVERT, FREE = 0x141421150, 0x14563da10, 0x14563dc30, 0x1415e48f0, 0x14147d580
ARRAY, HASH, FIND, OBJECT = 0x1415e4680, 0x141420380, 0x14158a730, 0x2003e000
CONCAT_C, CONCAT, APPEND, COPY_GLOBAL, FORMAT = 0x141425ec0, 0x1414260a0, 0x141424430, 0x141424870, 0x14142d840
PORT_CALL = 0x1456623bf
KEYS = ('lobbyAddress', 'lobbyPort', 'patchURL', 'dataURL')
OFFSETS = (0xd0, 0xe0, 0xf0, 0x100)


class ServerListEmulator(body.BodyEmulator):
    def __init__(self, raw, image, fragments, document):
        super().__init__(raw, image, fragments)
        self.document = document
        self.obj, self.root_ref = self.scratch + 0x1000, self.scratch + 0x5000
        self.values, self.maps, self.objects, self.nodes = {}, {}, {}, {}
        self.fstrings, self.lookups, self.hash_keys = set(), [], []
        self.cursor = self.scratch + 0x40000
        root = image.roots[image.containing(SET_LIST)][0]
        extra = [(image.pe.base + f['begin_rva'], image.pe.base + f['end_rva'])
                 for f in fragments if f['root_begin_rva'] == root]
        extra += [(CMP, CMP + 71), (TYPE_START, TYPE_END)]
        self.allowed.extend(extra)
        rows = {r['address']: r for f in fragments for r in f['instructions']}
        self.global_host = rows[0x145662389]['rip_references'][0]
        self.global_port = rows[0x1456623c5]['rip_references'][0]
        self.fold_table = CMP + 10 + struct.unpack_from('<i', raw, image.offset(CMP - image.pe.base) + 6)[0]
        pages = {a & ~4095 for lo, hi in extra for a in range(lo, hi + 4095, 4096)}
        shims = [CTOR, LOOKUP, TOP_LOOKUP, CONVERT, FREE, ARRAY, HASH, FIND,
                 CONCAT_C, CONCAT, APPEND, COPY_GLOBAL, FORMAT, TYPE_MISSING]
        pages.update(a & ~4095 for a in [*shims, self.global_host, self.global_port, self.fold_table])
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
        self.crt._wtoi.argtypes = [ctypes.c_wchar_p]
        self.crt._wtoi.restype = ctypes.c_int
        self.root_map = self.allocate(32)
        self.maps[self.root_map] = document
        self.uc.mem_write(self.root_ref, struct.pack('<QQ', self.root_map, 0))
        self.type_missing = False
        self.global_host_value = None
        self.uc.mem_write(self.global_port, b'\xcc' * 4)
        for offset, value in [(0x28, 'old-type'), (0x230, ''), *zip(OFFSETS, ['old-host', 'old-port', 'old-patch', 'old-data'])]:
            self.put_fstring(self.obj + offset, value)

    def put_fstring(self, destination, text):
        if not isinstance(text, str):
            raise ValueError('Non-string JSON-to-FString fixture is unproven')
        data = text.encode('utf-16le', 'surrogatepass') + b'\0\0'
        self.bounded(destination, 16)
        if len(data) > 1024:
            raise ValueError('FString fixture exceeds budget')
        pointer = self.allocate(len(data))
        self.fstrings.add(pointer)
        self.uc.mem_write(pointer, data)
        self.uc.mem_write(destination, struct.pack('<QII', pointer, len(data) // 2, len(data) // 2))

    def get_fstring(self, address):
        self.bounded(address, 16)
        pointer, count, capacity = struct.unpack('<QII', bytes(self.uc.mem_read(address, 16)))
        if count == 0:
            return ''
        if pointer not in self.fstrings or not 1 <= count <= capacity <= 512:
            raise ValueError('Invalid FString fixture')
        data = bytes(self.uc.mem_read(pointer, count * 2))
        if not data.endswith(b'\0\0'):
            raise ValueError('Unterminated FString fixture')
        return data[:-2].decode('utf-16le', 'surrogatepass')

    def wide_pointer(self, pointer):
        data = bytearray()
        for index in range(512):
            value = bytes(self.uc.mem_read(pointer + index * 2, 2))
            if value == b'\0\0':
                return data.decode('utf-16le', 'surrogatepass')
            data.extend(value)
        raise ValueError('Wide literal exceeds fixture budget')

    def value_token(self, value):
        pointer = self.allocate(32)
        self.values[pointer] = value
        return pointer

    def shim_return(self, result, kind):
        rsp = self.uc.reg_read(self.x.UC_X86_REG_RSP)
        ret = struct.unpack('<Q', bytes(self.uc.mem_read(rsp, 8)))[0]
        self.uc.reg_write(self.x.UC_X86_REG_RAX, result)
        self.uc.reg_write(self.x.UC_X86_REG_RSP, rsp + 8)
        self.uc.reg_write(self.x.UC_X86_REG_RIP, ret)
        self.calls.append(dict(kind=kind))

    def hook(self, uc, address, size, user):
        x = self.x
        a, b, c, d = [uc.reg_read(r) for r in [x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9]]
        if address == TYPE_MISSING:
            self.type_missing = True
            uc.emu_stop()
            return
        if address == PORT_CALL:
            result = self.crt._wtoi(self.wide_pointer(a))
            uc.reg_write(x.UC_X86_REG_RAX, result & 0xffffffff)
            uc.reg_write(x.UC_X86_REG_RIP, address + 6)
            self.calls.append(dict(kind='actual_system_crt_wtoi', result=result))
            return
        kind, result = None, a
        if address == CTOR:
            self.put_fstring(a, self.wide_pointer(b))
            kind = 'fstring_ctor_shim'
        elif address in (TOP_LOOKUP, LOOKUP):
            if a != self.obj:
                raise ValueError('Unexpected server config context')
            source = struct.unpack('<Q', bytes(uc.mem_read(b, 8)))[0]
            mapping = self.maps[source]
            section = self.get_fstring(c)
            if address == TOP_LOOKUP:
                value = mapping.get(section)
                keys = [section]
            else:
                key = self.get_fstring(d)
                child = mapping.get(section)
                value = child.get(key) if isinstance(child, dict) else None
                keys = [section, key]
            self.lookups.append(dict(keys=keys, source=source, found=value is not None))
            result = self.value_token(value) if value is not None else 0
            kind = 'json_lookup_shim'
        elif address == CONVERT:
            self.put_fstring(b, self.values[a])
            result, kind = b, 'json_to_fstring_shim'
        elif address == FREE:
            if a not in self.fstrings:
                raise ValueError('FString free outside fixture ownership')
            kind = 'fstring_free_capture'
        elif address == ARRAY:
            values = self.values[a]
            if not isinstance(values, list) or len(values) > 16:
                raise ValueError('Server list fixture exceeds local bounds')
            entries = self.allocate(max(16, len(values) * 16))
            for index, value in enumerate(values):
                if not isinstance(value, dict):
                    raise ValueError('Non-object server fixture is unproven')
                map_pointer, holder, node, vtable = [self.allocate(32) for _ in range(4)]
                self.maps[map_pointer] = value
                self.objects[node] = holder
                self.nodes[map_pointer] = index
                uc.mem_write(holder, struct.pack('<QQ', map_pointer, 0))
                uc.mem_write(node, struct.pack('<Q', vtable))
                uc.mem_write(vtable, struct.pack('<Q', OBJECT))
                uc.mem_write(entries + index * 16, struct.pack('<QQ', node, 0))
            result = self.allocate(16)
            uc.mem_write(result, struct.pack('<QII', entries, len(values), len(values)))
            kind = 'json_array_shim'
        elif address == OBJECT:
            result, kind = self.objects[a], 'json_object_virtual_shim'
        elif address == HASH:
            key = self.wide_pointer(b)[:a]
            if key != 'type':
                raise ValueError('Unexpected server item field')
            self.hash_keys.append(key)
            result, kind = 0x12345678, 'json_key_hash_fixture'
        elif address == FIND:
            if b != 0x12345678:
                raise ValueError('Unexpected JSON lookup hash')
            value = self.maps[a].get('type')
            result = 0
            if value is not None:
                token, result = self.value_token(value), self.allocate(32)
                uc.mem_write(result + 0x10, struct.pack('<QQ', token, 0))
            kind = 'json_type_find_shim'
        elif address in (CONCAT_C, CONCAT):
            suffix = self.wide_pointer(c) if address == CONCAT_C else self.get_fstring(c)
            self.put_fstring(a, self.get_fstring(b) + suffix)
            kind = 'diagnostic_concat_shim'
        elif address in (APPEND, COPY_GLOBAL):
            if c > 512:
                raise ValueError('FString append exceeds fixture budget')
            text = bytes(uc.mem_read(b, c * 2)).decode('utf-16le') if c else ''
            if address == COPY_GLOBAL:
                if a != self.global_host:
                    raise ValueError('Unexpected lobby global destination')
                self.global_host_value = text
            else:
                self.put_fstring(a, self.get_fstring(a) + text)
            kind = 'global_host_capture' if address == COPY_GLOBAL else 'diagnostic_append_shim'
        elif address == FORMAT:
            self.put_fstring(a, '')
            kind = 'diagnostic_format_shim'
        if kind:
            self.shim_return(result, kind)
            return
        return super().hook(uc, address, size, user)

    def replay(self):
        # Execute the actual select_server/type lookup and move into config+0x28.
        self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
        for name, value in dict(rsp=self.stack, rbp=self.scratch + 0x18000,
                                rbx=self.obj, r14=self.root_ref, rsi=0).items():
            self.uc.reg_write(getattr(self.x, 'UC_X86_REG_' + name.upper()), value)
        self.uc.emu_start(TYPE_START, TYPE_END, count=32768)
        if self.type_missing:
            return dict(document_fixture=self.document, type_missing=True,
                        lookups=self.lookups, set_server_list_executed=False)
        if self.uc.reg_read(self.x.UC_X86_REG_RIP) != TYPE_END:
            raise ValueError('Type load instruction budget exceeded')
        selected_type = self.get_fstring(self.obj + 0x28)
        self.run(SET_LIST, rcx=self.obj, rdx=self.root_ref)
        success = bool(self.uc.reg_read(self.x.UC_X86_REG_AL))
        selected = next((self.nodes[lookup['source']] for lookup in self.lookups if lookup['keys'] == ['detail', 'lobbyAddress']), None)
        fields = {key: self.get_fstring(self.obj + offset) for key, offset in zip(KEYS, OFFSETS)}
        return dict(document_fixture=self.document, type_missing=False, loaded_type=selected_type,
                    success=success, selected_index=selected, fields=fields,
                    global_host=self.global_host_value,
                    global_port_uint32=struct.unpack('<I', bytes(self.uc.mem_read(self.global_port, 4)))[0],
                    lookups=self.lookups, hash_keys=self.hash_keys, calls=list(self.calls),
                    set_server_list_executed=True, json_and_fstring_helpers_are_shims=True)


def build():
    config = body.head.headers.uri.http.preparation.url.settings.config
    native = config.native
    prior_path = native.ROOT / 'code-clues/headless-cdn-json-flow.json'
    prior = json.loads(prior_path.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('EXE changed')
    image = native.Image(raw)
    addresses = [SET_LIST, 0x14565a5d0, TOP_LOOKUP, LOOKUP]
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in addresses})
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    imports_module = body.head.headers.uri.http.preparation.url.settings.load('server_imports', HERE / 'build-object-zero-init-code.py')
    imported = imports_module.import_at(raw, image, rows[PORT_CALL]['rip_references'][0])
    if imported['name'] != '_wtoi':
        raise ValueError('Lobby port conversion import changed')
    table = CMP + 10 + struct.unpack_from('<i', raw, image.offset(CMP - image.pe.base) + 6)[0]
    anchors = []
    for address, count in [(CMP, 71), (table, 128)]:
        off = image.offset(address - image.pe.base)
        data = raw[off:off + count]
        anchors.append(dict(address=address, file_offset=off, bytes=data.hex(), sha256=hashlib.sha256(data).hexdigest()))
    literals = []
    for f in fragments:
        if f['root_begin_rva'] not in (SET_LIST - image.pe.base, 0x14565a5d0 - image.pe.base):
            continue
        for row in f['instructions']:
            if f['root_begin_rva'] != SET_LIST - image.pe.base and not TYPE_START <= row['address'] < TYPE_END:
                continue
            for address in row['rip_references']:
                literal = config.read_literal(raw, image, address)
                if literal:
                    literals.append(dict(instruction=row['address'], **literal))
    detail = dict(lobbyAddress='lobby.invalid', lobbyPort='12345', patchURL='https://patch.invalid/', dataURL='https://data.invalid/')
    def entry(kind, values=None):
        return dict(type=kind, detail=detail if values is None else values)
    documents = [{}, dict(select_server=dict(type='real')), dict(select_server=dict(type='real'), server_list=[])]
    for wanted, types in [('real', ['dev', 'real']), ('REAL', ['real', 'REAL']), ('real', ['real', 'real']),
                          ('real', ['unreal', 'dev']), ('', ['']), ('real ', ['real', 'real ']),
                          ('réal', ['RÉAL', 'réal']), ('real', [None, 'REAL'])]:
        documents.append(dict(select_server=dict(type=wanted), server_list=[entry(t) if t is not None else {} for t in types]))
    for mask in itertools.product((False, True), repeat=4):
        values = {key: detail[key] for key, present in zip(KEYS, mask) if present}
        documents.append(dict(select_server=dict(type='real'), server_list=[entry('real', values)]))
    for port in ('0', '-1', '65536', '2junk'):
        documents.append(dict(select_server=dict(type='real'), server_list=[entry('real', {**detail, 'lobbyPort': port})]))
    cases = [ServerListEmulator(raw, image, fragments, document).replay() for document in documents]
    crt_path = Path(os.environ['SystemRoot']) / 'System32/ucrtbase.dll'
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                json_flow_report_sha256=hashlib.sha256(prior_path.read_bytes()).hexdigest(),
                fragments=fragments, literals=literals, anchors=anchors, port_import=imported,
                system_crt=dict(path=str(crt_path), sha256=hashlib.sha256(crt_path.read_bytes()).hexdigest()),
                cases=cases, network_ready=False,
                limitations=['Type-load slice and whole SetServerList execute with JSON/FString/diagnostic capture shims.',
                    'Actual ASCII-fold UTF16 comparator, first-match iteration, field moves and port CRT conversion execute.',
                    'JSON type/key conversion, refcount control blocks and FString allocation semantics are fixtures, not whole native JSON.',
                    'Missing endpoint fields preserve synthetic old values; no endpoint validity, config readiness or live server claimed.',
                    'No network, game process, actual CDN payload or account files used.'])


if __name__ == '__main__':
    report = build()
    target = body.head.headers.uri.http.preparation.url.settings.config.native.ROOT / 'code-clues/headless-cdn-server-list.json'
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                          native_cases=len(report['cases'])), indent=2))
