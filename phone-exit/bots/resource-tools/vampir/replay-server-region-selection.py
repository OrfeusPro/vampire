"""Native region enum initialization and master-list region gate; no network."""
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('region_ping', HERE / 'build-headless-ping-codec.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
native, unicorn, x = base.native, base.unicorn, base.x
CTOR, BUILD, GETTER = 0x141420f70, 0x14450d970, 0x145564550
FILTER, ACCEPT, REJECT = 0x145d4b56a, 0x145d4b585, 0x145d4b82d


class Machine:
    def __init__(self, raw, image, fragments):
        self.raw, self.image = raw, image
        self.uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        self.allowed = {r['address'] for f in fragments for r in f['instructions']}
        pages = {a & ~4095 for f in fragments for r in f['instructions']
            for a in (r['address'], *r['rip_references'])}
        pages.update(a & ~4095 for a in (CTOR, BUILD, GETTER, ACCEPT, REJECT))
        for page in sorted(pages):
            self.uc.mem_map(page, 4096)
            try: off = image.offset(page - image.pe.base)
            except ValueError: continue
            self.uc.mem_write(page, raw[off:off + 4096])
        for address in (CTOR, BUILD): self.uc.mem_write(address, b'\xc3')
        self.uc.mem_map(0x20000000, 0x30000)
        self.stack, self.heap = 0x20010000, 0x20020000
        self.uc.reg_write(x.UC_X86_REG_RSP, self.stack)
        self.uc.reg_write(x.UC_X86_REG_RBP, self.stack + 0xa9)
        self.uc.reg_write(x.UC_X86_REG_RDI, 0)
        self.members, self.literals, self.stopped = None, [], None
        self.uc.hook_add(unicorn.UC_HOOK_CODE, self.hook)

    def hook(self, uc, address, size, user):
        if address in (ACCEPT, REJECT):
            self.stopped = 'accepted' if address == ACCEPT else 'rejected'
            uc.emu_stop()
            return
        if address == BUILD:
            begin, end = struct.unpack('<QQ', bytes(uc.mem_read(uc.reg_read(x.UC_X86_REG_RDX), 16)))
            if not 0 <= end - begin <= 128 or (end - begin) % 16: raise ValueError('Enum initializer bounds')
            members = {}
            for p in range(begin, end, 16):
                desc, number = struct.unpack('<QQ', bytes(uc.mem_read(p, 16)))
                text_ptr, n, cap = struct.unpack('<QII', bytes(uc.mem_read(desc, 16)))
                if not 1 <= n <= cap <= 64: raise ValueError('Enum string bound')
                name = bytes(uc.mem_read(text_ptr, n * 2))[:-2].decode('utf-16le')
                if name in members: raise ValueError('Duplicate enum key')
                members[name] = int.from_bytes(uc.mem_read(number, 4), 'little')
            self.members = members
            uc.emu_stop()
            return
        if address == CTOR:
            desc, pointer = (uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX))
            off = self.image.offset(pointer - self.image.pe.base)
            end = self.raw.index(b'\0', off, off + 64)
            data = self.raw[off:end + 1]
            text = data[:-1].decode('ascii')
            encoded = (text + '\0').encode('utf-16le')
            uc.mem_write(self.heap, encoded)
            uc.mem_write(desc, struct.pack('<QII', self.heap, len(encoded) // 2, len(encoded) // 2))
            self.heap += 128
            self.literals.append(dict(address=pointer, file_offset=off, bytes=data.hex(), text=text))
            rsp = uc.reg_read(x.UC_X86_REG_RSP)
            target = int.from_bytes(uc.mem_read(rsp, 8), 'little')
            uc.reg_write(x.UC_X86_REG_RAX, desc)
            uc.reg_write(x.UC_X86_REG_RSP, rsp + 8)
            uc.reg_write(x.UC_X86_REG_RIP, target)
            return
        if address not in self.allowed: raise ValueError('Unexpected region instruction ' + hex(address))


def build():
    manifest = json.loads((native.ROOT / 'ghidra/entry-manifest.json').read_text('utf-8'))
    raw = Path(manifest['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest['source_sha256']: raise ValueError('Client changed')
    image = native.Image(raw)
    enum_fragments = native.decode_ranges(image, {image.roots[image.containing(0x1457c7780)]})
    rows = [r for f in enum_fragments for r in f['instructions']]
    first = next(i for i, r in enumerate(rows) if r.get('direct_target') == CTOR)
    start = rows[first - 2]['address']
    if 0x1499040fc not in rows[first - 2]['rip_references']: raise ValueError('ASIA enum entry source changed')
    machine = Machine(raw, image, enum_fragments)
    machine.uc.emu_start(start, BUILD, count=4096)
    # Unicorn's end boundary stops before the hook at BUILD; execute it explicitly.
    machine.hook(machine.uc, BUILD, 1, None)
    if machine.members != {'ASIA': 2, 'Common': 0, 'JP': 4, 'KR': 1, 'TW': 3}:
        raise ValueError('Server region enum differs from independent expected model: ' + str(machine.members))
    filter_data = raw[image.offset(FILTER - image.pe.base):image.offset(ACCEPT - image.pe.base)]
    cs = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    cs.detail = True
    fragments = []
    for address, data in ((FILTER, filter_data), (GETTER, raw[image.offset(GETTER - image.pe.base):image.offset(GETTER - image.pe.base) + 8])):
        decoded = []
        for i in cs.disasm(data, address):
            refs = [i.address + i.size + op.mem.disp for op in i.operands if op.type == native.capstone.x86_const.X86_OP_MEM and op.mem.base == native.capstone.x86_const.X86_REG_RIP]
            decoded.append(dict(address=i.address, bytes=i.bytes.hex(), mnemonic=i.mnemonic, operands=i.op_str, rip_references=refs))
        if sum(len(bytes.fromhex(r['bytes'])) for r in decoded) != len(data): raise ValueError('Region gate decode incomplete')
        fragments.append(dict(address=address, bytes=data.hex(), sha256=hashlib.sha256(data).hexdigest(), instructions=decoded))
    singleton = fragments[1]['instructions'][0]['rip_references'][0]
    cases = []
    for selected in range(1, 5):
        for group in range(1, 5):
            for enabled in (0, 1):
                m = Machine(raw, image, fragments)
                policy, group_obj = 0x20001000, 0x20002000
                m.uc.mem_write(singleton, struct.pack('<Q', policy))
                m.uc.mem_write(policy + 0xa8, struct.pack('<I', selected))
                m.uc.mem_write(group_obj + 0x20, struct.pack('<I', group))
                m.uc.mem_write(m.stack + 0x30, bytes([enabled]))
                m.uc.reg_write(x.UC_X86_REG_RBX, group_obj)
                m.uc.emu_start(FILTER, 0x2002f000, count=64)
                expected = 'accepted' if not enabled or selected == group else 'rejected'
                if m.stopped != expected: raise ValueError('Native region gate mismatch')
                cases.append(dict(selected=selected, group=group, enabled=enabled, result=m.stopped))
    tables = []
    for filename, index_name in (('ProjectRED-Windows-6196.csv', 'index.json'), ('pakchunk1-Windows-1493.csv', 'index-pakchunk1-Windows.json'), ('ProjectRED-Windows-6105.csv', 'index.json')):
        index = native.ROOT / 'table-study' / index_name
        record = next(t for t in json.loads(index.read_text('utf-8'))['tables'] if t['file'] == filename)
        data = (index.parent / filename).read_bytes()
        if hashlib.sha256(data).hexdigest() != record['sha256']: raise ValueError('Region table changed')
        tables.append(dict(provenance=record, rows=list(csv.DictReader(io.StringIO(data.decode('utf-8-sig'))))))
    return dict(source=manifest['source'], source_sha256=manifest['source_sha256'], tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        enum_initializer=dict(start=hex(start), end=hex(BUILD), members=machine.members, literals=machine.literals, fragments=enum_fragments),
        filter_fragments=fragments, filter_cases=cases, tables=tables,
        limitations=['Actual enum initializer branch before map builder; FString and map construction captured.',
            'TLS guard/prologue and hash lookup not executed; RBP relation and zero RDI are explicit source-bound fixtures.',
            'Actual master-list region compare and singleton getter; group/policy/flag objects are fixtures.',
            'Group lookup and full master Update excluded; CSV joins do not prove SDK country selection lifecycle.',
            'No game launch, credentials, process memory or network.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/server-region-selection-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), members=report['enum_initializer']['members'], cases=len(report['filter_cases']))))
