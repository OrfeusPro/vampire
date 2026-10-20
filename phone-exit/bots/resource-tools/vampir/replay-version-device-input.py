"""Real Version/Input48 wrapper -> existing native NMDeviceKey getter replay.

Storage/parser/GUID source remain inherited fixtures, never the user's keys.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('version_nm_lifecycle', HERE / 'replay-device-key-lifecycle.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
native = base.guid.source.config.native
WRAPPER, NM = 0x1445c63a0, 0x1444e5ff0


class Replay(base.Replay):
    def __init__(self, raw, image, report, fixture, fragments):
        super().__init__(raw, image, report, fixture)
        rows = [r for f in fragments for r in f['instructions']]
        self.allowed.update(r['address'] for r in rows)
        for page in {p & ~4095 for r in rows for p in (r['address'], *r['rip_references'])}:
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()): continue
            self.uc.mem_map(page, 4096)
            off = image.offset(page - image.pe.base)
            self.uc.mem_write(page, raw[off:off + 4096])

    def nm(self):
        self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
        self.uc.reg_write(base.x.UC_X86_REG_RSP, self.stack)
        self.uc.reg_write(base.x.UC_X86_REG_RCX, self.output)
        self.uc.emu_start(WRAPPER, self.stop, count=10000)
        if self.uc.reg_read(base.x.UC_X86_REG_RIP) != self.stop:
            raise ValueError('Version device wrapper instruction budget')
        if self.uc.reg_read(base.x.UC_X86_REG_RAX) != self.output:
            raise ValueError('Version device descriptor return changed')
        return self.text(self.output)


def build():
    path = native.ROOT / 'code-clues/headless-device-identity.json'
    source = json.loads(path.read_text('utf-8'))
    raw = Path(source['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != source['sha256']: raise ValueError('Device source changed')
    image = native.Image(raw)
    wrapper = native.decode_ranges(image, {image.roots[image.containing(WRAPPER)]})
    if [r['direct_target'] for f in wrapper for r in f['instructions'] if r['mnemonic'] == 'call'] != [NM]:
        raise ValueError('Version device source call changed')
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in (0x1467a9cd0, 0x1467a9700)})
    # Pin both getter invocation and immediate destination assignment, rather
    # than infer packet offsets from two similar getter names.
    bindings = []
    for function in fragments:
        rows = function['instructions']
        for index, row in enumerate(rows):
            if row.get('direct_target') == WRAPPER:
                bindings.append(dict(root=hex(image.pe.base + function['root_begin_rva']),
                                     instructions=rows[max(0, index - 2):index + 5]))
    if len(bindings) != 2: raise ValueError('Expected Version and Login device getter callsites')
    profiles = [dict(cache='cached-nm-fixture'),
                dict(stored='stored-nm-fixture', parse_ok=True),
                dict(stored='', parse_ok=False),
                dict(stored='invalid-fixture', parse_ok=False, write_ok=False)]
    cases = []
    for fixture in profiles:
        em = Replay(raw, image, source, fixture, wrapper)
        first = em.nm()
        events = em.events.copy()
        again = em.nm()
        if first != again or em.events != events: raise ValueError('NM cache reuse changed')
        cases.append(dict(fixture=fixture, value=first, repeated=again, events=events))
    return dict(source=source['source'], sha256=source['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                dependency_sha256=hashlib.sha256((HERE / 'replay-device-key-lifecycle.py').read_bytes()).hexdigest(),
                upstream_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                wrapper=wrapper, callsite_bindings=bindings, cases=cases,
                native_execution=True, network_ready=False,
                limitations=['Actual wrapper and NM getter; inherited storage/parser/GUID fixtures.',
                             'Version+0x48 and Login+0x78 callsites are static; whole packet preparation is not rerun here.',
                             'No user registry values or account linkage in replay.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/version-device-input-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
