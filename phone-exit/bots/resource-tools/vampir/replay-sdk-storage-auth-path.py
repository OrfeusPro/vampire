"""Native auth-specific storage path gate and Load join with explicit auth fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('auth_path_filename', HERE / 'replay-sdk-storage-filename.py')
filename = importlib.util.module_from_spec(spec)
spec.loader.exec_module(filename)
native, x = filename.native, filename.x


class Replay(filename.Replay):
    def __init__(self, raw, image, base_report, storage_report, extra, compare, fixture):
        super().__init__(raw, image, base_report, storage_report, extra, 'C:/fixture/PersistentDownloadDir')
        self.auth_fixture = fixture
        rows = [r for f in extra if f['root_begin_rva'] == 0x452adc0 for r in f['instructions']]
        self.allowed.update(r['address'] for r in rows)
        self.allowed.add(0x14452c78c)
        cs = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
        leaf = compare['compare_leaf']
        self.allowed.update(i.address for i in cs.disasm(bytes.fromhex(leaf['bytes']), leaf['address']))
        pages = {r['address'] & ~4095 for r in rows}
        pages.update(a & ~4095 for r in rows for a in r['rip_references'])
        pages.update(a & ~4095 for a in (leaf['address'], compare['compare_table']['address'],
                                        0x144520a60, 0x14b4f1ee0))
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()):
                continue
            self.uc.mem_map(page, 4096)
            try:
                offset = image.offset(page - image.pe.base)
            except ValueError:
                continue
            self.uc.mem_write(page, raw[offset:offset + 4096])
        self.string(0x14b4f1a48, 'netmarble')
        self.string(0x14b4f1ee0, 'nid-profile-fixture')
        self.uc.mem_write(0x14b4f13fd, bytes([fixture['prior_post_restore_gate']]))

    def hook(self, uc, address, size, user):
        if address != 0x144520a60:
            return super().hook(uc, address, size, user)
        a, b = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX)]
        self.string(a, self.auth_fixture['auth_type'])
        self.string(b, 'token-fixture' if self.auth_fixture['context_ok'] else '')
        self.events.append(dict(action='auth_context_fixture', returned=self.auth_fixture['context_ok']))
        uc.reg_write(x.UC_X86_REG_RAX, int(self.auth_fixture['context_ok']))
        rsp = uc.reg_read(x.UC_X86_REG_RSP)
        target = struct.unpack('<Q', bytes(uc.mem_read(rsp, 8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(x.UC_X86_REG_RIP, target)

    def capture_auth_path(self):
        # First initialize the two actual constructor filename defaults.
        rbp = self.stack + 0x100
        for register, value in ((x.UC_X86_REG_RSP, self.stack), (x.UC_X86_REG_RBP, rbp),
                                (x.UC_X86_REG_RBX, self.settings), (x.UC_X86_REG_RDI, 0)):
            self.uc.reg_write(register, value)
        self.uc.emu_start(*filename.CTOR, count=1024)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != filename.CTOR[1]:
            raise ValueError('Auth path constructor slice budget exceeded')
        # Unlike previous replay, execute the real Load gate call as well.
        self.uc.reg_write(x.UC_X86_REG_R13, self.settings)
        self.uc.reg_write(x.UC_X86_REG_RDI, 0)
        self.uc.emu_start(0x14452c78c, filename.LOAD[1], count=10000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != filename.LOAD[1]:
            raise ValueError('Auth path Load continuation budget exceeded')
        return dict(fixture=self.auth_fixture, path=self.text(rbp - 0x70),
                    gate_return=bool(self.uc.reg_read(x.UC_X86_REG_R15) & 255),
                    post_restore_gate=int.from_bytes(self.uc.mem_read(0x14b4f13fd, 1), 'little'),
                    events=self.events)


def build():
    root = native.ROOT
    storage_path = root / 'code-clues/headless-sdk-storage.json'
    storage_report = json.loads(storage_path.read_text('utf-8'))
    base_report = json.loads((root / 'code-clues/headless-device-identity.json').read_text('utf-8'))
    prior_filename_path = root / 'code-clues/sdk-storage-filename-replay.json'
    prior_filename = json.loads(prior_filename_path.read_text('utf-8'))
    compare_path = root / 'code-clues/nid-result-primitives.json'
    compare_report = json.loads(compare_path.read_text('utf-8'))
    raw = Path(storage_report['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != storage_report['sha256']:
        raise ValueError('SDK auth path source changed')
    image = native.Image(raw)
    extra = prior_filename['fragments'] + native.decode_ranges(image, {
        image.roots[image.containing(a)] for a in (0x14452adc0, 0x144520a60, 0x14454c7a0, 0x1411b55c0)})
    compare = {k: compare_report['evidence'][k] for k in ('compare_leaf', 'compare_table')}
    for item in compare.values():
        data = bytes.fromhex(item['bytes'])
        if raw[item['file_offset']:item['file_offset'] + len(data)] != data:
            raise ValueError('SDK auth path compare source changed')
    literals = []
    for f in extra:
        for row in f['instructions']:
            if row['mnemonic'] == 'lea':
                for ref in row['rip_references']:
                    if lit := filename.paths.storage.source.config.read_literal(raw, image, ref):
                        literals.append(dict(instruction=row['address'], **lit))
    cases = []
    for auth_type, context_ok in (('netmarble', True), ('NETMARBLE', True), ('other-fixture', True), ('', False)):
        for prior_gate in (0, 1):
            fixture = dict(auth_type=auth_type, context_ok=context_ok, prior_post_restore_gate=prior_gate)
            cases.append(Replay(raw, image, base_report, storage_report, extra, compare, fixture).capture_auth_path())
    rows = {r['address']: r for f in storage_report['fragments'] for r in f['instructions']}
    shared_state_references = [rows[a] for a in (0x14452a383, 0x14453d9af, 0x14453dc9f)]
    if any(r['rip_references'] != [0x14b4f13fd] for r in shared_state_references):
        raise ValueError('SDK shared path/migration state references changed')
    return dict(schema_version=1, source=storage_report['source'], sha256=storage_report['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                storage_report_sha256=hashlib.sha256(storage_path.read_bytes()).hexdigest(),
                filename_report_sha256=hashlib.sha256(prior_filename_path.read_bytes()).hexdigest(),
                fragments=extra, literals=literals, compare=compare, cases=cases,
                shared_state_references=shared_state_references,
                native_execution=True, user_storage_read=False, limitations=[
                    'Native Load auth gate, native ASCII compare and path join execute; logs disabled.',
                    'Auth context extraction and persistent directory are fixtures; no real command line or token read.',
                    'Auth path suffix is a fixture. SetupServiceSettingPath and command-line parser are static evidence only.',
                    'Global 14b4f13fd state is tested before/after calls; actual initialization and reset lifecycle not established.',
                    'No Saved files, registry, identity, credentials or network used.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/sdk-storage-auth-path-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
