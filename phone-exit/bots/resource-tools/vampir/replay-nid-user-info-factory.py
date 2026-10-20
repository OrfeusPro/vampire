"""Execute owner factory, real owner constructor and real UserInfo getters."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('nid_factory_owner', HERE / 'replay-nid-user-info-owner.py')
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)
native, x = owner.native, owner.x
CREATE = 0x14450f420
HOST, BIND, AFTER_BIND = 0x144510fd0, 0x14451115b, 0x144511167


class Replay(owner.Replay):
    def hook(self, uc, address, size, user):
        a, b, c = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        if address == owner.CONSTRUCT:
            self.owner = a
        if address == 0x1468e4100 and a == 0xf0:
            result = self.allocate(a)
            uc.mem_write(result, bytes([self.fill]) * a)
            self.allocations.append(dict(pointer=result, size=a))
        elif address == 0x1487a2e25 and c == 0xf0:
            if b != 0:
                raise ValueError('Unexpected owner factory memset fill')
            uc.mem_write(a, bytes(c))
            result = a
        else:
            return super().hook(uc, address, size, user)
        stack = uc.reg_read(x.UC_X86_REG_RSP)
        uc.reg_write(x.UC_X86_REG_RAX, result)
        uc.reg_write(x.UC_X86_REG_RIP, int.from_bytes(uc.mem_read(stack, 8), 'little'))
        uc.reg_write(x.UC_X86_REG_RSP, stack + 8)

    def capture(self):
        bridge, handle = self.allocate(0x500), self.allocate(8)
        pair = bridge + 0x310
        self.uc.mem_write(pair, bytes([self.fill]) * 16)
        self.uc.reg_write(x.UC_X86_REG_RDI, bridge)
        self.uc.reg_write(x.UC_X86_REG_RSP, self.stack)
        self.uc.emu_start(BIND, AFTER_BIND, count=10000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != AFTER_BIND:
            raise ValueError('Host callsite instruction budget')
        if self.uc.reg_read(x.UC_X86_REG_RAX) != pair:
            raise ValueError('Owner factory return changed')
        created, control = struct.unpack('<QQ', bytes(self.uc.mem_read(pair, 16)))
        if created != self.owner or created != self.allocations[0]['pointer']:
            raise ValueError('Owner factory did not return the constructed owner')
        if control != self.allocations[-1]['pointer']:
            raise ValueError('Owner factory control block changed')
        if struct.unpack('<QQ', bytes(self.uc.mem_read(created + 0x10, 16))) != (created, control):
            raise ValueError('Owner shared-self linkage changed')
        vtable, first_count, second_count, payload = struct.unpack('<QIIQ', bytes(self.uc.mem_read(control, 24)))
        if vtable != 0x1489a4e48 or payload != created or (first_count, second_count) != (1, 2):
            raise ValueError('Owner factory control block contents changed')
        inner = int.from_bytes(self.uc.mem_read(created + 0x28, 8), 'little')
        self.uc.mem_write(handle, struct.pack('<Q', bridge))
        wrapper = self.call(owner.SETTINGS, handle)
        info = self.call(owner.GET, wrapper)
        if wrapper != bridge + 0x310 or info != inner + 0x28:
            raise ValueError('Factory -> actual getters link changed')
        if bytes(self.uc.mem_read(info, 0x250)) != bytes(0x250):
            raise ValueError('Factory unexpectedly populated common log fields')
        return dict(fill=self.fill, owner_size=0xf0, descriptor_count=37,
                    user_info_empty=True, shared_self_linked=True,
                    native_host_callsite=True, bridge_owner_offset='0x310',
                    control_vtable=hex(vtable), control_counters=[first_count, second_count],
                    allocation_sizes=[a['size'] for a in self.allocations], captures=self.events)


def build():
    root = native.ROOT / 'code-clues'
    source = json.loads((root / 'headless-device-identity.json').read_text('utf-8'))
    platform = json.loads((root / 'version-platform-context-replay.json').read_text('utf-8'))
    manifest = json.loads((native.ROOT / 'ghidra/entry-manifest.json').read_text('utf-8'))
    raw = Path(source['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != source['sha256']:
        raise ValueError('Client changed')
    image = native.Image(raw)
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in (CREATE, owner.CONSTRUCT, HOST)})
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    if (rows[BIND]['mnemonic'], rows[BIND]['operands']) != ('lea', 'rcx, [rdi + 0x310]'):
        raise ValueError('Host owner slot setup changed')
    if rows[BIND + 7]['direct_target'] != CREATE:
        raise ValueError('Host owner factory target changed')
    leaves = [r for f in manifest['functions'] if int(f['address'], 16) in (owner.ZERO, owner.GET, owner.SETTINGS) for r in f['ranges']]
    if len(leaves) != 3:
        raise ValueError('Reviewed owner/getter leaves missing')
    return dict(source=source['source'], source_sha256=source['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                owner_replay_sha256=hashlib.sha256((HERE / 'replay-nid-user-info-owner.py').read_bytes()).hexdigest(),
                fragments=fragments, leaves=leaves,
                cases=[Replay(raw, image, source, platform, fragments, leaves, fill).capture() for fill in (0, 0x55, 0xff)],
                limitations=['Native host callsite and whole factory, owner constructor, zeroing constructor and both actual getters execute.',
                             'Allocation, memset, pointer transfer, unrelated owner containers and lock initialization are fixtures.',
                             'Host storage/register at the callsite is a fixture; the remaining host constructor and field population are not executed.',
                             'Only successful allocations; no live process, credentials, device storage or network.'])


if __name__ == '__main__':
    report = build()
    target = native.ROOT / 'code-clues/nid-user-info-factory-replay.json'
    target.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest(), cases=report['cases'])))
