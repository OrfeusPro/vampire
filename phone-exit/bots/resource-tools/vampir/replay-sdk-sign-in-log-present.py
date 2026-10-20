"""Native SendSignIn with present service; capture event before log transport."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('signin_present_base', HERE / 'replay-sdk-sign-in-log.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
native, x = base.native, base.x
REGISTRY_LOOKUP = 0x30020000


class Replay(base.Replay):
    def __init__(self, raw, image, source, platform, fragments, leaves, channel):
        super().__init__(raw, image, source, platform, fragments, leaves)
        self.service, self.common_owner = self.allocate(0x400), self.allocate(0x100)
        self.game_settings, self.channel_settings = self.allocate(0x120), self.allocate(0x120)
        self.game_data, self.channel_data = self.allocate(0x100), self.allocate(0x100)
        self.uc.mem_write(self.service + 0x310, struct.pack('<Q', self.common_owner))
        self.uc.mem_write(self.game_settings + 0x110, struct.pack('<Q', self.game_data))
        self.uc.mem_write(self.channel_settings + 0x110, struct.pack('<Q', self.channel_data))
        self.string(self.game_data + 0x38, 'fixture-game-code')
        self.uc.mem_write(self.channel_data + 0x88, bytes([channel]))
        self.channel = channel
        self.variants, self.event_maps, self.sent = {}, {}, []
        self.registry = self.allocate(0x100)
        self.registry_vtable = self.allocate(0x100)
        self.uc.mem_write(self.registry, struct.pack('<Q', self.registry_vtable))
        self.uc.mem_write(self.registry_vtable + 0xb8, struct.pack('<Q', REGISTRY_LOOKUP))
        self.uc.mem_write(0x14b248fd0, struct.pack('<Q', self.registry))
        hooks = (0x1444ab740, 0x1444aab90, 0x14446eed0, 0x14446eff0,
                 0x1444bbb30, 0x14446d890, 0x144546880, 0x144512b40,
                 0x141420f70, REGISTRY_LOOKUP)
        for page in {p & ~4095 for a in hooks for p in (a, a + 64)}:
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()):
                continue
            self.uc.mem_map(page, 4096)
            try:
                offset = image.offset(page - image.pe.base)
            except ValueError:
                continue
            self.uc.mem_write(page, raw[offset:offset+4096])

    def hook(self, uc, address, size, user):
        if address in self.allowed:
            return super().hook(uc, address, size, user)
        a, b, c, d = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        result = 0
        if address == 0x144523ff0:
            if a != self.expected_impl:
                raise ValueError('Wrong platform log impl')
            uc.mem_write(b, struct.pack('<QQ', self.service, 0))
            result = b
            self.events.append('weak_service_getter_present_fixture')
        elif address == 0x14451fd40:
            if b != self.service:
                raise ValueError('Wrong service fixture')
            handle = self.allocate(8)
            uc.mem_write(handle, struct.pack('<Q', self.service))
            uc.mem_write(a, struct.pack('<QQ', handle, 0))
            result = a
            self.events.append('weak_service_lock_present_fixture')
        elif address == 0x1444ab740:
            result = self.game_settings
        elif address == 0x1444aab90:
            result = self.channel_settings
        elif address == 0x141420f70:
            self.string(a, self.literal(b, 1))
            result = a
        elif address == 0x14446eed0:
            self.variants[a] = dict(kind='string_fixture', value=self.text(b))
            uc.mem_write(a, bytes(16))
            result = a
        elif address == 0x14446eff0:
            self.variants[a] = dict(kind='raw_constructor_argument', value=b)
            uc.mem_write(a, bytes(16))
            result = a
        elif address == 0x1444bbb30:
            pointer, end = struct.unpack('<QQ', bytes(uc.mem_read(b, 16)))
            count = (end - pointer) // 16
            if end - pointer != 32:
                raise ValueError('Unexpected SignIn event pair span')
            if count != 2:
                raise ValueError('Unexpected SignIn event pair count: ' + str(count))
            pairs = []
            for i in range(count):
                key, value = struct.unpack('<QQ', bytes(uc.mem_read(pointer + i * 16, 16)))
                pairs.append(dict(key=self.text(key), variant=self.variants[value]))
            self.event_maps[a] = pairs
            uc.mem_write(a, bytes(64))
            result = a
        elif address == 0x14446d890:
            self.event_maps[a] = self.event_maps[b]
            uc.mem_write(a, bytes(64))
            result = a
        elif address == 0x144546880:
            if a != self.common_owner:
                raise ValueError('Wrong event sink owner')
            self.sent.append(dict(raw_mode=b, raw_event=c, pairs=self.event_maps[d]))
        elif address == 0x144512b40:
            pass
        elif address == REGISTRY_LOOKUP:
            if a != self.registry or self.literal(b, 2) != 'NMSDK.PlatformType' or c != 1:
                raise ValueError('Unexpected console-variable lookup')
            self.events.append('platform_type_absent_fixture')
        else:
            return super().hook(uc, address, size, user)
        stack = uc.reg_read(x.UC_X86_REG_RSP)
        uc.reg_write(x.UC_X86_REG_RAX, result)
        uc.reg_write(x.UC_X86_REG_RIP, int.from_bytes(uc.mem_read(stack, 8), 'little'))
        uc.reg_write(x.UC_X86_REG_RSP, stack + 8)

    def capture(self):
        owner, wrapper, impl = self.allocate(0xf0), self.allocate(16), self.allocate(0x100)
        self.uc.mem_write(owner + 0x88, struct.pack('<Q', impl))
        self.uc.mem_write(wrapper, struct.pack('<Q', owner))
        self.expected_impl = impl
        self.call(base.THUNK, self.call(base.GET, wrapper))
        expected = [dict(raw_mode=1, raw_event=2, pairs=[
            dict(key='GameCode', variant=dict(kind='string_fixture', value='fixture-game-code')),
            dict(key='ChannelCode', variant=dict(kind='raw_constructor_argument', value=self.channel))])]
        if self.sent != expected:
            raise ValueError('SignIn event contents changed: ' + repr(self.sent))
        return dict(channel_fixture=self.channel, sent=self.sent, events=self.events,
                    optional_platform_type_available=False)


def build():
    root = native.ROOT / 'code-clues'
    source = json.loads((root / 'headless-device-identity.json').read_text('utf-8'))
    platform = json.loads((root / 'version-platform-context-replay.json').read_text('utf-8'))
    manifest = json.loads((native.ROOT / 'ghidra/entry-manifest.json').read_text('utf-8'))
    raw = Path(source['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != source['sha256']:
        raise ValueError('Client changed')
    image = native.Image(raw)
    fragments = native.decode_ranges(image, {image.roots[image.containing(base.SEND)]})
    sink_fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in (0x144546880, 0x144547040)})
    sink_names = []
    for address in (0x1494eac80, 0x1494ead68, 0x1494ead70, 0x1494ead80, 0x1494ead88):
        literal = base.config.read_literal(raw, image, address)
        refs = [r for f in sink_fragments for r in f['instructions'] if address in r['rip_references']]
        if literal is None or not refs:
            raise ValueError('Sink diagnostic or key reference missing')
        sink_names.append(dict(literal=literal, references=refs))
    sink_calls = [r for f in sink_fragments for r in f['instructions']
                  if r.get('direct_target') in (0x14450e580, 0x144551060)]
    if len(sink_calls) != 4:
        raise ValueError('Common data copy/write call count changed')
    leaves = [r for f in manifest['functions'] if int(f['address'], 16) == base.GET for r in f['ranges']]
    if len(leaves) != 1:
        raise ValueError('Reviewed platform log getter missing')
    return dict(source=source['source'], source_sha256=source['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                dependency_sha256=hashlib.sha256((HERE / 'replay-sdk-sign-in-log.py').read_bytes()).hexdigest(),
                fragments=fragments, leaves=leaves, sink_fragments=sink_fragments,
                sink_names=sink_names, sink_common_data_calls=sink_calls,
                cases=[Replay(raw, image, source, platform, fragments, leaves, channel).capture() for channel in (0, 20, 33, 255)],
                limitations=['Whole native SendSignIn executes with present service and absent optional PlatformType.',
                             'Weak refs, settings getters, variant/map backends and event sink are fixtures.',
                             'ChannelCode variant constructor type is not inferred from raw argument.',
                             'Event sink is captured; common-data population, final log transport, live auth and network are not executed.'])


if __name__ == '__main__':
    report = build()
    target = native.ROOT / 'code-clues/sdk-sign-in-log-present-replay.json'
    target.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest(), cases=report['cases'])))
