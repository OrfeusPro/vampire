"""Execute the full lobby success handler with native Windows platform gate.

Synthetic strings, service state and connection capture; no network or game launch.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('lobby_windows_platform', HERE / 'replay-version-platform-context.py')
platform = importlib.util.module_from_spec(spec)
spec.loader.exec_module(platform)
native, x = platform.native, platform.x
HANDLER, GATE = 0x14677ec50, 0x1445cb650
CONNECT = 0x144aaa9c0


class Replay(platform.Replay):
    def __init__(self, raw, image, source, fragments, members, fixture):
        super().__init__(raw, image, source, fragments, members, fixture['scoped'])
        self.case = fixture
        self.packet, self.game, self.owner, self.service, self.state = [self.allocate(n) for n in (0x80, 0x200, 0x100, 0x100, 0x100)]
        self.uc.mem_write(self.state + 0x38, b'\x01')
        self.strings = ['' if fixture['empty'] else 'lobby-fixture-' + str(n) for n in range(5)]
        for offset, value in zip((0x20, 0x30, 0x40, 0x50, 0x60), self.strings):
            self.string(self.packet + offset, value)
        hooks = (0x14142d840, 0x141424430, 0x145d37220, 0x144aaa9d0,
                 0x14143c260, 0x145c859f0, 0x145a2f050, 0x145a3f410,
                 0x145a4b8d0, CONNECT, 0x141435320, 0x1443fcdf0)
        for page in {a & ~4095 for a in hooks}:
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()): continue
            self.uc.mem_map(page, 4096)
            offset = image.offset(page - image.pe.base)
            self.uc.mem_write(page, raw[offset:offset + 4096])
        self.captures = []

    def hook(self, uc, address, size, user):
        if address in self.allowed: return
        a, b = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX)]
        result = 0
        if address == 0x14142d840:
            uc.mem_write(a, bytes(16)); result = a  # Diagnostic formatting only.
        elif address == 0x141424430: pass
        elif address == 0x145d37220: result = self.state
        elif address == 0x144aaa9d0: result = self.game
        elif address == 0x14143c260:
            self.string(a, self.text(b)); result = a
        elif address == 0x145c859f0: result = self.owner
        elif address == 0x145a2f050: result = self.service
        elif address == 0x145a3f410:
            if a != self.service: raise ValueError('Service predicate owner changed')
            result = int(self.case['service_ready'])
        elif address == 0x145a4b8d0:
            if (a, b) != (self.service, 0): raise ValueError('Service call arguments changed')
            self.captures.append('service_state_false')
        elif address == CONNECT:
            if a != self.game: raise ValueError('Game continuation owner changed')
            self.captures.append('connect_game')
        elif address == 0x141435320:
            uc.mem_write(a, bytes(0x90))  # Diagnostic UTF-8 conversion only.
        elif address == 0x1443fcdf0: pass
        else: return super().hook(uc, address, size, user)
        stack = uc.reg_read(x.UC_X86_REG_RSP)
        uc.reg_write(x.UC_X86_REG_RAX, result)
        uc.reg_write(x.UC_X86_REG_RIP, int.from_bytes(uc.mem_read(stack, 8), 'little'))
        uc.reg_write(x.UC_X86_REG_RSP, stack + 8)

    def capture(self):
        selector, gate = self.call(platform.SELECTOR), self.call(GATE) & 255
        if (selector, gate) != (3, 0): raise ValueError('Windows continuation gate changed')
        self.call(HANDLER, 0, 0, self.packet)
        actual = [self.text(self.game + offset) for offset in (0xf0, 0xe0)]
        if actual != self.strings[:2] or self.text(self.owner + 0x28) != self.strings[0]:
            raise ValueError('Lobby success string handoff changed')
        expected = ([] if self.case['service_ready'] else ['service_state_false']) + ['connect_game']
        if self.captures != expected: raise ValueError('Windows continuation order changed')
        if bytes(self.uc.mem_read(self.state + 0x38, 1)) != b'\0': raise ValueError('Lobby pending state not cleared')
        return dict(fixture=self.case, selector=selector, external_gate=gate,
                    game_strings=actual, captures=self.captures, pending_cleared=True)


def build():
    root = native.ROOT / 'code-clues'
    paths = [root / name for name in ('headless-device-identity.json', 'version-platform-context-replay.json')]
    source, prior = [json.loads(p.read_text('utf-8')) for p in paths]
    raw = Path(source['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != source['sha256']: raise ValueError('Client changed')
    image = native.Image(raw)
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in (HANDLER, GATE)})
    cases = [Replay(raw, image, source, prior['fragments'] + fragments, prior['members'],
                    dict(scoped=scoped, service_ready=ready, empty=empty)).capture()
             for scoped in (False, True) for ready in (False, True) for empty in (False, True)]
    return dict(source=source['source'], source_sha256=source['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                platform_tool_sha256=hashlib.sha256((HERE / 'replay-version-platform-context.py').read_bytes()).hexdigest(),
                upstream_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
                fragments=fragments, cases=cases,
                limitations=['Complete success handler entry/return, native platform selector and external gate execute.',
                             'UEnum object/name pool and string helpers reuse explicit platform fixtures.',
                             'Service predicate/state transition and connection are captures, not executed backends.',
                             'No server, account, SDK playerStatus or complete application lifecycle; failure branches excluded.',
                             'Does not establish the cause of LoginResult InvalidState or the live lobby kind.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/lobby-windows-continuation-replay.json'
    path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
