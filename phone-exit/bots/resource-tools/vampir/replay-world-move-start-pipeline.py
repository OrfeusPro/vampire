"""Actual ID204 reader -> handler -> service branches -> guarded ID205.

The dispatcher invocation and engine/UI predicates are explicit fixtures.
No level is loaded and the send boundary captures a packet before socket I/O.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


base = module('start_pipeline_send', 'replay-world-move-finish-send.py')
reader = module('start_pipeline_reader', 'replay-world-move-start-reader.py')
native, x = base.native, base.x
HANDLER, RECEIVE = 0x1467a61a0, 0x145dbf720
OTHER = 0x3000f0c0


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        support = reader.Emulator()
        self.reader_ranges = support.start_ranges
        self.reader_constructor = support.constructor
        self.ranges.extend(support.ranges)
        for lo, hi in support.ranges:
            for page in range(lo & ~4095, (hi + 4095) & ~4095, 4096):
                self.map_source_page(page)
        manifest = json.loads((native.ROOT / 'ghidra/entry-manifest.json').read_text('utf-8'))
        names = {'WorldMoveStartResult_Handler', 'WorldMoveStartResult_Receive'}
        self.pipeline_ranges = [r for f in manifest['functions'] if f['name'] in names for r in f['ranges']]
        for r in self.pipeline_ranges:
            lo, hi = int(r['start'], 16), int(r['end_exclusive'], 16)
            if hashlib.sha256(self.raw[r['file_offset']:r['file_offset'] + hi - lo]).hexdigest() != r['sha256']:
                raise ValueError('Start handler/service source changed')
            self.ranges.append((lo, hi))
            for page in range(lo & ~4095, (hi + 4095) & ~4095, 4096):
                self.map_source_page(page)
        self.binding = support.binding
        getter = self.binding['id_getter']
        self.ranges.append((getter, getter + 6))
        self.map_source_page(getter & ~4095)
        off = self.image.offset(0x1499f11f0 - self.image.pe.base)
        self.service_table = self.raw[off:off + 0xd0]
        self.service30, self.predicate = [struct.unpack_from('<Q', self.service_table, n)[0] for n in (0x30, 0xa8)]
        if struct.unpack_from('<Q', self.service_table, 0x70)[0] != base.REQUEST:
            raise ValueError('Start finish-request dispatch changed')
        self.start_hooks = {0x14563d960, 0x1423051f0, 0x1454894b0, self.predicate,
                            0x144aaaab0, self.service30, 0x1456907a0, 0x145508e00,
                            0x145604890, OTHER, 0x145decbc0, 0x14560a400,
                            0x145da8510, 0x1466fa250, 0x14550e2e0}
        for address in self.start_hooks:
            self.map_source_page(address & ~4095)

    def hook(self, uc, address, size, user):
        if self.handler_phase and address in (HANDLER, RECEIVE):
            self.events.append(dict(action='native_start_handler' if address == HANDLER else 'native_start_receive'))
        if self.handler_phase and address in self.start_hooks:
            a, b, c, d = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX,
                                                  x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
            ctx = self.context
            result = 0
            if address == 0x14563d960:
                result = ctx + 0x18000
            elif address == 0x14550e2e0:
                result = ctx + 0x1a000
            elif address == 0x1423051f0:
                self.events.append(dict(action='old_world_config_capture', raw_world=b & 0xffffffff))
            elif address == self.predicate:
                result = int(self.load_world)
                self.events.append(dict(action='load_predicate_capture', result=result))
            elif address == 0x144aaaab0:
                result = int(self.alternate)
                self.events.append(dict(action='transport_predicate_capture', result=result))
            elif address == self.service30:
                if a != ctx + 0x5000:
                    raise ValueError('Service preparation receiver')
                self.events.append(dict(action='service_prepare_capture', actor=b, reason=c & 255, flag=d & 255))
            elif address == 0x1456907a0:
                result = 0
                self.events.append(dict(action='reuse_condition_capture', raw=a, result=result))
            elif address == 0x145508e00:
                if b != 1:
                    raise ValueError('World enable capture argument')
                self.events.append(dict(action='world_enable_capture'))
            elif address == 0x145604890:
                result = ctx + 0x19000
            elif address == OTHER:
                self.events.append(dict(action='other_service_capture', world=b & 0xffffffff, kind=c & 255))
            elif address == 0x145decbc0:
                self.events.append(dict(action='load_label_prepare_capture', target=a & 0xffffffff))
            elif address == 0x14560a400:
                if a != ctx + 0x5000:
                    raise ValueError('Load state receiver')
                self.events.append(dict(action='load_state_capture', target=b & 0xffffffff))
            elif address == 0x145da8510:
                if int.from_bytes(uc.mem_read(a, 8), 'little') != ctx + 0x5000:
                    raise ValueError('Deferred load callback service pointer')
                self.events.append(dict(action='load_callback_capture'))
            elif address == 0x1466fa250:
                self.events.append(dict(action='start_error_ui_capture'))
            self.finish(result)
            return
        return super().hook(uc, address, size, user)

    def execute_pipeline(self, *, code=0, gate_state=0, status=1, current_world=37,
                         target_world=41, old_kind=0, new_kind=0, flag=0,
                         load_world=False, alternate=False, reason=24):
        self.load_world, self.alternate = load_world, alternate
        self.handler_phase = False
        body = struct.pack('<IIfffBBQ', code, target_world, 1.5, -2.25, -0., new_kind, flag, 0xfedcba9876543210)
        decoded = reader.Emulator.read_start(self, body)
        if decoded['returned'] != 1:
            raise ValueError('Complete start result required')
        self.setup_consumer(status)
        ctx = self.context
        self.uc.mem_write(ctx + 0x5000, struct.pack('<Q', ctx + 0x5800))
        self.uc.mem_write(ctx + 0x5800, self.service_table)
        self.uc.mem_write(ctx + 0x58c8, struct.pack('<Q', base.LABEL))
        self.uc.mem_write(ctx + 0x5040, struct.pack('<II', current_world, 0x12345678))
        self.uc.mem_write(ctx + 0x5058, bytes([old_kind]))
        self.uc.mem_write(ctx + 0x50f0, bytes([reason]))
        self.uc.mem_write(ctx + 0x14000, struct.pack('<Q', ctx + 0x14800))
        self.uc.mem_write(ctx + 0x14838, struct.pack('<Q', base.CAPTURE))
        self.uc.mem_write(ctx + 0x19000, struct.pack('<Q', ctx + 0x19800))
        self.uc.mem_write(ctx + 0x19860, struct.pack('<Q', OTHER))
        self.uc.mem_write(ctx + 0x4008, bytes([gate_state]))
        self.uc.mem_write(0x14b520cc3, b'\0')
        self.events, self.gate_return = [], None
        stack, stop = self.scratch + 0x30000, self.scratch + 0x3f000
        self.uc.mem_write(stack, struct.pack('<Q', stop))
        for register, value in ((x.UC_X86_REG_RSP, stack), (x.UC_X86_REG_RCX, ctx),
                                 (x.UC_X86_REG_RDX, 0x12345678), (x.UC_X86_REG_R8, self.scratch + 0x1000)):
            self.uc.reg_write(register, value)
        self.uc.emu_start(HANDLER, stop, count=300000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != stop:
            raise ValueError('Start pipeline instruction budget')
        return dict(input=dict(code=code, gate_state=gate_state, status=status, current_world=current_world,
                               target_world=target_world, old_kind=old_kind, new_kind=new_kind, flag=flag,
                               load_world=load_world, alternate=alternate, reason=reason),
                    decoded=decoded, events=self.events.copy(), state=dict(
                        status30=self.uc.mem_read(ctx + 0x5030, 1)[0],
                        current40=int.from_bytes(self.uc.mem_read(ctx + 0x5040, 4), 'little'),
                        target44=int.from_bytes(self.uc.mem_read(ctx + 0x5044, 4), 'little'),
                        previousf4=int.from_bytes(self.uc.mem_read(ctx + 0x50f4, 4), 'little'),
                        kind59=self.uc.mem_read(ctx + 0x5059, 1)[0],
                        vector_hex=bytes(self.uc.mem_read(ctx + 0x5060, 24)).hex()))


def build():
    em = Emulator()
    cases = []
    for code in (1, 0x1197):
        for gate in (0, 1):
            cases.append(em.execute_pipeline(code=code, gate_state=gate, load_world=True))
    for load in (False, True):
        for status in (1, 2, 4, 5):
            cases.append(em.execute_pipeline(status=status, load_world=load, alternate=True))
    for status in (1, 2, 3, 4, 5):
        for old, new, flag in ((3, 0, 1), (3, 0, 0), (0, 3, 0), (3, 3, 1)):
            cases.append(em.execute_pipeline(status=status, current_world=41, old_kind=old, new_kind=new, flag=flag))
    cases.append(em.execute_pipeline(current_world=37, target_world=41))
    cases.append(em.execute_pipeline(code=0, gate_state=1, load_world=True, current_world=0xffffffff))
    cases.append(em.execute_pipeline(new_kind=255, flag=255))
    for case in cases:
        inp, state = case['input'], case['state']
        accepted = inp['code'] == 0 or (inp['code'] == 0x1197 and inp['gate_state'] != 1)
        received = [e for e in case['events'] if e['action'] == 'native_start_receive']
        if len(received) != int(accepted):
            raise ValueError('Start result acceptance mismatch')
        if accepted:
            if (state['target44'], state['previousf4'], state['kind59'], state['vector_hex']) != (
                    inp['target_world'], inp['current_world'], min(inp['new_kind'], 22), case['decoded']['vector_hex']):
                raise ValueError('Decoded start fields not applied')
        actions = [e['action'] for e in case['events']]
        reuse = (inp['current_world'] == inp['target_world'] and
                 (min(inp['new_kind'], 22) == 3 or
                  (inp['old_kind'] == 3 and inp['new_kind'] == 0 and bool(inp['flag']))))
        load = accepted and inp['load_world']
        callback = accepted and not load and not inp['alternate'] and not reuse
        finish_path = accepted and not load and (inp['alternate'] or reuse)
        send = finish_path and (inp['status'] in (2, 3, 4) or (inp['alternate'] and inp['status'] == 5))
        if (actions.count('load_state_capture'), actions.count('load_callback_capture'),
                actions.count('finish_packet_capture')) != (int(load), int(callback), int(send)):
            raise ValueError('Start service branch mismatch')
        if state['status30'] != (5 if send else inp['status']):
            raise ValueError('Start finish guard state mismatch')
    return dict(source=em.bindings['source'], sha256=em.bindings['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                dependency_sha256={name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in (
                    'replay-world-move-finish-send.py', 'replay-world-move-start-reader.py')},
                ranges=em.pipeline_ranges, reader_ranges=em.reader_ranges, constructor=em.reader_constructor,
                binding=em.binding, service_table=em.service_table.hex(), cases=cases, network_ready=False,
                limitations=['Actual ID204 reader/handler/result gate/service and actual ID205 guard/header/status execute.',
                             'Synthetic dispatch; selected state is explicit, not reached through a live ID110 session.',
                             'Load/transport/reuse predicates, actor preparation, loader, UI and send boundary are captures.',
                             'The result vector is transferred intact but its use as world coordinates is not proved.'])


if __name__ == '__main__':
    report = build()
    output = native.ROOT / 'code-clues/world-move-start-pipeline-replay.json'
    output.write_text(json.dumps(report, indent=2) + '\n', 'utf-8')
    print(json.dumps(dict(output=str(output), cases=len(report['cases']),
                          sha256=hashlib.sha256(output.read_bytes()).hexdigest())))
