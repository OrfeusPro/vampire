"""Whole environment completion methods and actual phase write; engine boundaries explicit."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
SHA = 'd00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
EXPORTS = {
    'run-b225d75559e5': '4b48cda97394b83ffe6477c43ea7337852a89bba9fbd7164898d013ba019b85d',
    'run-e3795e7cbff3': 'c927f025a32e802e56bba3a91c20550847a88d252178020bf81f8927bbc90510',
    'run-5743ff88f614': 'e410a7c3d7c3b8397bc33f92f2245075f1dd9dafb034d3955d1fa99ac354b1aa',
}


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(with_world_finish=False):
    exports = dict(EXPORTS)
    functions = {0x145612a90, 0x145618b30, 0x145da88d0}
    leaves = {0x141403b70: 'c20000'}
    if with_world_finish:
        exports.update(load('quest-world-finish-binding-11316').EXPORTS)
        functions.add(0x145daca00)
    h = load('native-request-harness-11316').make_harness(
        exports, functions, leaves=leaves)
    index = load('knowledge-index')
    if h.sha != SHA or any(not f.get('block_coverage_complete')
            or f.get('direct_flow_coverage_complete') is not True
            or index.missing_conditional_fallthroughs(f['instructions']) for f in h.fragments):
        raise ValueError('Completion source/coverage differs')
    uc, x, b = h.uc, h.x, h.scratch
    environment, services, listeners, ui, context = [b + v for v in (0x1000, 0x3000, 0x5000, 0x7000, 0x9000)]
    state, events = {}, []

    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_' + name))

    def put(at, value, size=8):
        uc.mem_write(at, int(value).to_bytes(size, 'little'))

    def get(at, size=8):
        return int.from_bytes(uc.mem_read(at, size), 'little')

    def string(machine):
        uc.mem_write(reg('RCX'), bytes(16))
        h.finish(reg('RCX'))

    def formatter(machine):
        if reg('RDX') == 0x149909ae0:
            if reg('R8') & 255 != state['before'] or reg('R9') & 255 != 6:
                raise ValueError('Completion old/new phase arguments differ')
            events.append('phase-format')
        elif reg('RDX') not in (0x1489f18ac, 0x1496455f0):
            raise ValueError('Unexpected completion phase diagnostic')
        string(machine)

    def diagnostic(machine):
        uc.mem_write(reg('RCX'), bytes(0x90))
        h.finish(reg('RCX'))

    def notify(machine):
        if reg('RCX') != context or get(environment + 0x30, 1) != 6 or get(reg('RDX')):
            raise ValueError('Completion notification precedes phase write or has wrong context')
        events.append('phase-notify')
        h.finish()

    def event_clear(machine):
        if reg('RCX') != services + 0x90:
            raise ValueError('Unexpected completion event clear')
        events.append('event-clear')
        h.finish()

    def ui_reset(machine):
        if reg('RCX') != ui or reg('RDX') & 255:
            raise ValueError('Completion UI reset differs')
        events.append('ui-reset')
        h.finish()

    def unexpected(machine):
        raise ValueError('Completion reached an unadmitted engine branch')

    fixtures = {
        0x141426950: string, 0x141433340: formatter, 0x14142b620: string,
        0x141429e10: lambda machine: h.finish(reg('RCX')),
        0x14143ae20: diagnostic, 0x144403310: lambda machine: h.finish(),
        0x14563dd30: lambda machine: h.finish(context), 0x145639100: notify,
        0x1455595f0: lambda machine: h.finish(0),
        0x145490870: lambda machine: h.finish(context),
        0x143c1bac0: lambda machine: h.finish(0),
        0x143c15a40: lambda machine: h.finish(0),
        0x1456ad7a0: lambda machine: h.finish(),
        0x144ab0c40: lambda machine: h.finish(ui),
        0x144ab0d20: lambda machine: h.finish(1),
        0x1454e6500: lambda machine: h.finish(services),
        0x141445be0: event_clear,
        0x144a7e340: lambda machine: h.finish(0),
        0x144ab1530: ui_reset,
        0x145594de0: lambda machine: h.finish(listeners),
        0x1455b5210: lambda machine: h.finish(0),
        0x141483080: unexpected,
        0x1487e8ce0: lambda machine: h.finish(reg('RAX')),
    }
    for at, fn in fixtures.items():
        h.add_fixture(at, fn)
    bindings = []
    for table, entry in ((0x149909370, 0x145612a90), (0x149a3dac0, 0x145da88d0)):
        off = h.image.offset(table + 0x78 - h.image.pe.base)
        if struct.unpack_from('<Q', h.raw, off)[0] != entry:
            raise ValueError('Environment completion virtual binding differs')
        bindings.append(dict(table=hex(table), slot='0x78', entry=hex(entry)))
    off = h.image.offset(0x145da88f1 - h.image.pe.base)
    if h.raw[off:off+5].hex() != 'e89aa186ff':
        raise ValueError('Derived completion call differs')
    # Explicit fixture mode: no current world/actor, no selected group,
    # no saved delegate/listeners and no special derived branches.
    put(0x14b3cb8c0, 0, 1)
    put(0x14b2f014b, 1, 1)
    cases = []
    for derived in (False, True):
        for before in (0, 2, 3, 4, 5, 6, 7):
            for flag79 in (False, True):
                events.clear()
                state['before'] = before
                uc.mem_write(environment, bytes(0x1b0))
                uc.mem_write(listeners, bytes(0x40))
                put(environment, 0x149a3dac0 if derived else 0x149909370)
                put(environment + 0x30, before, 1)
                put(environment + 0x40, 10012, 4)
                put(environment + 0x44, 10020, 4)
                put(environment + 0x79, int(flag79), 1)
                put(environment + 0xf0, 0x6420, 2)
                snapshot = bytearray(uc.mem_read(environment, 0x1b0))
                snapshot[0x30] = 6
                uc.reg_write(x.UC_X86_REG_RDX, b + 0xb000)
                uc.reg_write(x.UC_X86_REG_R8, 10012)
                uc.reg_write(x.UC_X86_REG_R9, 0)
                try:
                    h.call(0x145da88d0 if derived else 0x145612a90, environment, budget=50000)
                except Exception as error:
                    raise RuntimeError('Completion stopped at ' + hex(reg('RIP'))) from error
                if bytes(uc.mem_read(environment, 0x1b0)) != bytes(snapshot):
                    raise ValueError('Completion changed unexpected environment fields')
                if events != ['phase-format', 'phase-notify', 'event-clear', 'ui-reset']:
                    raise ValueError('Completion ordering differs')
                if get(listeners + 0x24, 4) != 0:
                    raise ValueError('Empty listener iteration did not restore nesting')
                cases.append(dict(derived=derived, before=before, flag79=flag79,
                    after=get(environment + 0x30, 1), phase_gate_passed=get(environment + 0x30, 1) > 5,
                    events=events.copy()))
    finish = load('quest-world-finish-binding-11316').run_cases(
        h, environment, services, listeners, context, state, events) if with_world_finish else None
    audit = load('audit-client-release')
    result = dict(source_sha256=SHA, tool_sha256=audit.sha256(Path(__file__)), exports=h.evidence,
        bindings=bindings, derived_call=dict(address='0x145da88f1', bytes='e89aa186ff', target='0x145612a90'),
        cases=cases, world_finish=finish, native_execution=True, network_used=False, action_admitted=False,
        limits=['Whole derived/base completion and phase setter execute in an explicitly empty engine mode.',
            'Diagnostics, world/actor lookup, UI/event reset and providers are fixtures; no listeners or saved delegate.',
            'Derived flag+1A8, special world10010, kind0x12 and configuration branches are not exercised.',
            ('ID206 receiver-to-virtual78 executes; handler binding is static, whole handler/gate, real records, active task and full Time remain unproven.'
             if with_world_finish else 'ID206 handler/receiver-to-virtual78 binding, real environment records, active task and full Time lifecycle remain unproven.'),
            'Source11316 only; no automatic installed11318 or live action admission.'])
    topic = 'quest-world-finish-completion-11316' if with_world_finish else 'quest-environment-completion-11316'
    return audit.save_snapshot(h.root / 'code-clues' / topic, result), result


if __name__ == '__main__':
    path, result = run()
    print(json.dumps(dict(artifact=str(path), cases=len(result['cases']))))
