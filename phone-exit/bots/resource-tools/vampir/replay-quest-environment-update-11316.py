"""Whole environment writer/retry and quest readiness, with explicit engine fixtures."""
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run():
    path = HERE / 'knowledge/native-contexts/quest-environment-update-11316.json'
    context = json.loads(path.read_text('utf-8'))
    h = load('native-request-harness-11316').make_harness(
        context['exports'], {int(v, 16) for v in context['functions']},
        leaves={int(a, 16):b for a, b in context['leaves'].items()})
    index = load('knowledge-index')
    legacy = []
    for f in h.fragments:
        if not f.get('block_coverage_complete') or index.missing_conditional_fallthroughs(f['instructions']):
            raise ValueError('Environment writer coverage incomplete')
        if f.get('direct_flow_coverage_complete') is not True:
            if f.get('direct_flow_coverage_complete') is not None or f['address'] not in context['legacy_direct_flow']:
                raise ValueError('Environment writer direct flow incomplete')
            legacy.append(f['address'])
    if h.sha != context['source_sha256']:
        raise ValueError('Environment writer source changed')
    uc, x, base = h.uc, h.x, h.scratch
    environment, task, record, data, model, world, text = [base+n for n in
        (0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000)]
    world_table, guard_entry = base+0xe000, base+0xf000
    current, calls = {}, []

    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_'+name))

    def put(at, value, size=8):
        uc.mem_write(at, (int(value) % (1 << (8*size))).to_bytes(size, 'little'))

    def get(at, size=8):
        return int.from_bytes(uc.mem_read(at, size), 'little')

    def source(at):
        off = h.image.offset(at-h.image.pe.base)
        return int.from_bytes(h.raw[off:off+8], 'little')

    for slot, target in ((0x10, 0x14560e670), (0x70, 0x14561bca0),
                         (0xb8, 0x1418af880), (0xc8, 0x14144e120)):
        if source(0x149909370+slot) != target:
            raise ValueError('Environment table binding changed')

    def registration(machine):
        if reg('RCX') != environment+0x28:
            raise ValueError('Environment registration receiver')
        h.finish(reg('RCX'))

    def format_text(machine):
        if reg('R8') & 0xffffffff != current['formatted']:
            raise ValueError('Environment formatting argument')
        uc.mem_write(reg('RCX'), bytes(16))
        calls.append('format'); h.finish(reg('RCX'))

    def phase_request(machine):
        if reg('RCX') != environment or reg('RDX') & 255 not in (3, 5):
            raise ValueError('Environment phase request scope')
        if get(reg('R8')) != 0:
            raise ValueError('Environment phase diagnostic fixture')
        calls.append('phase:'+str(reg('RDX') & 255)); h.finish()

    def convert_text(machine):
        uc.mem_write(reg('RCX'), bytes(32)); calls.append('convert'); h.finish(reg('RCX'))

    def world_get(machine):
        if reg('RCX') != 0:
            raise ValueError('Environment world lookup scope')
        calls.append('world'); h.finish(0 if current['guard']=='missing' else world)

    def guard(machine):
        if reg('RCX') != world:
            raise ValueError('Environment guard receiver')
        calls.append('guard'); h.finish(int(current['guard']=='allow'))

    def string_init(machine):
        uc.mem_write(reg('RCX'), bytes(16)); h.finish(reg('RCX'))

    def callback_sink(machine):
        if get(reg('RCX')) != 0x145606830 or reg('XMM2') != 0 or reg('R9') != 0x14b5912e8:
            raise ValueError('Environment callback submission differs')
        # Explicit moved-callback fixture; the callback itself is never executed.
        calls.append('callback'); put(reg('RCX'), 0); h.finish()

    def model_lookup(machine):
        if reg('RCX') != model or reg('RDX') != 110120:
            raise ValueError('Environment readiness model scope')
        h.finish(record)

    def unexpected_free(machine):
        raise ValueError('Empty-string fixture unexpectedly freed memory')

    callbacks = {0x144286f50:registration, 0x141433340:format_text,
        0x145618b30:phase_request, 0x14566d560:convert_text, 0x1445d2a20:world_get,
        guard_entry:guard, 0x141426b30:string_init, 0x144a78160:callback_sink,
        0x1455bbcb0:model_lookup, 0x141483080:unexpected_free,
        0x1487e8ce0:lambda machine:h.finish(reg('RAX'))}
    for at, callback in callbacks.items():
        h.add_fixture(at, callback)

    def setup(old, requested, flag, phase, guard_mode):
        current.clear(); current.update(requested=requested, guard=guard_mode, formatted=requested if flag else old)
        calls.clear(); uc.mem_write(environment, bytes(0x200))
        if h.call(0x1456001d0, environment) != environment:
            raise ValueError('Environment constructor return')
        h.call(0x14560e670, environment)
        put(environment+0x40, old, 4); put(environment+0x44, requested, 4)
        put(environment+0xc1, flag, 1); put(environment+0x30, phase, 1)
        put(world, world_table); put(world_table+0x7b8, guard_entry)
        uc.mem_write(text, bytes(16)); put(0x14b5e4d60, model)
        uc.mem_write(record, bytes(0x60)); uc.mem_write(task, bytes(0x60))
        uc.mem_write(data, bytes(0x60))
        put(record+0x30, task); put(task+0x40, data); put(data+0x14, requested, 4)

    cases = []
    for path_name in ('direct', 'retry'):
      for guard_mode in ('missing', 'deny', 'allow'):
       for old in (0, 5):
        for requested in (0, 1, 0xffffffff):
            setup(old, requested, 1, 7, guard_mode)
            if path_name=='direct':put(environment+0xc1,0,1)
            immutable = [(a, bytes(uc.mem_read(a, 0x60))) for a in (record, task, data)]
            before = h.call(0x14568cad0, 110120) & 255
            if path_name == 'direct':
                uc.reg_write(x.UC_X86_REG_RDX, requested)
                uc.reg_write(x.UC_X86_REG_R8, text)
                h.call(0x14560f9e0, environment)
            elif h.call(source(0x149909370+0x70), environment) != 0:
                raise ValueError('Environment retry return changed')
            after = h.call(0x14568cad0, 110120) & 255
            allowed = guard_mode == 'allow'
            expected = requested if allowed else old
            if get(environment+0x40, 4) != expected or get(environment+0x44, 4) != (0 if allowed else requested):
                raise ValueError('Environment committed/pending fields differ')
            if before != int(old==requested) or after != int(expected==requested):
                raise ValueError('Environment writer/readiness linkage differs')
            if get(environment+0xc1, 1) != int(path_name=='retry' or not allowed) or calls.count('callback') != int(allowed):
                raise ValueError('Environment deferred flag/callback differs')
            if calls.count('phase:3') != 1 or calls.count('phase:5'):
                raise ValueError('Environment writer phase submission differs')
            if any(bytes(uc.mem_read(a, len(value))) != value for a, value in immutable):
                raise ValueError('Environment writer changed task/model inputs')
            cases.append(dict(path=path_name, guard=guard_mode, old=old, requested=requested,
                actual=get(environment+0x40, 4), pending=get(environment+0x44, 4), flag_c1=get(environment+0xc1,1),
                ready_before=bool(before), ready_after=bool(after), calls=calls.copy()))
    for old in (0, 5):
      for phase in (0, 2, 3, 4, 5, 7):
        setup(old, 1, 0, phase, 'allow')
        result = h.call(source(0x149909370+0x70), environment)
        selected = phase in (2, 3, 4)
        if result != int(selected) or get(environment+0x40, 4) != old or get(environment+0x44, 4) != 1:
            raise ValueError('Environment non-retry phase branch differs')
        if calls != (['format', 'phase:5'] if selected else []):
            raise ValueError('Environment non-retry performed unexpected work')
        cases.append(dict(path='phase', old=old, phase=phase, result=result, calls=calls.copy()))
    audit = load('audit-client-release')
    report = dict(source_sha256=h.sha, tool_sha256=audit.sha256(Path(__file__)),
        context_sha256=audit.sha256(path), exports=h.evidence, legacy_direct_flow_checked=legacy,
        cases=cases, native_execution=True, network_used=False, action_admitted=False, limits=context['limits'])
    target = audit.save_snapshot(h.root/'code-clues/quest-environment-update-11316', report)
    return target, report


if __name__ == '__main__':
    target, result = run()
    print(json.dumps(dict(artifact=str(target), cases=len(result['cases'])), ensure_ascii=False))
