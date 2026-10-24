"""Execute explicit post-state wrapper and tail callee; backends remain fixtures."""
import argparse
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify(context, root):
    functions = {name: int(at, 16) for name, at in context['functions'].items()}
    h = load('update-native-harness').make_harness(context, context['exports'], set(functions.values()),
        leaves={int(at, 16): code for at, code in context['leaves'].items()}, root=root)
    native, rows = load('build-native-entry-code'), load('update-bindings').rows
    decoded = {name: rows(native, h.image, at) for name, at in functions.items()}
    calls = {name: {hex(r['address']): hex(r['direct_target']) if r['direct_target'] is not None else r['operands']
                   for r in rr if r['call']} for name, rr in decoded.items()}
    if calls != context['call_sites']:
        raise ValueError('Post-state call sites differ')
    tails = [dict(address=hex(r['address']), target=hex(r['direct_target']), bytes=r['bytes'])
             for r in decoded['wrapper'] if r['mnemonic'] == 'jmp' and r['direct_target'] == functions['target']]
    if tails != context['tail_calls'] or len(tails) != 1:
        raise ValueError('Post-state tail link differs')
    wrapper = next(f for f in h.fragments if int(f['address'], 16) == functions['wrapper'])
    if wrapper.get('tail_call_models') != tails or not wrapper.get('block_coverage_complete'):
        raise ValueError('Post-state export tail model differs')
    fixture = {int(at, 16): name for name, at in context['fixtures'].items()}
    if len(fixture) != len(context['fixtures']) or set(fixture) & (set(functions.values()) | {int(at, 16) for at in context['leaves']}):
        raise ValueError('Post-state fixture overlaps native code')
    direct = {int(target, 16) for sites in calls.values() for target in sites.values() if target.startswith('0x')}
    if direct - set(functions.values()) - set(fixture) - {int(at, 16) for at in context['leaves']}:
        raise ValueError('Post-state undeclared backend')
    service, actor, info, klass, chain, table, chunks, chunk0, chunk1 = [h.scratch + off for off in
        (0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000, 0x8000, 0x9000)]
    uc, x = h.uc, h.x
    globals_ = {name: int(at, 16) for name, at in context['globals'].items()}
    references = {at for rr in decoded.values() for r in rr for at in r['rip_references']}
    if not {globals_['count'], globals_['chunks']} <= references:
        raise ValueError('Post-state global links differ')
    leaf = int(context['service_getter'], 16)
    code = bytes.fromhex(context['leaves'][hex(leaf)])
    if code[:3] != b'\x48\x8b\x05' or code[7:] != b'\xc3' or leaf + 7 + struct.unpack_from('<i', code, 3)[0] != globals_['service']:
        raise ValueError('Post-state singleton getter differs')
    current, events, writes, entry = {}, [], [], []
    import unicorn

    def require(ok, message):
        if not ok:
            raise ValueError(message)

    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_' + name))

    def put(at, fmt, *values):
        uc.mem_write(at, struct.pack('<' + fmt, *values))

    def qword(at):
        return int.from_bytes(uc.mem_read(at, 8), 'little')

    def backend(machine, name):
        a, b, c, d = (reg(name) for name in ('RCX', 'RDX', 'R8', 'R9'))
        value = 0
        if name == 'class':
            value = info
        elif name == 'lookup':
            require(a == service and b == info, 'Post-state lookup arguments differ')
            value = actor if current['present'] else 0
        elif name == 'occupied':
            require(a == service + 0x250, 'Post-state slot argument differs')
            value = int(current['occupied'])
        elif name == 'mode':
            require(a == actor, 'Post-state mode receiver differs')
            value = current['mode']
        elif name in ('predicate', 'fallback', 'eligible'):
            require(a == actor, 'Post-state predicate receiver differs')
            value = int(current[name])
        elif name == 'list_match':
            require(a == service + 0x2c8 and b == actor, 'Post-state list arguments differ')
            value = int(current['list_match'])
        elif name == 'assign':
            require(a == service + 0x250 and b == actor, 'Post-state assignment arguments differ')
        elif name == 'hide':
            require(a == actor and b == 1 and c & 255 == 0 and d & 255 == 1
                    and qword(reg('RSP') + 0x28) & 255 == 1, 'Post-state hide arguments differ')
        elif name == 'settle':
            require(a == service and b == 0x1234 and c == actor, 'Post-state settle arguments differ')
        elif name == 'mark':
            expected = (chunk1 if current['object_index'] >> 16 else chunk0) + (current['object_index'] & 0xffff) * 0x18
            require(a == (expected if current['object_index'] < current['object_count'] else 0)
                    and b == 0x40000000, 'Post-state mark arguments differ')
        else:
            raise ValueError('Unsupported post-state backend')
        events.append(name)
        h.finish(value)

    for at, name in fixture.items():
        h.add_fixture(at, lambda machine, name=name: backend(machine, name))
    for i, slot in enumerate((0x2e8, 0x4c8, 0x540)):
        at = h.scratch + 0xe000 + i * 16
        put(table + slot, 'Q', at)
        def callback(machine, slot=slot):
            require(reg('RCX') == actor, 'Post-state virtual receiver differs')
            events.append('virtual_' + hex(slot)); h.finish()
        h.add_fixture(at, callback)

    def memory(machine, access, at, size, value, unused):
        if service <= at < service + 0x300:
            writes.append(dict(offset=hex(at - service), size=size, value=value, instruction=hex(reg('RIP'))))

    def reached(machine, at, size, unused):
        if at == functions['target']:
            entry.append(dict(service=reg('RCX') == service, actor=reg('RDX') == actor,
                              flag=reg('R8') & 255, stack=reg('RSP') - h.scratch))
    uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, memory)
    uc.hook_add(unicorn.UC_HOOK_CODE, reached)

    def run(direct=False, **settings):
        current.clear()
        current.update(present=True, class_count=3, class_index=2, class_match=True, active=True, busy=False,
                       occupied=False, mode=0, predicate=False, fallback=False, list_match=True,
                       eligible=False, object_index=0, object_count=1, flag=1)
        current.update(settings)
        events.clear(); writes.clear(); entry.clear()
        for at, size in ((service, 0x300), (actor, 0x340), (info, 0x40), (klass, 0x40), (chain, 0x40)):
            uc.mem_write(at - 16, b'\xa5' * 16 + bytes(size) + b'\xa6' * 16)
        put(service + 0x250, 'Q', 0xaabbccdd)
        put(service + 0x260, 'BB', int(current['active']), int(current['busy']))
        put(actor, 'Q', table); put(actor + 0x10, 'Q', klass); put(actor + 0xc, 'I', current['object_index'])
        put(actor + 0x328, 'Q', 0x1234); put(info + 0x38, 'i', current['class_index'])
        put(klass + 0x30, 'Qi', chain, current['class_count'])
        require(0 <= current['class_index'] <= 3, 'Post-state synthetic class index bound')
        put(chain + current['class_index'] * 8, 'Q', info + 0x30 if current['class_match'] else 0)
        put(globals_['service'], 'Q', service); put(globals_['count'], 'I', current['object_count'])
        put(globals_['chunks'], 'Q', chunks); put(chunks, 'QQ', chunk0, chunk1)
        actor_before = bytes(uc.mem_read(actor, 0x340)); service_before = bytes(uc.mem_read(service, 0x300))
        abi = {name: 0x1234567800000000 + i for i, name in enumerate(('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15'))}
        for name, value in abi.items():
            uc.reg_write(getattr(x, 'UC_X86_REG_' + name), value)
        uc.reg_write(x.UC_X86_REG_RDX, actor if current['present'] else 0)
        uc.reg_write(x.UC_X86_REG_R8, current['flag'])
        returned = h.call(functions['target'] if direct else functions['wrapper'], service)
        require(all(reg(name) == value for name, value in abi.items()) and reg('RSP') == h.scratch + 0x38008,
                'Post-state ABI differs')
        require(bytes(uc.mem_read(actor, 0x340)) == actor_before, 'Post-state changed actor outside fixtures')
        after = bytes(uc.mem_read(service, 0x300))
        require(all(a == b for i, (a, b) in enumerate(zip(service_before, after)) if not 0x250 <= i < 0x258),
                'Post-state changed unrelated service fields')
        for at, size in ((service, 0x300), (actor, 0x340), (info, 0x40), (klass, 0x40), (chain, 0x40)):
            require(bytes(uc.mem_read(at - 16, 16)) == b'\xa5' * 16 and bytes(uc.mem_read(at + size, 16)) == b'\xa6' * 16,
                    'Post-state guards changed')
        return dict(direct=direct, settings=dict(current), returned=returned, events=list(events), writes=list(writes),
                    target_entry=list(entry), slot=qword(service + 0x250), guards=True)

    cases = [run(mode=mode, predicate=pred, fallback=fallback, list_match=match, eligible=eligible)
             for mode, pred, fallback, match, eligible in itertools.product((0, 3), (False, True), (False, True), (False, True), (False, True))]
    cases += [run(**settings) for settings in (dict(present=False), dict(class_count=1), dict(class_match=False),
              dict(active=False), dict(busy=True), dict(occupied=True),
              dict(list_match=False, eligible=True, object_count=0),
              dict(list_match=False, eligible=True, object_index=0x10005, object_count=0x10006))]
    cases += [run(direct=True, **settings) for settings in (dict(flag=0), dict(present=False), dict(active=False), dict(occupied=True))]
    return dict(schema=1, source_sha256=context['source_sha256'], method='bounded_native', cases=cases,
                tail_calls=tails, evidence=h.evidence, runtime=load('update-native-harness').runtime_inputs(),
                network_used=False, profile_activated=False,
                limits=['Only explicit wrapper/tail callee and singleton getter execute; objects/class arrays and all backend/virtual methods are fixtures.',
                        'No handler integration, real services, CharacterListRead send or session proof; raw return values are not named success codes.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    result = verify(json.loads(args.context.read_text('utf-8')), args.root)
    result.update(context_sha256=hashlib.sha256(args.context.read_bytes()).hexdigest(), tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    path = load('research-workflow').snapshot(args.root, 'native-login-post-state-checks', result)
    print(json.dumps(dict(report=str(path), cases=len(result['cases']))))
