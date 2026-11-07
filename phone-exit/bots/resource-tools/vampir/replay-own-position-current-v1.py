"""Execute the current actor-position selector with explicit surface fixtures."""
from collections import Counter
import math
import struct


SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
RECIPE = 'own-position-current-v1'
CORRECTOR = 0x1456a5290
PREDICATE = 0x14568dee0
NAVIGATION = 0x14568fbf0
COLLISION = 0x1456a6d10
BIAS = 0x14b1bc4c0
THRESHOLD = 0x1489fa038
FALLBACK = 0x14b0c3298
CONSTANTS = {
    'capsule_bias': hex(BIAS),
    'z_threshold': hex(THRESHOLD),
    'fallback_vector': hex(FALLBACK),
}
SOURCE_ROLES = {
    'world_dispatch': '0x1467cd950',
    'world_receiver': '0x145dafdd0',
    'spawn': '0x14567d560',
    'retain_z_predicate': hex(PREDICATE),
    'navigation': hex(NAVIGATION),
    'collision': hex(COLLISION),
    'quest_producer': '0x145d72d80',
    'move_producer': '0x145d8c8c0',
}
BINDINGS = {
    'scaled_capsule_name_slot': '0x1492582f0',
    'scaled_capsule_name': '0x1492501f0',
    'scaled_capsule_getter': '0x143a71c40',
    'scaled_capsule_getter_bytes': '4883ec28488b42204533c94885c0410f95c14c03c84c894a200f108120020000f20f5ac0f30f598108050000f3410f11004883c428c3',
}
LIMITS = (
    'The whole actor-position selector executes; actor predicate, navigation and collision results are explicit fixtures.',
    'Actor flags, root transform, capsule scale and half-height are synthetic objects, not live actor data.',
    'Writable bias and fallback globals are seeded with their file values only; their live values are unknown.',
    'The special-predicate-fixture covers arithmetic with independent synthetic predicate/flag inputs; live reachability is unproved.',
    'Surface selection, active geometry, actual actor transform, runtime admission and a real 1810 result remain open.',
)


def require(ok, reason):
    if not ok:
        raise ValueError('Own-position replay: ' + reason)


def f32(value):
    return struct.unpack('<f', struct.pack('<f', value))[0]


def scenarios():
    position = (123.25, -456.5, 789.75)
    common = dict(position=position, actor=True, component=True, capsule=True,
                  predicate=False, special=False, navigation=False, collision=False,
                  navigation_position=position, collision_z=position[2],
                  scale=1., half_height=88., retained_z=-12.5, status_pointer=True)
    variants = (
        ('no-surface', {}),
        ('navigation-only', dict(navigation=True, navigation_position=(125., -458., 500.))),
        ('collision-only', dict(collision=True, collision_z=500.)),
        ('no-actor', dict(actor=False, navigation=True, navigation_position=(125., -458., 500.))),
        ('no-actor-no-surface', dict(actor=False)),
        ('no-capsule', dict(capsule=False)),
        ('no-component', dict(component=False)),
        ('keep-component-z', dict(predicate=True)),
        ('keep-fallback-z', dict(predicate=True, component=False)),
        ('no-status-pointer', dict(status_pointer=False)),
        ('zero-scale', dict(scale=0.)),
        ('negative-scale', dict(scale=-1.125, half_height=77.3)),
        ('fractional-scale', dict(scale=1. / 3., half_height=88.2)),
        ('float32-rounding', dict(scale=16777217., half_height=.1)),
        ('special-predicate-fixture', dict(special=True)),
        ('special-no-capsule-fixture', dict(special=True, capsule=False)),
    )
    cases = [dict(common, **changes, name=name) for name, changes in variants]
    for name, nav_z, hit_z in (
        ('equal-surfaces', 10., 10.),
        ('navigation-higher', 10., 9.),
        ('collision-higher', 9., 10.),
        ('threshold-below', 0., math.nextafter(1000., 0.)),
        ('threshold-equal', 0., 1000.),
        ('threshold-above', 0., math.nextafter(1000., math.inf)),
        ('threshold-navigation-higher', 1000., 0.),
    ):
        cases.append(dict(common, name=name, navigation=True, collision=True,
                          navigation_position=(125., -458., nav_z), collision_z=hit_z))
    return cases


def expected_case(case):
    position = case['position']
    calls = []
    found = 0x7b
    if case['actor']:
        calls.append('predicate')
    if case['actor'] and case['predicate']:
        value = (*position[:2], case['retained_z'] if case['component'] else 0.)
    elif case['actor'] and case['special']:
        offset = f32(f32(f32(case['scale']) * f32(case['half_height'])) + 1.) if case['capsule'] else 0.
        value = (*position[:2], float(offset))
    else:
        calls.extend(('navigation', 'collision'))
        navigation = case['navigation_position'] if case['navigation'] else position
        collision = (*position[:2], case['collision_z'] if case['collision'] else position[2])
        if case['navigation'] and (not case['collision'] or abs(navigation[2] - collision[2]) >= 1000.):
            selected = navigation
        elif case['navigation'] and navigation[2] > collision[2]:
            selected = navigation
        else:
            selected = collision
        offset = f32(f32(f32(case['scale']) * f32(case['half_height'])) + 1.) if case['actor'] and case['capsule'] else 0.
        value = (*selected[:2], selected[2] + float(offset))
        if case['status_pointer']:
            found = int(case['navigation'] or case['collision'])
    return dict(name=case['name'], output=list(value), output_bytes=struct.pack('<3d', *value).hex(),
                status_byte=found, helpers=calls)


def validate(result, context):
    expected = [expected_case(case) for case in scenarios()]
    require(context['source_sha256'] == SOURCE and context['recipe'] == RECIPE
            and context['roles'] == {'corrector': hex(CORRECTOR)}
            and context['source_roles'] == SOURCE_ROLES and context['constants'] == CONSTANTS
            and result.get('recipe') == RECIPE and result.get('source_sha256') == SOURCE
            and result.get('cases') == expected and result.get('whole_functions') == context['roles']
            and result.get('source_functions') == context['source_roles']
            and result.get('named_bindings') == BINDINGS
            and result.get('native_entries') == {hex(CORRECTOR): len(expected)}
            and result.get('abi_checks') == len(expected)
            and result.get('fixture_abi_checks') == sum(len(case['helpers']) for case in expected)
            and result.get('limits') == list(LIMITS) and result.get('native_execution') is True
            and all(result.get(field) is False for field in ('network_used', 'action_admitted', 'actor_vector_verified')),
            'source or exact fixture matrix differs')


def run(index, root, context):
    require(context['schema'] == 1 and context['source_sha256'] == SOURCE
            and context['recipe'] == RECIPE and context['roles'] == {'corrector': hex(CORRECTOR)}
            and context['source_roles'] == SOURCE_ROLES and context['constants'] == CONSTANTS,
            'source context differs')
    functions = {int(address, 16) for address in (*context['roles'].values(), *context['source_roles'].values())}
    h = index.extension('native-request-harness-11316').make_harness(
        context['exports'], functions, root=root, source_sha256=SOURCE, copy_thunk=None)
    native = index.extension('build-native-entry-code')
    bindings = index.extension('update-bindings')
    for export in h.fragments:
        address = int(export['address'], 16)
        actual = [(int(row['address'], 16), row['bytes']) for row in export['instructions']]
        expected = [(row['address'], row['bytes']) for row in bindings.rows(native, h.image, address)]
        require(export['block_coverage_complete'] and export['direct_flow_coverage_complete']
                and not index.missing_conditional_fallthroughs(export['instructions']) and actual == expected,
                'whole corrector instructions differ')

    def source(at, length):
        offset = h.image.offset(at - h.image.pe.base)
        return h.raw[offset:offset + length]

    require(source(BIAS, 4) == struct.pack('<f', 1.)
            and source(THRESHOLD, 8) == struct.pack('<d', 1000.) and source(FALLBACK, 24) == bytes(24),
            'file constants differ')
    name_slot = int(BINDINGS['scaled_capsule_name_slot'], 16)
    name = int(BINDINGS['scaled_capsule_name'], 16)
    getter = int(BINDINGS['scaled_capsule_getter'], 16)
    getter_bytes = bytes.fromhex(BINDINGS['scaled_capsule_getter_bytes'])
    require(source(name_slot, 16) == struct.pack('<2Q', name, getter)
            and source(name, 27) == b'GetScaledCapsuleHalfHeight\0'
            and source(getter, len(getter_bytes)) == getter_bytes,
            'named scaled capsule getter differs')
    uc, x, base = h.uc, h.x, h.scratch
    output, position, actor, component, capsule, status = (base + at for at in (0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000))
    stack, stop = base + 0x38008, base + 0x3f000
    current = {}
    helpers = []
    counts = Counter()
    fixture_abi_checks = 0

    def register(name):
        return getattr(x, 'UC_X86_REG_' + name)

    def reg(name):
        return uc.reg_read(register(name))

    def put(at, value, size=8):
        uc.mem_write(at, int(value).to_bytes(size, 'little'))

    def allow_write(at, length):
        require(any(lo <= at and at + length <= hi for lo, hi in
                    ((output, output + 24), (status, status + 1), (stack - 0x800, stack + 0x80))),
                'unexpected write at ' + hex(at))

    def fixture_write(at, data):
        allow_write(at, len(data))
        uc.mem_write(at, data)

    def predicate(_machine):
        require(current['actor'] and reg('RCX') == actor, 'predicate receiver differs')
        helpers.append('predicate')
        h.finish(int(current['predicate']))

    def navigation(_machine):
        require(reg('RCX') == position and stack - 0x800 < reg('RDX') < stack, 'navigation arguments differ')
        helpers.append('navigation')
        if current['navigation']:
            fixture_write(reg('RDX'), struct.pack('<3d', *current['navigation_position']))
        h.finish(int(current['navigation']))

    def collision(_machine):
        require(reg('RDX') == position and stack - 0x800 < reg('RCX') < stack
                and stack - 0x800 < reg('R8') < stack + 0x80 and reg('R9') == 0
                and int.from_bytes(uc.mem_read(reg('RSP') + 0x28, 8), 'little') == 0,
                'collision arguments differ')
        helpers.append('collision')
        value = (*current['position'][:2], current['collision_z'] if current['collision'] else current['position'][2])
        fixture_write(reg('RCX'), struct.pack('<3d', *value))
        fixture_write(reg('R8'), bytes([int(current['collision'])]))
        h.finish(reg('RCX'))

    def abi_fixture(callback):
        def execute(machine):
            nonlocal fixture_abi_checks
            before = reg('RSP')
            require(stack - 0x800 < before < stack and before % 16 == 8, 'fixture entry ABI differs')
            ret = int.from_bytes(uc.mem_read(before, 8), 'little')
            callback(machine)
            require(reg('RSP') == before + 8 and reg('RIP') == ret, 'fixture return ABI differs')
            fixture_abi_checks += 1
        return execute

    for at, callback in ((PREDICATE, predicate), (NAVIGATION, navigation), (COLLISION, collision)):
        h.add_fixture(at, abi_fixture(callback))
    from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    uc.hook_add(UC_HOOK_CODE, lambda _u, at, _s, _d: counts.update([at]), begin=CORRECTOR, end=CORRECTOR)
    uc.hook_add(UC_HOOK_MEM_WRITE, lambda _u, _a, at, length, _v, _d: allow_write(at, length))
    nonvolatile = ('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15', *(f'XMM{i}' for i in range(6, 16)))
    markers = tuple(0x3c40 + i for i in range(len(nonvolatile)))
    cases = []
    for case in scenarios():
        current.clear()
        current.update(case)
        helpers.clear()
        guards = []
        for at, length in ((output, 24), (position, 24), (actor, 0x700), (component, 0x240), (capsule, 0x520), (status, 1)):
            uc.mem_write(at - 16, b'L' * 16 + bytes(length) + b'R' * 16)
            guards.append((at, length))
        uc.mem_write(position, struct.pack('<3d', *case['position']))
        uc.mem_write(component + 0x200, struct.pack('<d', case['retained_z']))
        uc.mem_write(capsule + 0x220, struct.pack('<d', case['scale']))
        uc.mem_write(capsule + 0x508, struct.pack('<f', case['half_height']))
        put(actor + 0x1b8, component if case['component'] else 0)
        put(actor + 0x338, capsule if case['capsule'] else 0)
        put(actor + 0x6a5, int(case['special']), 1)
        put(status, 0x7b, 1)
        preserved = {at: bytes(uc.mem_read(at, length)) for at, length in guards if at not in (output, status)}
        uc.mem_write(BIAS, source(BIAS, 4))
        uc.mem_write(FALLBACK, source(FALLBACK, 24))
        uc.mem_write(stack - 0x800, b'\xa5' * 0x900)
        put(stack, stop)
        for name, value in zip(nonvolatile, markers):
            uc.reg_write(register(name), value)
        for name, value in (('RSP', stack), ('RCX', output), ('RDX', actor if case['actor'] else 0),
                            ('R8', position), ('R9', status if case['status_pointer'] else 0)):
            uc.reg_write(register(name), value)
        try:
            uc.emu_start(CORRECTOR, 0, count=3000)
        except Exception as error:
            raise ValueError(f"Own-position replay: {case['name']} at {reg('RIP'):#x}") from error
        require(reg('RIP') == stop and reg('RSP') == stack + 8 and reg('RAX') == output
                and tuple(reg(name) for name in nonvolatile) == markers, 'native call/return ABI differs')
        require(all(bytes(uc.mem_read(at, len(data))) == data for at, data in preserved.items()),
                'fixture input mutated')
        require(all(bytes(uc.mem_read(at - 16, 16)) == b'L' * 16
                    and bytes(uc.mem_read(at + length, 16)) == b'R' * 16 for at, length in guards),
                'fixture guard mutated')
        data = bytes(uc.mem_read(output, 24))
        observed = dict(name=case['name'], output=list(struct.unpack('<3d', data)), output_bytes=data.hex(),
                        status_byte=uc.mem_read(status, 1)[0], helpers=helpers.copy())
        require(observed == expected_case(case), 'result differs for ' + case['name'] + ': ' + repr(observed))
        cases.append(observed)
    result = dict(recipe=RECIPE, source_sha256=SOURCE, cases=cases, whole_functions=context['roles'],
                  source_functions=context['source_roles'], named_bindings=BINDINGS.copy(),
                  native_entries={hex(at): count for at, count in counts.items()}, abi_checks=len(cases),
                  fixture_abi_checks=fixture_abi_checks, limits=list(LIMITS), native_execution=True,
                  network_used=False, action_admitted=False, actor_vector_verified=False)
    validate(result, context)
    return result
