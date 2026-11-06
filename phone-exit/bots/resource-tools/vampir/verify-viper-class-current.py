"""Current ClassInfo lookup and selection consumers, with explicit engine fixtures."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/viper-class-11322.json'
SHA = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify(context_path=CONTEXT, *, root=ROOT):
    context_path, root = Path(context_path).resolve(), Path(root).resolve()
    context = json.loads(context_path.read_bytes())
    if (context.get('schema') != 1 or context.get('recipe') != 'viper-class-current-v1'
            or context.get('source_sha256') != SHA):
        raise ValueError('Current class context/source differs')
    roles = {k: int(v, 16) for k, v in context['functions'].items()}
    if set(roles) != {'lookup', 'iterator', 'selection', 'selected_type'}:
        raise ValueError('Current class consumer roles differ')
    h = load('native-request-harness-11316').make_harness(context['exports'], set(roles.values()),
        root=root, source_sha256=SHA, copy_thunk=None)
    native = load('build-native-entry-code')
    normalizer = load('audit-launcher-shape-11318')
    inputs = {str(context_path): digest(context_path), str(Path(__file__).resolve()): digest(__file__),
              str(h.source.resolve()): SHA}
    exported = {}
    for run, expected in context['exports'].items():
        path = root / 'ghidra/request-exports' / SHA / run / 'details.json'
        if digest(path) != expected:
            raise ValueError('Current class static export changed')
        doc = json.loads(path.read_bytes())
        if doc['new_source_sha256'] != SHA:
            raise ValueError('Current class export source differs')
        inputs[str(path.resolve())] = expected
        exported.update({f['address']: f for f in doc['functions']})
    static = []
    for at in context['static_roots']:
        body = exported[at]
        normalized = normalizer.normalize_function(native, h.image, body)
        static.append(dict(address=at, instructions=len(normalized['shape']),
            calls=normalized['calls'], references=normalized['references']))
    source_anchors = []
    for anchor in context['source_anchors']:
        at, raw = int(anchor['address'], 16), bytes.fromhex(anchor['bytes'])
        off = h.image.offset(at - h.image.pe.base)
        if h.raw[off:off + len(raw)] != raw:
            raise ValueError('Current ClassInfo source binding changed')
        source_anchors.append(anchor)
    # Every consumer body is covered against exact source ranges before execution.
    for at in roles.values():
        normalizer.normalize_function(native, h.image, exported[hex(at)])
    uc, x = h.uc, h.x
    owner, storage, bits, controller, actor, player, actor_class, player_class, actor_chain, player_chain = [
        h.scratch + n for n in (0x1000, 0x3000, 0x9000, 0xa000, 0xb000, 0xc000, 0xd000, 0xe000, 0xf000, 0x10000)]
    flags = int(context['selection_global'], 16)
    state = dict(kind=1, gender=1, busy=False, ready=True, player=True, selected_row=0)
    hooks = {k: int(v, 16) for k, v in context['fixtures'].items()}
    calls = []

    def fixture(machine):
        at = machine.reg_read(x.UC_X86_REG_RIP)
        a, b = [machine.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX)]
        calls.append(at)
        if at == hooks['busy']:
            if a != controller + 0xa60: raise ValueError('Selection busy receiver differs')
            h.finish(int(state['busy']))
        elif at == hooks['ready']:
            if a != controller: raise ValueError('Selection ready receiver differs')
            h.finish(int(state['ready']))
        elif at == hooks['actor_class']: h.finish(actor_class)
        elif at == hooks['player_class']: h.finish(player_class)
        elif at == hooks['player']: h.finish(player if state['player'] else 0)
        elif at == hooks['kind']: h.finish(state['kind'])
        elif at == hooks['gender']: h.finish(state['gender'])
        elif at == hooks['singleton']: h.finish(owner)
        elif at == hooks['old_selected']: h.finish(0)
        elif at == hooks['store_selection']:
            if (a, b) != (controller + 0xa60, actor): raise ValueError('Stored selection differs')
            h.finish()
        elif at == hooks['after_selection']:
            if a != controller: raise ValueError('Postselection receiver differs')
            h.finish()
        elif at == hooks['find_by_id']:
            if b != state['expected_id']: raise ValueError('Selected type lookup key differs')
            machine.mem_write(a, struct.pack('<Q', state['selected_row']))
            h.finish(a)
        elif at == hooks['row_pointer']:
            h.finish(int.from_bytes(machine.mem_read(a, 8), 'little'))
        else: raise ValueError('Unexpected class fixture')
    for at in hooks.values(): h.add_fixture(at, fixture)

    def table(count, occupied):
        uc.mem_write(owner, bytes(0x80)); uc.mem_write(storage, b'\xa5' * (35 * 0x1c8))
        uc.mem_write(owner + 0x18, struct.pack('<Q', storage))
        uc.mem_write(owner + 0x40, struct.pack('<I', count))
        words = [0] * max(1, (count + 31) // 32)
        for index in occupied: words[index // 32] |= 1 << (index % 32)
        if count > 32:
            uc.mem_write(bits, struct.pack('<' + 'I' * len(words), *words))
            uc.mem_write(owner + 0x38, struct.pack('<Q', bits))
        else: uc.mem_write(owner + 0x28, struct.pack('<I', words[0]))
        for index, (identifier, kind) in occupied.items():
            row = storage + index * 0x1c8 + 8
            uc.mem_write(row + 8, struct.pack('<I', identifier))
            uc.mem_write(row + 0x28, bytes([kind]))

    lookup_cases = []
    profiles = [(0, {}), (5, {i: (0x80001000 + i, i + 1) for i in range(5)}),
        (35, {0: (0x80002000, 2), 3: (0x80002003, 1), 31: (0x8000201f, 1), 34: (0x80002022, 5)})]
    for count, occupied in profiles:
        table(count, occupied); before = bytes(uc.mem_read(storage, 35 * 0x1c8))
        for kind in (0, 1, 2, 3, 4, 5, 99, 100, 255):
            expected = next((i for i, value in occupied.items() if value[1] == kind), None)
            uc.reg_write(x.UC_X86_REG_RDX, kind)
            found = h.call(roles['lookup'], owner)
            if found != (storage + expected * 0x1c8 + 8 if expected is not None else 0):
                raise ValueError('Current ClassInfo first occupied type match differs')
            if bytes(uc.mem_read(storage, 35 * 0x1c8)) != before:
                raise ValueError('ClassInfo lookup changed rows')
            lookup_cases.append(dict(count=count, kind=kind, expected_slot=expected,
                row_id=None if expected is None else occupied[expected][0]))

    def prepare():
        uc.mem_write(controller, bytes(0xb00)); uc.mem_write(actor, bytes(0x700)); uc.mem_write(player, b'\xa5' * 0x400)
        for cls, chain in ((actor_class, actor_chain), (player_class, player_chain)):
            uc.mem_write(cls, bytes(0x80)); uc.mem_write(cls + 0x30, struct.pack('<Q', chain))
            uc.mem_write(chain, struct.pack('<Q', cls + 0x30))
        uc.mem_write(actor + 0x10, struct.pack('<Q', actor_class))
        uc.mem_write(player + 0x10, struct.pack('<Q', player_class))
        uc.mem_write(controller + 0xa79, b'\1'); uc.mem_write(controller + 0xa7c, struct.pack('<I', 1))
        uc.mem_write(flags, b'\0'); calls.clear()
        state.update(kind=1, gender=1, busy=False, ready=True, player=True)

    selection_cases = []
    for kind in (1, 3, 5, 99):
        for gender in (0, 1):
            prepare(); state.update(kind=kind, gender=gender)
            table(5, {i: (0x80003000 + i, i + 1) for i in range(5)})
            uc.reg_write(x.UC_X86_REG_RDX, actor); h.call(roles['selection'], controller)
            expected_id = 0x80003000 + kind - 1 if kind <= 5 else 0
            if int.from_bytes(uc.mem_read(player + 0x360, 4), 'little') != expected_id or uc.mem_read(player + 0x364, 1)[0] != gender:
                raise ValueError('Selection must store row ID and explicit gender')
            if calls.count(hooks['singleton']) != 1 or calls.count(hooks['store_selection']) != 1 or calls.count(hooks['after_selection']) != 1:
                raise ValueError('Class selection service sequence differs')
            selection_cases.append(dict(kind=kind, gender=gender, stored_id=expected_id, stored=True))
    for blocker in ('disabled', 'busy', 'null_actor', 'wrong_mode', 'not_ready', 'bad_actor_type', 'kind100', 'gender2'):
        prepare(); table(5, {i: (i + 1, i + 1) for i in range(5)})
        if blocker == 'disabled': uc.mem_write(controller + 0xa79, b'\0')
        elif blocker == 'busy': state['busy'] = True
        elif blocker == 'wrong_mode': uc.mem_write(controller + 0xa7c, struct.pack('<I', 2))
        elif blocker == 'not_ready': state['ready'] = False
        elif blocker == 'bad_actor_type': uc.mem_write(actor_chain, bytes(8))
        elif blocker == 'kind100': state['kind'] = 100
        elif blocker == 'gender2': state['gender'] = 2
        uc.reg_write(x.UC_X86_REG_RDX, 0 if blocker == 'null_actor' else actor)
        h.call(roles['selection'], controller)
        if bytes(uc.mem_read(player + 0x360, 5)) != b'\xa5' * 5 or hooks['singleton'] in calls or hooks['store_selection'] in calls:
            raise ValueError('Blocked class selection wrote state or table')
        selection_cases.append(dict(blocker=blocker, stored=False))

    type_cases = []
    for row_kind in (1, 3, 5):
        for present in (False, True):
            prepare(); state.update(expected_id=0x80005555, selected_row=storage + 8 if present else 0)
            uc.mem_write(player + 0x360, struct.pack('<I', state['expected_id']))
            uc.mem_write(storage + 8 + 0x28, bytes([row_kind]))
            value = h.call(roles['selected_type']) & 255
            if value != (row_kind if present else 0): raise ValueError('Selected class getter type differs')
            type_cases.append(dict(row_type=row_kind, present=present, returned=value))
    for name in ('native-request-harness-11316', 'build-native-entry-code', 'audit-launcher-shape-11318',
                 'knowledge-index', 'audit-client-release'):
        path = HERE / (name + '.py'); inputs[str(path.resolve())] = digest(path)
    if any(digest(path) != expected for path, expected in inputs.items()):
        raise ValueError('Class proof inputs changed')
    report = dict(schema=1, recipe=context['recipe'], source_sha256=SHA, inputs=inputs,
        native_execution=True, lookup_cases=lookup_cases, selection_cases=selection_cases, type_cases=type_cases,
        static_roots=static, source_anchors=source_anchors, network_used=False, runtime_admitted=False,
        loaded_class_table_verified=False, complete_viper_payload_verified=False,
        limits=['Whole current sparse ClassInfo lookup/iterator, class selection and selected-type getter execute.',
            'Table rows/occupation bits and engine class/player/tag/gender access are explicit fixtures. IDs intentionally differ from class types.',
            'No previous actor, preview widget or deselection branch is supplied; their engine effects remain outside this package.',
            'Exact ClassInfo identity and loader body are statically source checked, not live table cache or full loader execution.',
            'Current allocation/completion/CDO copy, concrete loaded Viper integers and Create103/104 remain unverified.'])
    path = load('audit-client-release').save_snapshot(root / 'code-clues/viper-class-current-v1', report)
    return dict(report=str(path), sha256=digest(path), native_cases=len(lookup_cases) + len(selection_cases) + len(type_cases))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, default=CONTEXT)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    print(json.dumps(verify(args.context, root=args.root)))
