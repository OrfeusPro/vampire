"""Независимые symbolic ожидания source lifetime; не управляют native памятью."""
import copy
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CONTRACT = load('service-lifecycle-case-contracts')
CALLBACK_TOKEN = 0x123456789abcdef0


def expected_round(spec, poison):
    calls = dict.fromkeys(CONTRACT.CALL_KEYS, 0)
    entries, allocations, frees, atomic, retained = [], [], [], [], []
    fixture_owners = [dict(owner='global', kind='global_container'),
                      dict(owner='global.head', kind='fixture_sentinel')]

    def enter(role):
        entries.append(role)

    def transition(control, field, before, after):
        atomic.append(dict(control=control, field=field, before=before, after=after))

    def free(owner, size):
        frees.append(dict(owner=owner, size=size))

    def construct(backend, native_allocation=False, inserts=0):
        if native_allocation:
            allocations.append(800)
        calls['backend.constructor'] += 1
        calls['backend.base_constructor'] += 1
        allocations.extend([16] * (4 + inserts))

    def destroy(backend, callback=False, release_object=True):
        calls['backend.deleting'] += 1
        calls['backend.destructor'] += 1
        calls['backend.base_destructor'] += 1
        calls['backend.reset'] += 1
        calls['backend.string_ring_clear'] += 2
        if callback:
            free(backend + '.callback', 48)
        free(backend + '.sentinel98', 16)
        free(backend + '.sentinel8', 16)
        if release_object:
            free(backend, 800)

    def release(control, backend, strong, weak, callback=False):
        transition(control, 'strong', strong, strong - 1)
        if strong == 1:
            calls['control.dispatch'] += 1
            if backend is not None:
                destroy(backend, callback)
            transition(control, 'weak', weak, weak - 1)
            if weak == 1:
                calls['control.deleting'] += 1
                free(control, 24)

    group = spec['group']
    if group == 'assignment_lifecycle':
        enter('service.publisher')
        calls['service.publisher'] = 1
        count = 1 if spec['old_backend'] == 'none' else 2
        callback = spec['callback_model'] != 'absent'
        assignments = []
        for index in range(1, count + 1):
            backend, control = 'backend' + str(index), 'control' + str(index)
            enter('service.assign')
            calls['service.assign'] += 1
            construct(backend, native_allocation=True)
            allocations.append(24)
            calls['control.move_release'] += 1
            if index == 2:
                release('control1', 'backend1', 2 if spec['old_backend'] == 'shared_reference' else 1,
                        1, callback)
            captured = None if not callback else dict(table='callback', service='service',
                token=CALLBACK_TOKEN, literal='callback.literal', zero_dword=0,
                unknown_dword=int.from_bytes(bytes([poison['stack_poison']]) * 4, 'little'),
                unwritten_qword=int.from_bytes(bytes([poison['allocator_poison']]) * 8, 'little'))
            assignments.append(dict(backend=backend, control=control, service_backend=backend,
                service_control=control, backlink='service', strong=1, weak=1, service_d8=0,
                backend_state=2, backend_busy=0, backend_socket=0, callback=captured))
        enter('service.deleting')
        calls['service.deleting'] = 1
        release('control' + str(count), 'backend' + str(count), 1, 1, callback)
        if spec['service_delete_flags'] & 1:
            free('service', 240)
        else:
            retained.append(dict(owner='service', reason='destructed_storage'))
        if spec['old_backend'] == 'shared_reference':
            enter('control.move_release')
            calls['control.move_release'] += 1
            release('control1', 'backend1', 1, 1, callback)
            fixture_owners.extend([dict(owner='external', kind='pointer_slot'),
                                   dict(owner='external.null', kind='pointer_slot')])
        effects = dict(assignments=assignments, singleton_after=None,
            service_backend_after='backend' + str(count), service_control_after='control' + str(count),
            service_vptr_after='service.base', service_freed=bool(spec['service_delete_flags'] & 1))
    elif group == 'control_move_release':
        fixture_owners.append(dict(owner='destination', kind='pointer_slot'))
        if spec['source'] != 'same_slot':
            fixture_owners.append(dict(owner='source', kind='pointer_slot'))
        destination = spec['destination']
        source = destination if spec['source'] == 'same_slot' else spec['source']
        if destination == 'A':
            enter('backend.constructor')
            construct('backend1')
        enter('control.move_release')
        calls['control.move_release'] = 1
        changed = destination != source
        strong, weak = spec['old_strong'], spec['old_weak']
        disposed = bool(changed and destination and strong == 1 and destination != 'A_null')
        deleted = bool(changed and destination and strong == weak == 1)
        if changed and destination:
            release(destination, 'backend1' if destination == 'A' else None, strong, weak)
            strong -= 1
            if spec['old_strong'] == 1:
                weak -= 1
        effects = dict(destination=source if changed else destination,
            source=None if changed else source, return_destination_alias=True,
            old_strong=strong, old_weak=weak, old_backend_disposed=disposed, old_control_freed=deleted)
        if destination and not deleted:
            retained.append(dict(owner=destination,
                reason='strong_reference' if strong else 'external_weak_reference'))
        if destination == 'A' and not disposed:
            retained.append(dict(owner='backend1', reason='strong_reference'))
        if source == 'B':
            retained.append(dict(owner='B', reason='moved_destination_owner'))
    elif group == 'deleting_flags':
        role, flags = spec['entry'], spec['flags']
        if role == 'backend.deleting':
            enter('backend.constructor')
            construct('backend1')
            enter(role)
            destroy('backend1', release_object=bool(flags & 1))
            table = 'backend.root_base'
        else:
            enter(role)
            calls[role] = 1
            if flags & 1:
                free('control1', 24)
            table = 'control.base'
        effects = dict(entry=role, flags=flags, returned_alias=True, freed=bool(flags & 1), final_table=table)
        if not flags & 1:
            retained.append(dict(owner='backend1' if role == 'backend.deleting' else 'control1',
                                 reason='destructed_storage'))
    elif group == 'reset_and_ring_ownership':
        enter('backend.constructor')
        construct('backend1')
        capacities = {'all_empty': [0, 0, 0], 'first_nonempty': [16, 0, 0],
                      'all_three_nonempty': [16, 24, 32]}[spec['queues']]
        snapshots = []
        for index in range(2):
            enter('backend.reset')
            calls['backend.reset'] += 1
            calls['backend.string_ring_clear'] += 1
            if index == 0 and spec['string_ring'] != 'empty':
                free('backend1.ring.heap', 18)
                free('backend1.ring.node3', 32)
                free('backend1.ring.node0', 32)
                free('backend1.ring.map', 32)
            snapshots.append(dict(queue_sizes=[0, 0, 0], queue_capacities=list(capacities),
                queue_bytes_preserved=True, queue_begins_preserved=True, ring_count=0,
                ring_start=0, ring_map=False, ring_capacity=0, busy=0, state=2, socket=0))
        enter('backend.deleting')
        destroy('backend1')
        effects = dict(snapshots=snapshots, queue_storage_native_free=False)
    elif group == 'constructor_registration_branches':
        profile = spec['iterator_fixture']
        local, global_ = profile['local'] == 'end', profile['global_'] == 'end'
        if global_:
            fixture_owners.append(dict(owner='global.input.map' if profile['name'] == 'both_insert_mixed'
                                       else 'backend1.global.map', kind='registration_map'))
            fixture_owners.append(dict(owner='backend1.global.node', kind='registration_node'))
        enter('backend.constructor')
        construct('backend1', inserts=int(local) + int(global_))
        present = spec['observer_control'] != 'null'
        for name, inserted in (('local', local), ('global', global_)):
            if present and inserted:
                transition('backend1.' + name + '_observer', 'weak', 3, 4)
            if present:
                retained.append(dict(owner='backend1.' + name + '_observer', reason='external_weak_reference'))
        effects = dict(local_insert=local, global_insert=global_, reserve=list(profile['reserve']),
            local_count=int(local), global_count=int(global_), local_pair_written=local,
            global_pair_written=global_, local_observer_weak=3 + int(local) if present else None,
            global_observer_weak=3 + int(global_) if present else None, source_fields_checked=True)
        enter('backend.deleting')
        destroy('backend1')
    else:
        raise ValueError('Service lifecycle oracle group differs')
    return dict(**copy.deepcopy(poison), entries=entries, calls=calls, effects=effects,
        native_allocations=allocations, native_frees=frees, atomic_transitions=atomic,
        retained_owners=retained,
        retained_fixture_owners=sorted(fixture_owners, key=lambda row: row['owner']),
        **dict.fromkeys(CONTRACT.ROUND_CHECKS, True))


def expected_case(spec):
    CONTRACT.validate_spec(spec)
    return dict(spec=copy.deepcopy(spec), observation=dict(
        rounds=[expected_round(spec, poison) for poison in spec['rounds']]))


def validate_case(actual, spec):
    expected = expected_case(spec)
    try:
        if CONTRACT.canonical(actual) != CONTRACT.canonical(expected):
            raise ValueError('Service lifecycle actual case differs')
    except (TypeError, ValueError) as error:
        raise ValueError('Service lifecycle actual case differs') from error
    return actual
