"""Проверки независимых lifetime ожиданий без EXE/native engine."""
import copy
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent / 'resource-tools/vampir'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


contract, oracle = load('service-lifecycle-case-contracts'), load('service-lifecycle-oracle')


def expected(case_id, round_=0):
    spec = next(s for s in contract.scenarios() if s['case_id'] == case_id)
    return oracle.expected_case(spec)['observation']['rounds'][round_]


class ServiceLifecycleOracleTests(unittest.TestCase):
    def test_callback_copies_actual_stack_poison_and_preserves_unwritten_allocator_qword(self):
        first, second = expected('lifecycle-02'), expected('lifecycle-02', 1)
        callback1, callback2 = (r['effects']['assignments'][0]['callback'] for r in (first, second))
        self.assertEqual((callback1['unknown_dword'], callback2['unknown_dword']), (0x6d6d6d6d, 0xb7b7b7b7))
        self.assertEqual((callback1['unwritten_qword'], callback2['unwritten_qword']),
                         (0x5a5a5a5a5a5a5a5a, 0xa5a5a5a5a5a5a5a5))
        self.assertEqual(callback1['zero_dword'], 0)
        self.assertEqual(callback1['service'], 'service')
        self.assertEqual(callback1['token'], 0x123456789abcdef0)
        self.assertEqual(first['native_frees'][0], dict(owner='backend1.callback', size=48))

    def test_shared_old_release_follows_service_destruction_and_uses_real_counter_transitions(self):
        row = expected('lifecycle-09')
        self.assertEqual(row['entries'][-2:], ['service.deleting', 'control.move_release'])
        atomic = row['atomic_transitions']
        self.assertEqual(atomic[0], dict(control='control1', field='strong', before=2, after=1))
        self.assertEqual([a['control'] for a in atomic], ['control1', 'control2', 'control2', 'control1', 'control1'])
        names = [f['owner'] for f in row['native_frees']]
        self.assertLess(names.index('backend2'), names.index('service'))
        self.assertLess(names.index('service'), names.index('backend1'))
        self.assertEqual(row['retained_owners'], [])

    def test_service_dtor_keeps_dangling_slots_and_conditional_240_free(self):
        keep, free = expected('lifecycle-00'), expected('lifecycle-01')
        for row in (keep, free):
            self.assertIsNone(row['effects']['singleton_after'])
            self.assertEqual(row['effects']['service_backend_after'], 'backend1')
            self.assertEqual(row['effects']['service_control_after'], 'control1')
            self.assertEqual(row['effects']['service_vptr_after'], 'service.base')
        self.assertEqual(keep['retained_owners'], [dict(owner='service', reason='destructed_storage')])
        self.assertEqual(free['native_frees'][-1], dict(owner='service', size=240))

    def test_equal_values_and_equal_pointer_slots_do_not_clear_or_release(self):
        for case_id in ('move-01', 'move-02'):
            row = expected(case_id)
            self.assertEqual(row['effects']['destination'], 'A')
            self.assertEqual(row['effects']['source'], 'A')
            self.assertEqual(row['atomic_transitions'], [])
            self.assertEqual(row['native_frees'], [])
            self.assertEqual(row['calls']['control.dispatch'], 0)

    def test_shared_strong_suppresses_weak_and_zero_strong_retains_external_weak(self):
        shared, held = expected('move-04'), expected('move-05')
        self.assertEqual(shared['atomic_transitions'], [dict(control='A', field='strong', before=2, after=1)])
        self.assertFalse(shared['effects']['old_backend_disposed'])
        self.assertTrue(held['effects']['old_backend_disposed'])
        self.assertFalse(held['effects']['old_control_freed'])
        self.assertEqual((held['effects']['old_strong'], held['effects']['old_weak']), (0, 1))
        self.assertIn(dict(owner='A', reason='external_weak_reference'), held['retained_owners'])
        self.assertFalse(any(f['owner'] == 'A' for f in held['native_frees']))

    def test_null_backend_dispatch_returns_but_last_control_still_frees(self):
        row = expected('move-09')
        self.assertEqual(row['calls']['control.dispatch'], 1)
        self.assertEqual(row['calls']['backend.deleting'], 0)
        self.assertEqual(row['native_frees'], [dict(owner='A_null', size=24)])
        self.assertEqual(row['effects']['destination'], None)
        self.assertEqual(row['effects']['source'], None)

    def test_deleting_bit0_alone_controls_free_but_body_always_runs(self):
        rows = [expected('backend-delete-' + str(i)) for i in range(4)]
        self.assertEqual([r['effects']['freed'] for r in rows], [False, True, False, True])
        for row in rows:
            self.assertEqual(row['calls']['backend.destructor'], 1)
            self.assertEqual(row['calls']['backend.reset'], 1)
            self.assertEqual(row['calls']['backend.string_ring_clear'], 2)
            self.assertEqual(row['effects']['final_table'], 'backend.root_base')
        control = expected('control-delete-1')
        self.assertEqual(control['calls']['backend.destructor'], 0)
        self.assertEqual(control['native_frees'], [dict(owner='control1', size=24)])

    def test_reset_reuses_queues_ring_cleans_reverse_nodes_once_and_never_frees_queue_natively(self):
        row = expected('reset-05')
        self.assertEqual(row['entries'], ['backend.constructor', 'backend.reset', 'backend.reset', 'backend.deleting'])
        self.assertEqual(row['effects']['snapshots'][0], row['effects']['snapshots'][1])
        self.assertEqual(row['effects']['snapshots'][0]['queue_capacities'], [16, 24, 32])
        self.assertEqual(row['effects']['snapshots'][0]['queue_sizes'], [0, 0, 0])
        self.assertEqual(row['native_frees'][:4], [dict(owner='backend1.ring.heap', size=18),
            dict(owner='backend1.ring.node3', size=32), dict(owner='backend1.ring.node0', size=32),
            dict(owner='backend1.ring.map', size=32)])
        self.assertFalse(row['effects']['queue_storage_native_free'])
        self.assertEqual(row['calls']['backend.reset'], 3)
        self.assertEqual(row['calls']['backend.string_ring_clear'], 4)

    def test_native_constructor_increments_only_selected_observer_weak_pair(self):
        none, local, global_, both = [expected('constructor-' + str(i).zfill(2)) for i in (1, 3, 5, 7)]
        self.assertEqual(none['atomic_transitions'], [])
        self.assertEqual([a['control'] for a in local['atomic_transitions']], ['backend1.local_observer'])
        self.assertEqual([a['control'] for a in global_['atomic_transitions']], ['backend1.global_observer'])
        self.assertEqual([a['control'] for a in both['atomic_transitions']],
                         ['backend1.local_observer', 'backend1.global_observer'])
        self.assertEqual(local['effects']['reserve'], ['local'])
        self.assertEqual(global_['effects']['reserve'], ['global'])
        self.assertEqual(both['effects']['reserve'], ['local'])
        self.assertEqual(both['native_allocations'], [16] * 6)

    def test_end_cleanup_lookup_retains_explicit_global_registration_fixture_owners(self):
        local, global_, mixed = [expected('constructor-' + str(i).zfill(2)) for i in (2, 4, 6)]
        self.assertEqual(local['retained_fixture_owners'], [dict(owner='global', kind='global_container'),
            dict(owner='global.head', kind='fixture_sentinel')])
        self.assertIn(dict(owner='backend1.global.map', kind='registration_map'), global_['retained_fixture_owners'])
        self.assertIn(dict(owner='backend1.global.node', kind='registration_node'), mixed['retained_fixture_owners'])
        self.assertIn(dict(owner='global.input.map', kind='registration_map'), mixed['retained_fixture_owners'])
        self.assertFalse(any(r['owner'].endswith('local.node') for r in local['retained_fixture_owners']))
        shared = expected('lifecycle-09')
        self.assertIn(dict(owner='external', kind='pointer_slot'), shared['retained_fixture_owners'])
        self.assertIn(dict(owner='external.null', kind='pointer_slot'), shared['retained_fixture_owners'])

    def test_forged_cleanup_counter_order_and_poison_are_detected(self):
        spec = next(s for s in contract.scenarios() if s['case_id'] == 'lifecycle-11')
        for mutation in ('zero-unknown', 'free-order', 'release-order', 'stale-slots', 'manual-counter'):
            actual = oracle.expected_case(spec)
            row = actual['observation']['rounds'][0]
            if mutation == 'zero-unknown':
                row['effects']['assignments'][0]['callback']['unknown_dword'] = 0
            elif mutation == 'free-order':
                row['native_frees'].reverse()
            elif mutation == 'release-order':
                row['entries'][-2:] = ['control.move_release', 'service.deleting']
            elif mutation == 'stale-slots':
                row['effects']['service_backend_after'] = None
            else:
                row['atomic_transitions'][0]['after'] = 0
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                oracle.validate_case(actual, spec)


if __name__ == '__main__':
    unittest.main()
