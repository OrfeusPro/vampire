"""Pure exact-scope, entry-order and shared-memory admission checks."""
import copy
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent / 'resource-tools/vampir'
spec = importlib.util.spec_from_file_location('backend_harness', HERE / 'verify-login-backend-wire-harness.py')
H = importlib.util.module_from_spec(spec); spec.loader.exec_module(H)


class BackendHarnessTests(unittest.TestCase):
    def setUp(self):
        self.functions = set(range(0x1000, 0x101d))
        self.leaves = {at: 'c3' for at in range(0x2000, 0x200d)}
        self.tails = {at: 'e900000000' for at in range(0x3000, 0x3003)}
        self.exports = {'run-test': 'a' * 64}
        self.context = dict(family='login-backend-wire', format='login-backend-wire-v1',
            transfer_proof={'path': 'proof', 'sha256': 'b' * 64},
            functions={str(at): hex(at) for at in self.functions},
            leaves={hex(at): raw for at, raw in self.leaves.items()},
            tails={hex(at): raw for at, raw in self.tails.items()}, exports=self.exports)

    def test_exact_scope_keeps_tails_separate(self):
        H.check_scope(self.context, self.functions, self.leaves, self.exports, self.tails)
        for leaves, tails in (({**self.leaves, **self.tails}, {}),
                (self.leaves, {**self.tails, 0x4000: 'c3'})):
            with self.assertRaises(ValueError):
                H.check_scope(self.context, self.functions, leaves, self.exports, tails)

    def test_scope_rejects_root_alias_and_optional_budget(self):
        for key in ('function_budget', 'budget_scope', 'native_admission'):
            c = copy.deepcopy(self.context); c[key] = 29
            with self.assertRaises(ValueError): H.check_scope(c, self.functions, self.leaves, self.exports, self.tails)
        c = copy.deepcopy(self.context); c['tails'][hex(next(iter(self.functions)))] = c['tails'].pop('0x3000')
        with self.assertRaises(ValueError):
            H.check_scope(c, self.functions, self.leaves, self.exports, H.normalized_tails(c))

    def test_one_publisher_then_prepare_per_completed_case(self):
        gate = H.EntrySequence(0x1000, 0x2000)
        with self.assertRaises(ValueError): gate.enter(0x1000)
        gate.begin_case()
        with self.assertRaises(ValueError): gate.enter(0x2000)
        gate.enter(0x1000)
        with self.assertRaises(ValueError): gate.enter(0x2000)
        with self.assertRaises(ValueError): gate.begin_case()
        gate.finish(True); gate.enter(0x2000); gate.finish(True)
        with self.assertRaises(ValueError): gate.enter(0x2000)
        gate.begin_case(); gate.enter(0x1000); gate.finish(True)

    def test_failed_native_entry_cannot_be_silently_reset(self):
        gate = H.EntrySequence(0x1000, 0x2000); gate.begin_case(); gate.enter(0x1000); gate.finish(False)
        with self.assertRaises(ValueError): gate.begin_case()
        with self.assertRaises(ValueError): gate.enter(0x2000)

    def test_fixture_cannot_replace_middle_of_any_fragment(self):
        spans = [(0x1000, 0x1007), (0x2000, 0x200d), (0x3000, 0x300f)]
        for at in (0x1006, 0x200c, 0x300e):
            with self.assertRaises(ValueError): H.check_fixture_address(at, spans)
        H.check_fixture_address(0x300f, spans)

    def test_duplicate_export_identity_must_match_all_addresses_and_bytes(self):
        a = dict(instructions=[dict(address='0x1000', bytes='488bc1'), dict(address='0x1003', bytes='c3')])
        b = copy.deepcopy(a); b['instructions'].reverse()
        self.assertEqual(H.export_identity(a), H.export_identity(b))
        b['instructions'][0]['bytes'] = 'cc'
        self.assertNotEqual(H.export_identity(a), H.export_identity(b))
        a['instructions'].append(a['instructions'][0])
        with self.assertRaises(ValueError): H.export_identity(a)

    def test_shared_policy_distinguishes_native_and_fixture_write_windows(self):
        p = H.MemoryPolicy(object()); p.native_allow([(0x1000, 128)])
        p.begin_fixture([(0x1020, 8)])
        p.writable(0x1020, 8)
        for at, size in ((0x1027, 2), (0x101f, 2)):
            with self.assertRaises(ValueError): p.writable(at, size)
        p.end_fixture(); p.protect([(0x1040, 16)]); p.retire(0x1060, 16)
        for at in (0x1040, 0x1060):
            with self.assertRaises(ValueError): p.writable(at, 1, native=True)
        with self.assertRaises(ValueError): p.readable(0x1060, 1)


if __name__ == '__main__': unittest.main()
