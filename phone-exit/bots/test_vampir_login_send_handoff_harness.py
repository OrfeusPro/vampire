"""Pure admission, write policy and synthetic pending-provider regressions."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import unittest
from types import SimpleNamespace

TOOLS = Path(__file__).resolve().parent / 'resource-tools' / 'vampir'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), TOOLS / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HARNESS = load('verify-login-send-handoff-harness')
RUNTIME = load('login-send-handoff-runtime')
VERIFY = load('verify-login-send-handoff-context')


class HandoffAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.functions = set(range(0x1000, 0x100c))
        self.leaves = {at: 'c3' for at in range(0x2000, 0x2007)}
        self.exports = {'run-test': 'e' * 64}
        self.context = dict(family='login-send-handoff', format='login-send-handoff-v1',
            transfer_proof={'path': 'proof', 'sha256': 'a' * 64},
            functions={str(at): hex(at) for at in self.functions},
            leaves={hex(at): raw for at, raw in self.leaves.items()}, exports=self.exports)

    def test_only_exact_twelve_roots_and_seven_leaves(self):
        HARNESS.check_scope(self.context, self.functions, self.leaves, self.exports)
        with self.assertRaises(ValueError):
            HARNESS.check_scope(self.context, self.functions | {0x3000}, self.leaves, self.exports)
        with self.assertRaises(ValueError):
            HARNESS.check_scope(self.context, self.functions, {**self.leaves, 0x3000: 'c3'}, self.exports)

    def test_budget_overrides_and_foreign_exports_are_rejected(self):
        for key in ('function_budget', 'budget_scope', 'native_admission', 'native_input', 'native_handler'):
            context = copy.deepcopy(self.context)
            context[key] = 12
            with self.assertRaises(ValueError):
                HARNESS.check_scope(context, self.functions, self.leaves, self.exports)
        with self.assertRaises(ValueError):
            HARNESS.check_scope(self.context, self.functions, self.leaves, {'other': 'e' * 64})

    def test_mid_instruction_and_mid_leaf_fixture_collisions(self):
        spans = [(0x1000, 0x1005), (0x2000, 0x2008)]
        for address in (0x1000, 0x1004, 0x2000, 0x2007):
            with self.assertRaises(ValueError):
                HARNESS.check_fixture_address(address, spans)
        HARNESS.check_fixture_address(0x1005, spans)

    def test_only_top_level_prepare_and_no_nested_native_call(self):
        HARNESS.check_entry(0x1000, 0x1000, False)
        for address, active in ((0x2000, False), (0x1000, True)):
            with self.assertRaises(ValueError):
                HARNESS.check_entry(address, 0x1000, active)


class HandoffMemoryTests(unittest.TestCase):
    def setUp(self):
        self.policy = HARNESS.MemoryPolicy(object())
        self.policy.native_allow([(0x1000, 0x100)])

    def test_native_writes_are_bounded_and_packet_is_read_only(self):
        self.policy.writable(0x1000, 16, native=True)
        self.policy.protect([(0x1040, 16)])
        for at, size in ((0x103f, 2), (0x1040, 1), (0x10ff, 2)):
            with self.assertRaises(ValueError):
                self.policy.writable(at, size, native=True)

    def test_freed_strings_are_unreadable_and_unwritable(self):
        self.policy.retire(0x1020, 16)
        with self.assertRaises(ValueError):
            self.policy.readable(0x101f, 2)
        with self.assertRaises(ValueError):
            self.policy.writable(0x1020, 1)

    def test_fixture_windows_do_not_allow_native_or_nested_bypass(self):
        self.policy.begin_fixture([(0x1000, 8)])
        self.policy.writable(0x1000, 8)
        with self.assertRaises(ValueError):
            self.policy.writable(0x1008, 1)
        with self.assertRaises(ValueError):
            self.policy.begin_fixture([(0x1010, 8)])
        self.policy.end_fixture()


class PendingProviderTests(unittest.TestCase):
    def layout(self, name):
        return RUNTIME.pending_layout(name, 0x5000, 0x6000, 0x3fa00000)

    def test_empty_count_equal_skips_lookup(self):
        body, _, _ = self.layout('empty-count-equal')
        self.assertEqual(struct.unpack_from('<I', body, 0x40)[0], struct.unpack_from('<I', body, 0x6c)[0])

    def test_inline_miss_has_valid_other_bucket_node(self):
        body, nodes, _ = self.layout('inline-bucket-miss')
        capacity = struct.unpack_from('<I', body, 0x80)[0]
        self.assertEqual(capacity, 2)
        self.assertEqual(struct.unpack_from('<Q', body, 0x78)[0], 0)
        self.assertEqual(struct.unpack_from('<i', body, 0x70 + (4 & (capacity - 1)) * 4)[0], -1)
        key = struct.unpack_from('<h', nodes, 0)[0]
        self.assertEqual(key, 5)
        self.assertEqual(struct.unpack_from('<i', body, 0x70 + (key & (capacity - 1)) * 4)[0], 0)

    def test_heap_miss_and_hit_follow_hash_consistent_chain(self):
        for name, wanted in (('heap-chain-miss', [8]), ('heap-chain-hit', [8, 4])):
            body, nodes, buckets = self.layout(name)
            capacity = struct.unpack_from('<I', body, 0x80)[0]
            bucket = 4 & (capacity - 1)
            index = struct.unpack_from('<i', buckets, bucket * 4)[0]
            keys = []
            while index != -1:
                key = struct.unpack_from('<h', nodes, index * 32)[0]
                self.assertEqual(key & (capacity - 1), bucket)
                keys.append(key)
                if key == 4:
                    break
                index = struct.unpack_from('<i', nodes, index * 32 + 0x18)[0]
            self.assertEqual(keys, wanted)

    def test_pending_stack_aliases_are_exact_integer_addresses(self):
        stack = 0x1000
        aliases = [stack, stack + 0x58, stack + 0x38, stack + 0x68, stack + 0x28]
        RUNTIME.check_pending_aliases(*aliases)
        for index in range(1, len(aliases)):
            wrong = list(aliases)
            wrong[index] += 8
            with self.assertRaises(ValueError):
                RUNTIME.check_pending_aliases(*wrong)
        for value in (True, float(stack)):
            with self.assertRaises(ValueError):
                RUNTIME.check_pending_aliases(value, *aliases[1:])


class HandoffDiagnosticTests(unittest.TestCase):
    def test_bounded_paths_and_strict_bool_type(self):
        diff = VERIFY.differences({'a': {'b': 1}}, {'a': {'b': True}})
        self.assertEqual(diff[0]['path'], '$.a.b')
        self.assertEqual(len(VERIFY.differences(list(range(30)), list(range(30, 60)))), 16)

    def test_failure_identity_and_scope_cannot_look_accepted(self):
        canonical = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'))
        contract = SimpleNamespace(FAMILY='login-send-handoff', SCOPE='bounded_native_login_send_handoff',
            canonical=canonical, tools=lambda: {'verifier': 'e' * 64})
        context = dict(source_sha256='a' * 64, transfer_proof={'path': 'proof', 'sha256': 'b' * 64})
        payload = VERIFY.failure_payload(context, contract, {'case': 1}, {'value': 1}, {'value': 2}, ValueError('diff'))
        self.assertNotIn('context_sha256', payload)
        self.assertEqual(payload['context_canonical_sha256'], hashlib.sha256(canonical(context).encode()).hexdigest())
        self.assertEqual(payload['family'], contract.FAMILY)
        self.assertEqual(payload['method'], 'bounded_native_failure_diagnostic')
        for name in ('accepted', 'runtime_activated', 'profile_activated', 'network_used', 'native_wire_used'):
            self.assertIs(payload[name], False)
        self.assertEqual(payload['transfer_proof'], context['transfer_proof'])


if __name__ == '__main__':
    unittest.main()
