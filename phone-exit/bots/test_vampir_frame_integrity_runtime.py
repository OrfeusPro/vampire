"""Pure packet seeding, native callback exclusion and heap lifetime regressions."""
import importlib.util
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest

TOOLS = Path(__file__).resolve().parent / 'resource-tools/vampir'
def load(name):
    s = importlib.util.spec_from_file_location(name.replace('-', '_'), TOOLS / (name + '.py'))
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
R = load('frame-integrity-runtime')
H = load('frame-integrity-harness')
K = load('frame-integrity-codec')


class BytesMemory:
    def __init__(self): self.data = {}
    def mem_write(self, at, raw): self.data.update({at + i: b for i, b in enumerate(raw)})
    def mem_read(self, at, size): return bytes(self.data.get(at + i, 0) for i in range(size))


def fixture_state(h):
    return dict(heap=h.scratch + 0x50000, allocations={}, allocation_records={},
                allocation_owners={}, freed=set(), phase='inputs')


class SeedAndLifetimeTests(unittest.TestCase):
    def setUp(self):
        self.h = SimpleNamespace(scratch=0x28000000, uc=H.MemoryPolicy(BytesMemory()))
        self.state = fixture_state(self.h); self.ledger = R.AllocationLedger(self.h, self.state)

    def test_packet_seeds_raw_bool_and_utf16_before_native_without_wire_bytes(self):
        projection = dict(strings={hex(i): '' for i in R.STRINGS},
                          integers={hex(i): 0 for i in R.WIDTHS})
        projection['strings']['0x10'] = 'Ж🙂'
        projection['integers']['0x131'] = 0xff
        packet = self.h.scratch + 0xc000
        R.seed_packet(self.h, self.state, self.ledger, packet, 0x149928e90, projection)
        pointer, count, capacity = struct.unpack('<QII', self.h.uc.mem_read(packet + 0x10, 16))
        self.assertEqual((count, capacity), (4, 4))
        self.assertEqual(bytes(self.h.uc.mem_read(pointer, 8)), 'Ж🙂\0'.encode('utf-16le'))
        self.assertEqual(bytes(self.h.uc.mem_read(packet + 0x20, 16)), bytes(16))
        self.assertEqual(bytes(self.h.uc.mem_read(packet + 0x131, 1)), b'\xff')
        self.assertEqual(set(self.state['allocations']), set(self.state['input_buffers']))
        self.assertEqual(self.state['allocation_records'][pointer]['owner'], 'input.packet')
        self.assertEqual(self.state['allocation_records'][pointer]['phase'], 'inputs')
        self.assertEqual(len(self.state['packet_snapshot']), 352)
        self.assertNotIn('expected_frame', self.state)

    def test_unaccepted_projection_and_scalar_type_cannot_seed_packet(self):
        projection = dict(strings={hex(i): '' for i in R.STRINGS},
                          integers={hex(i): 0 for i in R.WIDTHS})
        projection['integers']['0x131'] = True
        with self.assertRaises(ValueError):
            R.seed_packet(self.h, self.state, self.ledger, self.h.scratch + 0xc000, 1, projection)
        projection['integers']['0x131'] = 0; projection['strings']['0x10'] = 'x\0y'
        with self.assertRaises(ValueError):
            R.seed_packet(self.h, self.state, self.ledger, self.h.scratch + 0xc000, 1, projection)

    def test_paired_reset_keeps_archive_retirement_then_independent_case_clears_it(self):
        at = self.ledger.allocate(1024, 'archive', 'wire.outer')
        self.state.update(fixture_owner='wire.cleanup', fixture_callsite=0x1234)
        self.ledger.release(at, 'archive', 1024)
        R.reset_policy(self.h.uc, preserve_retired=True)
        with self.assertRaises(ValueError): self.h.uc.mem_read(at, 1)
        R.reset_policy(self.h.uc)
        self.assertEqual(self.h.uc.retired, [])

    def test_sized_free_checks_owner_kind_and_does_not_retire_failed_free(self):
        at = self.ledger.allocate(260, 'utf8', 'wire.string-writer')
        with self.assertRaises(ValueError): self.ledger.release(at, 'archive', 260)
        with self.assertRaises(ValueError): self.ledger.release(at, 'utf8', 259)
        self.assertNotIn(at, self.state['freed'])
        self.ledger.release(at, 'utf8', 260)
        with self.assertRaises(ValueError): self.ledger.release(at, 'utf8', 260)


class NativeIntegrityCodecTests(unittest.TestCase):
    def setUp(self):
        self.memory = H.MemoryPolicy(BytesMemory())
        self.h = SimpleNamespace(scratch=0x28000000, uc=self.memory, finish=lambda value: None)
        self.regs = {'RCX': 0, 'RDX': 0, 'R8': 0, 'R9': 0, 'RSP': 0x3000, 'RAX': 0}
        self.state = dict(events=[], allocation_records={})
        self.context = dict(functions={'backend': '0x1000', 'wire.append': '0x1100',
            'wire.login-writer': '0x1200', 'wire.cleanup': '0x1300'},
            backend=dict(checksum_init='0x2000', checksum='0x2100', transform='0x2200',
                transport='0x2300', globals={}), helpers={'memcpy': '0x2400'},
            call_sites={'backend': {}, 'wire.append': {}}, source_inputs={})
        self.wire = dict(archive=dict(growth='0x2500'), fixtures=dict(utf8_allocate='0x2600',
            cpp_allocate='0x2700', utf8_free='0x2800', cpp_free='0x2900', security_check='0x2a00',
            archive_slot=40))
        self.codec = K.install(self.h, self.context, self.wire, self.state,
            lambda *args, **kwargs: None, lambda *args, **kwargs: None,
            lambda address: ('backend', 0x1010), lambda name: self.regs[name],
            lambda at, size=8: int.from_bytes(self.memory.mem_read(at, size), 'little'))
        self.codec.seed({'key_bits': 0x0102030405060708, 'transport_result_byte': 1}, 0x4000)

    def test_all_three_integrity_entries_are_native_not_fixture_callbacks(self):
        self.assertTrue({0x2000, 0x2100, 0x2200}.isdisjoint(self.codec.fixtures))
        self.assertNotIn('checksum_init', self.codec.fixture_addresses)
        self.assertNotIn('checksum', self.codec.fixture_addresses)
        self.assertNotIn('transform', self.codec.fixture_addresses)
        self.assertEqual(self.codec.result['checksum_init_calls'], 0)
        self.assertIsNone(self.codec.result['checksum_initial_state'])

    def test_native_transform_observation_protects_prefix_and_unused_capacity(self):
        frame = b'header and plaintext'
        self.codec.contents = lambda name: frame
        self.codec.archives = {'outer': {'buffer': 0x5000}}
        self.state['allocation_records'][0x5000] = dict(size=1024)
        self.regs.update(RCX=0x5003, R8=0x5003, RDX=len(frame) - 3, R9=0x0102030405060708)
        self.memory.mem_write(0x4248, struct.pack('<Q', self.regs['R9']))
        self.memory.mem_write(0x3000, struct.pack('<Q', 0x1015))
        self.codec.native_integrity_entry(0x2200)
        self.assertIn((0x5000, 0x5003), self.memory.readonly)
        self.assertIn((0x5000 + len(frame), 0x5400), self.memory.readonly)
        self.assertEqual(self.codec.pending_returns[0x1015], ('native-transform', None))
        self.assertEqual(self.codec.result['plaintext_frame_hex'], frame.hex())
        self.assertFalse(self.codec.result['transform_identity'])
        for at in (0x5000, 0x5000 + len(frame)):
            with self.assertRaises(ValueError): self.memory.mem_write(at, b'!')

    def test_crc_native_return_must_match_mutated_state(self):
        self.codec.checksum_state = 0x6000
        self.codec.pending_returns[0x1015] = ('native-crc-update', None)
        self.memory.mem_write(0x6000, struct.pack('<I', 0x12345678))
        self.regs['RAX'] = 0xedcba987
        self.codec.observe_return(0x1015)
        self.assertEqual(self.codec.result['checksum_final_state'], 0x12345678)
        self.assertEqual(self.codec.result['checksum_value'], 0xedcba987)
        self.codec.pending_returns[0x1015] = ('native-crc-update', None)
        self.regs['RAX'] = 1
        with self.assertRaises(ValueError): self.codec.observe_return(0x1015)


if __name__ == '__main__': unittest.main()
