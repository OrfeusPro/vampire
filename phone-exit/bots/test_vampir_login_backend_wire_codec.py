"""Bounded fixture and ownership checks with fake memory; no native execution."""
import importlib.util
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest

HERE = Path(__file__).resolve().parent / 'resource-tools/vampir'
def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
C = load('login-backend-wire-codec')
H = load('verify-login-backend-wire-harness')


class Memory:
    def __init__(self): self.data = {}
    def mem_read(self, at, size): return bytes(self.data.get(at+i, 0) for i in range(size))
    def mem_write(self, at, data): self.data.update({at+i: value for i, value in enumerate(data)})


class CodecFixtureTests(unittest.TestCase):
    def setUp(self):
        self.regs = {key: 0 for key in ('RCX', 'RDX', 'R8', 'R9', 'RAX', 'RSP')}
        self.role = 'backend'; self.finished = None; self.heap = 0x150000
        self.state = dict(allocations={}, allocation_records={}, freed=set(), events=[], packet=0x104000,
                          check_packet=lambda: None)
        self.h = SimpleNamespace(scratch=0x100000, uc=H.MemoryPolicy(Memory()),
            finish=lambda value: setattr(self, 'finished', value))
        functions = dict(backend='0x1000', **{'wire.append': '0x2000', 'wire.cleanup': '0x3000',
            'wire.login-writer': '0x4000'})
        archive = {key: hex(0x5000+i*32) for i, key in enumerate(('constructor', 'table', 'growth', 'raw'))}
        fixtures = {key: hex(0x6000+i*32) for i, key in enumerate(('utf8_allocate', 'utf8_free',
            'cpp_allocate', 'cpp_free', 'security_check'))}
        backend = {key: hex(0x7000+i*32) for i, key in enumerate(('checksum_init', 'checksum',
            'transform', 'transport', 'packet_id_getter', 'get_buffer'))}
        self.context = dict(functions=functions, backend=backend, helpers={'memcpy': '0x8000'},
            call_sites={'backend': {}, 'wire.append': {}}, source_inputs={
                'archive_flags': {'address': '0x9010', 'bytes': '01000000'},
                'cleanup_final_table': {'address': '0x9000'}})
        wire = dict(archive=archive, fixtures=fixtures, writer_metadata={'cookie': '0xa000'})
        self.codec = C.install(self.h, self.context, wire, self.state, self.allocate, self.release,
            lambda at: (self.role, 0x1234), self.regs.__getitem__, self.number)
        self.spec = {'transport_result_byte': 1}
        self.codec.seed(self.spec, 0x10a000)
        self.regs.update(RSP=0x138008, RCX=0x10a000)
        self.codec.observed(0x1000)

    def number(self, at, size=8): return int.from_bytes(self.h.uc.mem_read(at, size), 'little')
    def put(self, at, value, size=8): self.h.uc.mem_write(at, value.to_bytes(size, 'little'))
    def allocate(self, size, kind='utf16', owner=None):
        at = self.heap + 16; self.heap += (size + 63) & ~15
        self.h.uc.mem_write(at-16, b'\xa5'*16 + b'\x5a'*size + b'\xa6'*16)
        self.state['allocations'][at] = size
        self.state['allocation_records'][at] = dict(size=size, kind=kind, owner=owner)
        return at
    def release(self, at, expected_kind=None, expected_size=None):
        r = self.state['allocation_records'][at]
        if at in self.state['freed'] or r['kind'] != expected_kind or (expected_size is not None and r['size'] != expected_size):
            raise ValueError('fake ledger ownership mismatch')
        self.state['freed'].add(at); self.h.uc.retire(at, r['size'])
    def archive(self, name, data):
        item = self.codec.archives[name]; at = item['object']
        pointer = self.codec.new_allocation(1024, 'archive', name)
        item['buffer'] = pointer
        self.h.uc.mem_write(pointer, data)
        self.h.uc.mem_write(at+0x18, struct.pack('<QQQ', pointer, pointer+1024, pointer+1024))
        self.h.uc.mem_write(at+0x30, struct.pack('<III', 1024, len(data), len(data)))
        return pointer

    def test_initial_growth_requires_native_capacity_and_zero_old_descriptor(self):
        self.role = 'wire.archive.raw'; item = self.codec.archives['inner']; at = item['object']
        self.put(at+0x30, 1024, 4); self.regs.update(RCX=at+0x18, RDX=1024)
        self.codec.growth(None)
        self.assertEqual(self.codec.result['initial_growth_sizes'], [1024])
        self.assertEqual(self.codec.contents('inner'), b'')
        pointer = self.number(at+0x18)
        self.assertEqual(self.number(at+0x20), pointer+1024)
        self.assertEqual(self.number(at+0x28), pointer+1024)
        with self.assertRaises(ValueError): self.codec.growth(None)

    def test_archive_storage_is_resized_vector_not_borrowed_preallocation(self):
        pointer = self.archive('inner', b'abc'); at = self.codec.archives['inner']['object']
        self.assertEqual(self.codec.contents('inner'), b'abc')
        self.put(at+0x20, pointer)
        with self.assertRaisesRegex(ValueError, 'vector descriptor'):
            self.codec.contents('inner')

    def test_constructor_uses_current_shared_enum_provider_not_initial_file_value(self):
        at = self.codec.archives['inner']['object']
        self.put(0x9010, 0xffffffff, 4)
        self.regs.update(RCX=at, RDX=1)
        with self.assertRaisesRegex(ValueError, 'constructor arguments'):
            self.codec.observed(self.codec.archive['constructor'])
        self.regs['RDX'] = 0xffffffff; self.put(self.regs['RSP'], 0xcafe)
        self.codec.observed(self.codec.archive['constructor'])
        self.assertEqual(self.codec.result['archive_flags_bits'], 0xffffffff)

    def test_growth_rejects_reallocation_and_foreign_caller(self):
        at = self.codec.archives['inner']['object']; self.regs.update(RCX=at+0x18, RDX=1024)
        with self.assertRaises(ValueError): self.codec.growth(None)
        self.role = 'wire.archive.raw'; self.put(at+0x30, 1024, 4); self.put(at+0x18, 0xdead)
        with self.assertRaises(ValueError): self.codec.growth(None)

    def test_sized_delete_selects_archive_and_cpp_ledger_kinds(self):
        pointer = self.archive('outer', b'abc'); self.role = 'wire.cleanup'
        self.codec.active_cleanup = 'outer'
        self.regs.update(RCX=pointer, RDX=1023)
        with self.assertRaises(ValueError): self.codec.cpp_free(None)
        self.regs['RDX'] = 1024; self.codec.cpp_free(None)
        self.assertIn(pointer, self.state['freed'])
        with self.assertRaises(ValueError): self.codec.cpp_free(None)
        other = self.codec.new_allocation(23, 'cpp', 'writer'); self.regs.update(RCX=other, RDX=23)
        with self.assertRaises(ValueError): self.codec.cpp_free(None)
        self.role = 'wire.string-writer'; self.codec.cpp_free(None)

    def test_cleanup_cannot_free_another_archive_from_same_ledger(self):
        outer = self.archive('outer', b'abc'); inner = self.archive('inner', b'def')
        self.role = 'wire.cleanup'; self.codec.active_cleanup = 'outer'
        self.regs.update(RCX=inner, RDX=1024)
        with self.assertRaisesRegex(ValueError, 'active cleanup archive'):
            self.codec.cpp_free(None)
        self.regs['RCX'] = outer; self.codec.cpp_free(None)

    def test_transport_copies_owned_frame_and_protects_before_cleanup(self):
        frame = b'\x0b\0\0payload'; pointer = self.archive('outer', frame)
        self.put(self.codec.backend_object+0x248, C.KEY_BITS)
        self.regs.update(RCX=pointer+3, RDX=len(frame)-3, R8=pointer+3, R9=C.KEY_BITS)
        self.codec.transform(None)
        self.regs.update(RCX=self.codec.backend_object, RDX=pointer, R8=len(frame))
        self.codec.transport(None)
        self.assertEqual(self.codec.result['transport_hex'], frame.hex())
        self.assertEqual(self.finished & 255, 1)
        self.assertNotEqual(self.finished, 1)
        with self.assertRaises(ValueError): self.h.uc.mem_write(pointer, b'x')
        self.release(pointer, expected_kind='archive', expected_size=1024)
        self.assertEqual(bytes.fromhex(self.codec.result['transport_hex']), frame)
        with self.assertRaises(ValueError): self.h.uc.mem_read(pointer, 1)

    def test_transform_rejects_out_of_place_alias_or_wrong_key(self):
        pointer = self.archive('outer', b'\x0b\0\0payload'); self.put(self.codec.backend_object+0x248, C.KEY_BITS)
        self.regs.update(RCX=pointer+3, RDX=7, R8=pointer+4, R9=C.KEY_BITS)
        with self.assertRaises(ValueError): self.codec.transform(None)
        self.regs.update(R8=pointer+3, R9=0)
        with self.assertRaises(ValueError): self.codec.transform(None)

    def test_writer_observation_captures_actual_delta_and_preserves_prefix(self):
        pointer = self.archive('inner', b'\x03\0\xff\xff'); item = self.codec.archives['inner']
        self.regs.update(RCX=self.state['packet'], RDX=item['object'])
        self.put(self.regs['RSP'], 0xbeef)
        self.codec.observed(0x4000)
        payload = b'actual native bytes'; self.h.uc.mem_write(pointer+4, payload)
        self.put(item['object']+0x34, 4+len(payload), 4); self.put(item['object']+0x38, 4+len(payload), 4)
        self.regs['RAX'] = 1; self.codec.observed(0xbeef)
        self.assertEqual(self.codec.result['writer_delta_hex'], payload.hex())
        self.assertEqual(self.codec.result['writer_prefix_hex'], '0300ffff')
        with self.assertRaises(ValueError):
            self.h.uc.mem_write(pointer+4, b'changed after writer')
        self.assertEqual(self.h.uc.mem_read(pointer+4, len(payload)), payload)

    def test_packet_id_is_captured_only_after_actual_native_return(self):
        self.regs['RCX'] = self.state['packet']; self.put(self.regs['RSP'], 0xbabe)
        self.codec.observed(self.codec.backend['packet_id_getter'])
        self.assertIsNone(self.codec.result['request_id'])
        self.regs['RAX'] = 3; self.codec.observed(0xbabe)
        self.assertEqual(self.codec.result['request_id'], 3)

    def test_wrong_packet_id_return_is_observed_and_rejected(self):
        self.regs['RCX'] = self.state['packet']; self.put(self.regs['RSP'], 0xbabe)
        self.codec.observed(self.codec.backend['packet_id_getter'])
        self.regs['RAX'] = 4
        with self.assertRaisesRegex(ValueError, 'actual native packet-ID'):
            self.codec.observed(0xbabe)
        self.assertEqual(self.codec.result['request_id'], 4)

    def test_packet_writer_cannot_hide_changed_prefix(self):
        pointer = self.archive('inner', b'\x03\0\0\0'); item = self.codec.archives['inner']
        self.regs.update(RCX=self.state['packet'], RDX=item['object']); self.put(self.regs['RSP'], 0xbeef)
        self.codec.observed(0x4000); self.h.uc.mem_write(pointer, b'X'); self.regs['RAX'] = 1
        with self.assertRaises(ValueError): self.codec.observed(0xbeef)

    def test_memcpy_fixture_exposes_only_destination_window(self):
        self.role = 'wire.archive.raw'; self.regs.update(RCX=0x150010, RDX=0x150100, R8=3)
        self.h.uc.mem_write(0x150100, b'abc')
        self.assertEqual(self.codec.fixture_writes(0x8000, self.role), [(0x150010, 3)])
        self.codec.memcpy(None); self.assertEqual(self.h.uc.mem_read(0x150010, 3), b'abc')
        self.role = 'prepare'
        with self.assertRaises(ValueError): self.codec.memcpy(None)

    def test_observers_ignore_publisher_before_codec_seed(self):
        self.codec.spec = None
        self.codec.observed(0x1000)


if __name__ == '__main__': unittest.main()
