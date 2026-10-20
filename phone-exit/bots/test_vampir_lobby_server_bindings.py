import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import unittest

HERE = Path(__file__).parent / 'resource-tools/vampir'
ROOT = Path('F:/PhoneExit Resources/Vampir/code-clues')


def module(filename):
    spec = importlib.util.spec_from_file_location('test_lobby_binding_' + filename.replace('-', '_'), HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class LobbyServerBindingTests(unittest.TestCase):
    def test_discovery_reproduces_hash_bound_source(self):
        saved = json.loads((ROOT / 'lobby-server-bindings.json').read_text('utf-8'))
        self.assertEqual(module('build-lobby-server-bindings.py').build(), saved)
        raw = Path(saved['source']).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), saved['source_sha256'])
        for anchor in saved['anchors']:
            data = bytes.fromhex(anchor['bytes'])
            self.assertEqual(raw[anchor['file_offset']:anchor['file_offset'] + len(data)], data)
            self.assertEqual(hashlib.sha256(data).hexdigest(), anchor['sha256'])

    def test_native_ids_and_separate_lobby_serializers(self):
        saved = json.loads((ROOT / 'lobby-server-bindings.json').read_text('utf-8'))
        base = module('replay-version-packet-writer.py')
        em = base.Emulator()
        expected = {
            'PktLobbyVersion': (1, 0x145757490, 0x14574b090),
            'PktLobbyVersionResult': (2, 0x145757550, 0x14574b170),
            'PktLobbyServerListRead': (103, 0x145757260, 0x14574ad80),
            'PktLobbyServerListReadResult': (104, 0x1457572f0, 0x14574ae20),
        }
        for packet in saved['packets']:
            self.assertEqual((packet['packet_id'], packet['writer'], packet['reader']), expected[packet['name']])
            addr = packet['id_getter']
            self.assertEqual(em.raw[em.image.offset(addr - em.image.pe.base):
                em.image.offset(addr - em.image.pe.base) + 6], b'\xb8' + struct.pack('<I', packet['packet_id']) + b'\xc3')
            page = addr & ~4095
            if not any(lo <= page <= hi for lo, hi, _ in em.uc.mem_regions()):
                em.uc.mem_map(page, 4096)
                off = em.image.offset(page - em.image.pe.base)
                em.uc.mem_write(page, em.raw[off:off + 4096])
            em.ranges.append((addr, addr + 6))
            em.call(addr, em.scratch + 0x1000)
            self.assertEqual(em.uc.reg_read(base.x.UC_X86_REG_EAX), packet['packet_id'])
        self.assertNotEqual(expected['PktLobbyVersion'][1], 0x1456e5cf0)
        slots = struct.unpack('<9Q', bytes.fromhex(saved['peer_table']['bytes']))
        self.assertEqual((slots[1], slots[7], slots[8]), (0x1467aa090, 0x1467a9360, 0x1467aae20))
        self.assertEqual(saved['peer_table_load']['address'], 0x1467a7a75)


if __name__ == '__main__': unittest.main()
