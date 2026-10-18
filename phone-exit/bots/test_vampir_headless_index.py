"""Independent checks of the generated network evidence against installed bytes."""
import hashlib
import json
import os
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / '.tools/vampir-analysis'))
import capstone
from capstone.x86 import X86_OP_MEM, X86_REG_RIP


class HeadlessIndexTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
        path = root / 'code-clues/headless-network-index.json'
        if not path.exists():
            raise unittest.SkipTest('Generate headless-network-index.json first')
        cls.report = json.loads(path.read_text('utf-8'))
        cls.raw = Path(cls.report['source']).read_bytes()

    def test_source_and_fragment_integrity(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), self.report['sha256'])
        for fragment in self.report['fragments']:
            size = fragment['end_rva'] - fragment['begin_rva']
            offset = fragment['file_offset']
            content = self.raw[offset:offset + size]
            self.assertEqual(hashlib.sha256(content).hexdigest(), fragment['sha256'])
            self.assertEqual(b''.join(bytes.fromhex(i['bytes']) for i in fragment['instructions']), content)

    def test_literals_and_required_coverage(self):
        self.assertEqual(self.report['missing'], [])
        self.assertFalse(self.report['network_ready'])
        names = {s['name'] for s in self.report['symbols']}
        self.assertTrue({'PktLogin', 'PktLobbyLogin', 'PktCharacterSelect', 'PktCharacterPosition',
                         'PktPing', 'PktSkillStart', 'PacketDispatcher::Dispatch'} <= names)
        for symbol in self.report['symbols']:
            content = (symbol['name'] + '\0').encode(symbol['encoding'])
            offset = symbol['file_offset']
            self.assertEqual(self.raw[offset:offset + len(content)], content)
            self.assertEqual(content.hex(), symbol['bytes'])
            self.assertEqual(hashlib.sha256(content).hexdigest(), symbol['sha256'])

    def test_xrefs_redecode_from_original_bytes(self):
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        symbols = {s['name']: s for s in self.report['symbols']}
        self.assertGreater(len(self.report['xrefs']), 0)
        for xref in self.report['xrefs']:
            row = xref['instruction']
            original = self.raw[row['file_offset']:row['file_offset'] + len(bytes.fromhex(row['bytes']))]
            instruction, = decoder.disasm(original, row['address'])
            self.assertEqual(instruction.mnemonic, 'lea')
            targets = [instruction.address + instruction.size + op.mem.disp
                       for op in instruction.operands if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP]
            self.assertIn(symbols[xref['symbol']]['address'], targets)
            fragments = [f for f in self.report['fragments'] if f['root_begin_rva'] == xref['root_begin_rva']]
            self.assertTrue(any(row['address'] in {i['address'] for i in f['instructions']} for f in fragments))


if __name__ == '__main__':
    unittest.main()
