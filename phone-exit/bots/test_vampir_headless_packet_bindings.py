"""Audit packet bindings from original PE bytes, including native ID execution."""
import hashlib
import json
import os
import struct
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / '.tools/vampir-analysis'))
import capstone
import unicorn
from unicorn import x86_const as x
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP


class PacketBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
        path = root / 'code-clues/headless-packet-bindings.json'
        if not path.exists():
            raise unittest.SkipTest('Generate headless-packet-bindings.json first')
        cls.report = json.loads(path.read_text('utf-8'))
        cls.raw = Path(cls.report['source']).read_bytes()
        pe = struct.unpack_from('<I', cls.raw, 60)[0]
        count = struct.unpack_from('<H', cls.raw, pe+6)[0]
        optional_size = struct.unpack_from('<H', cls.raw, pe+20)[0]
        cls.base = struct.unpack_from('<Q', cls.raw, pe+24+24)[0]
        cls.sections = [struct.unpack_from('<IIII', cls.raw, pe+24+optional_size+40*i+8)
                        for i in range(count)]
        cls.decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cls.decoder.detail = True
        cls.packets = {p['name']: p for p in cls.report['packets']}

    def offset(self, address):
        rva = address-self.base
        for _, start, size, raw in self.sections:
            if start <= rva < start+size:
                return raw+rva-start
        self.fail('Address is not file-backed')

    def instruction(self, row):
        offset = self.offset(row['address'])
        content = bytes.fromhex(row['bytes'])
        self.assertEqual(offset, row['file_offset'])
        self.assertEqual(self.raw[offset:offset+len(content)], content)
        return next(self.decoder.disasm(content, row['address']))

    def test_provenance_and_all_evidence_bytes(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), self.report['sha256'])
        self.assertFalse(self.report['network_ready'])
        for row in self.report['data_anchors'] + self.report['leaves']:
            content = bytes.fromhex(row['bytes'])
            offset = self.offset(row['address'])
            self.assertEqual(self.raw[offset:offset+len(content)], content)
            self.assertEqual(hashlib.sha256(content).hexdigest(), row['sha256'])
        for f in self.report['fragments']:
            content = self.raw[f['file_offset']:f['file_offset']+f['end_rva']-f['begin_rva']]
            self.assertEqual(hashlib.sha256(content).hexdigest(),f['sha256'])
            self.assertEqual(b''.join(bytes.fromhex(i['bytes']) for i in f['instructions']),content)

    def test_table_slots_and_native_id_getters(self):
        uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        scratch = 0x20000000
        uc.mem_map(scratch, 0x2000)
        pages = set()
        for packet in self.report['packets']:
            table = self.offset(packet['vtable'])
            for slot, target in [(0x10,packet['writer']),(0x20,packet['reader']),
                                 (0x28,packet['id_getter']),(0x38,packet['name_getter'])]:
                self.assertEqual(struct.unpack_from('<Q',self.raw,table+slot)[0],target)
            address = packet['id_getter']
            page = address & ~4095
            if page not in pages:
                uc.mem_map(page,4096)
                offset = self.offset(page)
                uc.mem_write(page,self.raw[offset:offset+4096])
                uc.mem_protect(page,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
                pages.add(page)
            uc.mem_write(scratch+0x1000,struct.pack('<Q',scratch))
            uc.reg_write(x.UC_X86_REG_RSP,scratch+0x1000)
            uc.reg_write(x.UC_X86_REG_RAX,0xffffffffffffffff)
            uc.emu_start(address,scratch,count=4)
            self.assertEqual(uc.reg_read(x.UC_X86_REG_RIP),scratch)
            self.assertEqual(uc.reg_read(x.UC_X86_REG_RAX),packet['packet_id'])

    def test_constructor_boundaries_and_vptr_installation(self):
        for packet in self.report['packets']:
            self.assertTrue(packet['constructor_calls'])
            for call in packet['constructor_calls']:
                i = self.instruction(call)
                self.assertEqual(i.mnemonic,'call')
                self.assertEqual(i.operands[0].type,X86_OP_IMM)
                self.assertEqual(i.operands[0].imm,packet['constructor'])
            lea,store = [self.instruction(row) for row in packet['vptr_installation']]
            self.assertEqual(lea.mnemonic,'lea')
            targets = [lea.address+lea.size+op.mem.disp for op in lea.operands
                       if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP]
            self.assertEqual(targets,[packet['vtable']])
            self.assertEqual((store.mnemonic,store.op_str),('mov','qword ptr [rcx], rax'))

    def test_result_registration_and_context_collisions(self):
        registrations = {r['name']:r for r in self.report['registrations']}
        self.assertEqual(set(registrations),{n for n in self.packets if n.endswith('Result')})
        for name,r in registrations.items():
            ctor = self.instruction(r['constructor_call'])
            registration = self.instruction(r['registration_call'])
            self.assertEqual(ctor.operands[0].imm,self.packets[name]['constructor'])
            self.assertEqual(registration.operands[0].imm,r['registration_function'])
            self.assertEqual(struct.unpack_from('<Q',self.raw,self.offset(r['handler_vtable'])+16)[0],r['on_handler'])
        # Collisions are real; global ID-only dispatch would discard a distinct schema.
        for a,b in [('PktLogin','PktLobbyLogin'),('PktLoginResult','PktLobbyLoginResult')]:
            self.assertEqual(self.packets[a]['packet_id'],self.packets[b]['packet_id'])
            self.assertNotEqual(self.packets[a]['vtable'],self.packets[b]['vtable'])
            self.assertNotEqual(self.packets[a]['reader'],self.packets[b]['reader'])
        self.assertNotEqual(registrations['PktLoginResult']['registration_function'],
                            registrations['PktLobbyLoginResult']['registration_function'])


if __name__ == '__main__':
    unittest.main()
