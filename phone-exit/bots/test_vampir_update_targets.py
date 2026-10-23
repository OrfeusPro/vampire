import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest

HERE = Path(__file__).parent / 'resource-tools/vampir'
spec = importlib.util.spec_from_file_location('update_targets_test', HERE / 'locate-release-update-targets.py')
tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)


class UpdateTargetsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = tool.load_native()

    def image(self, *, ambiguous=False, embedded=False):
        raw = bytearray(0x500)
        raw[:2] = b'MZ'
        struct.pack_into('<I', raw, 60, 0x80)
        raw[0x80:0x84] = b'PE\0\0'
        struct.pack_into('<H', raw, 0x86, 2)
        struct.pack_into('<H', raw, 0x94, 0xf0)
        struct.pack_into('<H', raw, 0x98, 0x20b)
        struct.pack_into('<Q', raw, 0xb0, 0x140000000)
        struct.pack_into('<II', raw, 0x98 + 112 + 3 * 8, 0x2050, 24 if ambiguous else 12)
        for number, name, rva, offset in ((0,b'.text',0x1000,0x200),(1,b'.rdata',0x2000,0x300)):
            at = 0x188 + number * 40
            raw[at:at+8] = name.ljust(8,b'\0')
            struct.pack_into('<IIII',raw,at+8,0x100,rva,0x100,offset)
        raw[0x300:0x30a] = b'I_fixture\0'
        for number, begin in enumerate((0x1000,0x1020) if ambiguous else (0x1000,)):
            offset = 0x200 + begin - 0x1000
            raw[offset:offset+16] = b'\x90'*15+b'\xc3'
            at = begin + (2 if embedded else 0)
            lea = b'\x48\x8d\x05'+struct.pack('<i',0x2000-at-7)
            code = b'\x48\xb8'+lea+b'\x90' if embedded else lea
            raw[offset:offset+len(code)] = code
            struct.pack_into('<III',raw,0x350+number*12,begin,begin+16,0x2080)
        raw[0x380:0x384] = b'\x01\0\0\0'
        return bytes(raw)

    def anchor(self):
        return dict(id='fixture',text='I_fixture',encoding='ascii',baseline_literal='0x140002000',
                    baseline_root='0x140001000',required_checks=['fixture-check'])

    def test_unique_reference_is_only_a_candidate(self):
        rows, gaps = tool.locate(self.image(),[self.anchor()],self.native)
        self.assertEqual(rows[0]['state'],'candidate')
        self.assertEqual(rows[0]['candidates'][0]['root'],'0x140001000')
        self.assertFalse(gaps)

    def test_ambiguity_and_missing_literal_stay_queued(self):
        rows, _ = tool.locate(self.image(ambiguous=True),[self.anchor()],self.native)
        self.assertEqual(rows[0]['state'],'requires_review')
        self.assertEqual(len(rows[0]['candidates']),2)
        rows, _ = tool.locate(self.image(),[dict(self.anchor(),text='Missing_fixture')],self.native)
        self.assertEqual(rows[0]['state'],'requires_review')
        self.assertFalse(rows[0]['candidates'])

    def test_lea_pattern_inside_immediate_is_not_an_instruction(self):
        rows, _ = tool.locate(self.image(embedded=True),[self.anchor()],self.native)
        self.assertFalse(rows[0]['candidates'])
        self.assertEqual(rows[0]['state'],'requires_review')
        self.assertTrue(rows[0]['unresolved'])

    def test_repeat_reuses_report_and_corrupt_source_preserves_report(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); raw=self.image(); sha=hashlib.sha256(raw).hexdigest()
            source=root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'
            source.parent.mkdir(parents=True); source.write_bytes(raw)
            targets=root/'targets.json'
            targets.write_text(json.dumps(dict(schema=1,baseline_sha256=sha,anchors=[self.anchor()])),encoding='utf-8')
            first=tool.run(root=root,targets_path=targets,source_sha=sha)
            report=Path(first['report']); saved=report.read_bytes()
            self.assertEqual(first,tool.run(root=root,targets_path=targets,source_sha=sha))
            self.assertEqual(json.loads(saved)['compatibility'],'not_established')
            source.write_bytes(raw+b'changed')
            with self.assertRaisesRegex(ValueError,'Source snapshot changed'):
                tool.run(root=root,targets_path=targets,source_sha=sha)
            self.assertEqual(report.read_bytes(),saved)

    def test_saved_plan_points_to_existing_tools_and_registered_checks(self):
        definition=json.loads((HERE/'knowledge/release-update-targets.json').read_text(encoding='utf-8'))
        checks={c['id'] for c in json.loads((HERE/'knowledge/research-checks.json').read_text(encoding='utf-8'))['checks']}
        for group in definition['anchors']+definition['manual_port_targets']:
            self.assertTrue(set(group.get('required_checks',[])) <= checks)
            for name in group.get('tools',[]): self.assertTrue((HERE/name).is_file(),name)

    def test_short_utf16_anchor_requires_a_literal_boundary(self):
        raw=bytearray(self.image());raw[0x300:0x306]='os\0'.encode('utf-16le')
        anchor=dict(self.anchor(),text='os',encoding='utf-16le',require_preceding_nul=True)
        rows,_=tool.locate(bytes(raw),[anchor],self.native)
        self.assertEqual(rows[0]['state'],'candidate')
        raw[0x2fe:0x300]=b'x\0'
        rows,_=tool.locate(bytes(raw),[anchor],self.native)
        self.assertFalse(rows[0]['literals'])

    def test_decode_budget_is_shared_between_anchors_and_overflow_stays_queued(self):
        raw=bytearray(0x2200);raw[:0x200]=self.image()[:0x200]
        for at,rva,offset in ((0x188,0x1000,0x200),(0x1b0,0x3000,0x1200)):
            struct.pack_into('<IIII',raw,at+8,0x1000,rva,0x1000,offset)
        struct.pack_into('<II',raw,0x98+112+3*8,0x3100,33*12)
        raw[0x1200:0x120a]=b'I_fixture\0';raw[0x1220:0x122a]=b'B_fixture\0'
        raw[0x1700:0x1704]=b'\x01\0\0\0'
        for number in range(33):
            begin=0x1000+16*number;offset=0x200+16*number
            target=0x3020 if number==32 else 0x3000
            raw[offset:offset+16]=b'\x48\x8d\x05'+struct.pack('<i',target-begin-7)+b'\x90'*8+b'\xc3'
            struct.pack_into('<III',raw,0x1300+12*number,begin,begin+16,0x3500)
        rows,gaps=tool.locate(bytes(raw),[self.anchor(),dict(self.anchor(),id='second',text='B_fixture')],self.native)
        self.assertEqual(rows[0]['state'],'requires_review')
        self.assertEqual(rows[1]['state'],'candidate')
        self.assertEqual(len(rows[0]['candidates'])+len(rows[1]['candidates']),32)
        self.assertEqual(len(gaps),1)
        self.assertIn('budget exhausted',rows[0]['unresolved'][0]['reason'])


if __name__=='__main__': unittest.main()
