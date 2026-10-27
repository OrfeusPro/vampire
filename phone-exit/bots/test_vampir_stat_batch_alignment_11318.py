"""Candidate matching keeps ambiguity, instruction topology and enum provenance separate."""
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

TOOL=Path(__file__).parent/'resource-tools/vampir/align-stat-batch-11318.py'
spec=importlib.util.spec_from_file_location('stat_batch_alignment_test',TOOL)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class StatBatchAlignment11318Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native=module.load('build-native-entry-code')
        cls.decoder=cls.native.capstone.Cs(cls.native.capstone.CS_ARCH_X86,cls.native.capstone.CS_MODE_64)
        cls.decoder.detail=True

    def rows(self,data,address):
        result=[]
        for ins in self.decoder.disasm(data,address):
            edge=ins.group(self.native.capstone.CS_GRP_CALL) or ins.group(self.native.capstone.CS_GRP_JUMP)
            target=ins.operands[0].imm if edge and ins.operands[0].type==self.native.X86_OP_IMM else None
            refs=[ins.address+ins.size+op.mem.disp for op in ins.operands
                if op.type==self.native.X86_OP_MEM and op.mem.base==self.native.X86_REG_RIP]
            result.append(dict(address=ins.address,bytes=bytes(ins.bytes).hex(),
                call=ins.group(self.native.capstone.CS_GRP_CALL),branch=ins.group(self.native.capstone.CS_GRP_JUMP),
                direct_target=target,rip_references=refs))
        return result

    def test_relocated_external_edges_and_rip_refs_are_only_shape_candidates(self):
        old=self.rows(bytes.fromhex('e810000000488b0510000000b804000000c3'),0x1000)
        new=self.rows(bytes.fromhex('e820000000488b0520000000b804000000c3'),0x2000)
        self.assertEqual(module.instruction_shape(old,self.decoder),module.instruction_shape(new,self.decoder))
        changed=self.rows(bytes.fromhex('e820000000488b0520000000b805000000c3'),0x2000)
        self.assertNotEqual(module.instruction_shape(old,self.decoder),module.instruction_shape(changed,self.decoder))

    def test_local_control_flow_and_incomplete_instruction_remain_distinct(self):
        a=self.rows(bytes.fromhex('74009090c3'),0x1000)
        b=self.rows(bytes.fromhex('74019090c3'),0x2000)
        self.assertNotEqual(module.instruction_shape(a,self.decoder),module.instruction_shape(b,self.decoder))
        bad=[dict(a[0],bytes='74')]
        with self.assertRaises(ValueError):module.instruction_shape(bad,self.decoder)

    def test_candidates_never_choose_first_or_closest_match(self):
        roots,unknown=module.select_candidates({'0x1000':['0x1001','0x2000'],
            '0x3000':[],'0x4000':['0x4010','0x4010']})
        self.assertEqual(roots,{'0x4000':'0x4010'})
        self.assertEqual(set(unknown),{'0x1000','0x3000'})

    def test_source_callback_slot_resolves_shapes_without_distance_heuristic(self):
        old=[dict(address=0x1000,mnemonic='lea',rip_references=[0x3000])]
        nearby=[dict(address=0x1010,mnemonic='lea',rip_references=[0x4000])]
        other=[dict(address=0x9000,mnemonic='lea',rip_references=[0x5000])]
        old_word=lambda address:{0x3010:0x7000}[address]
        new_word=lambda address:{0x4010:0x8001,0x5010:0x8000}[address]
        hits,proofs=module.callback_candidates(old,{'0x1010':nearby,'0x9000':other},
            0x7000,0x8000,old_word,new_word)
        self.assertEqual(hits,['0x9000'])
        self.assertEqual(proofs[0]['bindings'][0]['new_callback'],'0x8000')
        both=lambda address:0x8000
        hits,_=module.callback_candidates(old,{'0x1010':nearby,'0x9000':other},
            0x7000,0x8000,old_word,both)
        self.assertEqual(hits,['0x1010','0x9000'])
        self.assertEqual(module.select_candidates({'0x1000':hits})[0],{})

    def test_missing_old_callback_binding_never_fabricates_a_resolution(self):
        old=[dict(address=0x1000,mnemonic='lea',rip_references=[0x3000])]
        rows={'0x1010':[dict(address=0x1010,mnemonic='lea',rip_references=[0x4000])],
              '0x9000':[dict(address=0x9000,mnemonic='lea',rip_references=[0x5000])]}
        hits,proofs=module.callback_candidates(old,rows,0x7000,0x8000,
            lambda address:0x7001,lambda address:0x8000)
        self.assertEqual(hits,sorted(rows));self.assertEqual(proofs,[])

    def test_changed_source_rejects_before_image_decode_or_artifact_write(self):
        image=Mock();workflow=Mock()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path=root/'client-code-snapshots'/module.OLD/'ProjectRED-Win64-Shipping.exe'
            path.parent.mkdir(parents=True);path.write_bytes(b'changed fixture')
            with patch.object(module,'load',side_effect=[SimpleNamespace(Image=image),workflow]):
                with self.assertRaisesRegex(ValueError,'source SHA changed'):module.run(root)
        image.assert_not_called();workflow.snapshot.assert_not_called()

    def test_estat_ambiguity_duplicates_and_changed_vital_ids_do_not_admit_runtime(self):
        rows=[dict(name='EStat::'+name,value=value,descriptor_offset=i*16,name_offset=100+i*16)
            for i,(name,value) in enumerate((('Level',3),('Hp',4),('MaxHp',5),('Mp',9),('MaxMp',10)))]
        actual,known=module.estat_rows({'EStat':rows},[])
        self.assertEqual(actual,rows);self.assertTrue(known)
        changed=[dict(row) for row in rows];changed[0]['value']=20
        self.assertFalse(module.estat_rows({'EStat':changed},[])[1])
        with self.assertRaises(ValueError):module.estat_rows({'EStat':rows},[{'enum':'EStat'}])
        with self.assertRaises(ValueError):module.estat_rows({'EStat':rows+[rows[0]]},[])
        with self.assertRaises(ValueError):module.estat_rows({},[])


if __name__=='__main__':unittest.main()
