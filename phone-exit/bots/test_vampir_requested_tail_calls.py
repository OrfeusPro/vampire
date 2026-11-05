import unittest
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest.mock import Mock, patch
from test_vampir_update_contracts import load


class RequestedTailCallsTests(unittest.TestCase):
    def test_declared_store_model_checks_proof_source_and_body(self):
        tool=load('collect-requested-functions');native=load('build-native-entry-code')
        sha='b'*64;at=0x1445523a0;raw=bytes.fromhex('890d00000000c3')
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            proof=dict(recipe='sdk-batch-transfer-v1',source_sha256=sha,unresolved={},semantic_verification=False,
                leaves=[dict(target=hex(at),target_bytes=raw.hex(),size=7,kind='leaf')])
            payload=json.dumps(proof).encode();digest=hashlib.sha256(payload).hexdigest()
            path=root/'knowledge/sdk-batch-transfer-v1'/digest/'manifest.json'
            path.parent.mkdir(parents=True);path.write_bytes(payload)
            model=dict(source_sha256=sha,address=hex(at),bytes=raw.hex(),kind='rip-u32-store-return',
                proof=dict(path=str(path),sha256=digest))
            registry=root/'models.json';registry.write_text(json.dumps(dict(schema=1,models=[model])))
            image=SimpleNamespace(pe=SimpleNamespace(base=0x140000000),data=raw,offset=lambda rva:0)
            self.assertEqual(tool.declared_leaf_tails(native,image,sha,registry,root),{at:raw.hex()})
            self.assertEqual(tool.declared_leaf_tails(native,image,'a'*64,registry,root),{})
            image.data=b'\x90'+raw[1:]
            with self.assertRaisesRegex(ValueError,'source or returning-store'):tool.declared_leaf_tails(native,image,sha,registry,root)
            image.data=raw;path.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'proof SHA'):tool.declared_leaf_tails(native,image,sha,registry,root)

    def test_reviewed_sdk_leaf_requires_exact_source_and_bounded_return(self):
        tool=load('collect-requested-functions');native=load('build-native-entry-code')
        sha='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
        at=0x144552540;raw=bytes.fromhex('890d9a5bc306c3')
        tool.REVIEWED_LEAF_TAILS={sha:{at:raw.hex()}}
        image=SimpleNamespace(pe=SimpleNamespace(base=0x140000000),data=raw,offset=lambda rva:0)
        self.assertEqual(tool.checked_leaf_tails(native,image,sha),{at:raw.hex()})
        self.assertEqual(tool.checked_leaf_tails(native,image,'0'*64),{})
        image.data=b'\x90'+raw[1:]
        with self.assertRaisesRegex(ValueError,'source differs'):tool.checked_leaf_tails(native,image,sha)
        for encoded in ('e900000000c3','9090','c3c3','90'*17):
            image.data=bytes.fromhex(encoded)
            with patch.dict(tool.REVIEWED_LEAF_TAILS,{sha:{at:encoded}},clear=True):
                with self.assertRaisesRegex(ValueError,'budget|control flow|Unreviewed'):
                    tool.checked_leaf_tails(native,image,sha)

    def test_archive_cleanup_tail_requires_exact_source_bytes_and_finite_target(self):
        tool=load('collect-requested-functions');native=load('build-native-entry-code')
        sha='03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
        at=0x144aad2c0;encoded='488d05f962bc04488901e921fcffff';raw=bytes.fromhex(encoded)
        tool.REVIEWED_LEAF_TAILS={sha:{at:encoded}}
        image=SimpleNamespace(pe=SimpleNamespace(base=0x140000000),data=raw,offset=lambda rva:0)
        leaves=tool.checked_leaf_tails(native,image,sha)
        self.assertEqual(leaves,{at:encoded})
        self.assertNotIn(0x144aacef0,leaves) # No recursive export/discovery.
        row=self.row(address=0x144aac859,direct_target=at,bytes='e9620a0000')
        self.assertEqual(tool.reviewed_tail_calls([row],set(leaves)),[
            dict(address='0x144aac859',target=hex(at),bytes='e9620a0000')])
        image.data=raw[:-1]+b'\x00'
        with self.assertRaisesRegex(ValueError,'source differs'):
            tool.checked_leaf_tails(native,image,sha)
        for source,entry,value in ((sha,at+1,encoded),('0'*64,at,encoded),
                (sha,at,encoded[:-2]+'00')):
            with self.subTest(source=source,entry=entry),patch.object(tool,'REVIEWED_LEAF_TAILS',{source:{entry:value}}):
                with self.assertRaisesRegex(ValueError,'Unreviewed'):
                    tool.checked_leaf_tails(native,image,source)

    def test_archive_cleanup_model_rejects_decoder_target_or_table_drift(self):
        tool=load('collect-requested-functions');native=load('build-native-entry-code')
        sha='03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
        raw=bytes.fromhex(tool.REVIEWED_LEAF_TAILS[sha][0x144aad2c0])
        tool.REVIEWED_LEAF_TAILS={sha:{0x144aad2c0:raw.hex()}}
        image=SimpleNamespace(pe=SimpleNamespace(base=0x140000000),data=raw,offset=lambda rva:0)
        real=native.capstone.Cs
        for drift in ('table','target'):
            def changed(*args):
                decoder=real(*args);decoder.detail=True
                def disasm(code,at):
                    rows=list(decoder.disasm(code,at));out=[]
                    for i,r in enumerate(rows):
                        operands=r.operands
                        if drift=='table' and i==0:
                            operands=[operands[0],SimpleNamespace(mem=SimpleNamespace(disp=0))]
                        if drift=='target' and i==2:operands=[SimpleNamespace(imm=0)]
                        out.append(SimpleNamespace(mnemonic=r.mnemonic,op_str=r.op_str,address=r.address,size=r.size,operands=operands))
                    return out
                return SimpleNamespace(disasm=disasm,detail=False)
            with self.subTest(drift=drift),patch.object(native.capstone,'Cs',side_effect=changed):
                with self.assertRaisesRegex(ValueError,'control flow'):
                    tool.checked_leaf_tails(native,image,sha)

    def test_sized_free_tail_requires_exact_source_bytes_and_finite_target(self):
        tool=load('collect-requested-functions');native=load('build-native-entry-code')
        sha='03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
        at=0x141431fe0;target=0x1414830e0;encoded='e9fb100500';raw=bytes.fromhex(encoded)
        self.assertEqual(tool.REVIEWED_LEAF_TAILS[sha][at],encoded)
        tool.REVIEWED_LEAF_TAILS={sha:{at:encoded}}
        image=SimpleNamespace(pe=SimpleNamespace(base=0x140000000),data=raw,offset=lambda rva:0)
        leaves=tool.checked_leaf_tails(native,image,sha)
        self.assertEqual(leaves,{at:encoded})
        self.assertNotIn(target,leaves)
        caller=self.row(address=0x1445ea11f,direct_target=at,bytes='e9bc7ee4fc')
        self.assertEqual(tool.reviewed_tail_calls([caller],set(leaves)),[
            dict(address='0x1445ea11f',target=hex(at),bytes='e9bc7ee4fc')])
        # The capsule's own E9 target never becomes an inferred export/model.
        self.assertEqual(tool.reviewed_tail_calls([
            self.row(address=at,direct_target=target,bytes=encoded)],set(leaves)),[])
        image.data=raw[:-1]+b'\x01'
        with self.assertRaisesRegex(ValueError,'source differs'):
            tool.checked_leaf_tails(native,image,sha)
        for source,entry,value in ((sha,at+1,encoded),('0'*64,at,encoded),
                (sha,at,'e9fc100500')):
            with self.subTest(source=source,entry=entry,value=value),patch.object(
                    tool,'REVIEWED_LEAF_TAILS',{source:{entry:value}}):
                with self.assertRaisesRegex(ValueError,'Unreviewed'):
                    tool.checked_leaf_tails(native,image,source)

    def test_sized_free_model_rejects_decoded_target_and_body_drift(self):
        tool=load('collect-requested-functions');native=load('build-native-entry-code')
        sha='03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
        at=0x141431fe0;encoded='e9fb100500';raw=bytes.fromhex(encoded)
        tool.REVIEWED_LEAF_TAILS={sha:{at:encoded}}
        image=SimpleNamespace(pe=SimpleNamespace(base=0x140000000),data=raw,offset=lambda rva:0)
        real=native.capstone.Cs
        for drift in ('target','operand_text','address','length','count'):
            def changed(*args):
                decoder=real(*args);decoder.detail=True
                def disasm(code,entry):
                    row=list(decoder.disasm(code,entry))[0]
                    values=dict(mnemonic=row.mnemonic,op_str=row.op_str,address=row.address,
                                size=row.size,operands=row.operands)
                    if drift=='target':values['operands']=[SimpleNamespace(imm=0x1414830e1)]
                    if drift=='operand_text':values['op_str']='0x1414830e1'
                    if drift=='address':values['address']+=1
                    if drift=='length':values['size']=4
                    out=[SimpleNamespace(**values)]
                    return out*2 if drift=='count' else out
                return SimpleNamespace(disasm=disasm,detail=False)
            with self.subTest(drift=drift),patch.object(native.capstone,'Cs',side_effect=changed):
                with self.assertRaisesRegex(ValueError,'control flow'):
                    tool.checked_leaf_tails(native,image,sha)

    def row(self, **updates):
        result = dict(address=0x100, mnemonic='jmp', branch=True, call=False, direct_target=0x200, bytes='e9fb000000')
        result.update(updates)
        return result

    def test_only_explicit_external_e9_tail_is_modelled(self):
        tool = load('collect-requested-functions')
        rows = [self.row(), self.row(address=0x110, mnemonic='jne', bytes='0f85ea000000'),
                self.row(address=0x120, direct_target=0x300), self.row(address=0x130, bytes='ffe0')]
        self.assertEqual(tool.reviewed_tail_calls(rows, {0x100, 0x200}),
                         [dict(address='0x100', target='0x200', bytes='e9fb000000')])
        self.assertEqual(tool.reviewed_tail_calls(rows, {0x100}), [])

    def test_local_branch_is_not_reclassified(self):
        tool = load('collect-requested-functions')
        self.assertEqual(tool.reviewed_tail_calls([self.row(), self.row(address=0x200)], {0x200}), [])

    def test_partial_linear_fragment_never_supplies_tail_models(self):
        tool=load('collect-requested-functions')
        native=SimpleNamespace(decode_ranges=Mock(side_effect=ValueError('Fragment not fully decoded')))
        tails,scan=tool.scan_tail_calls(native,object(),(1,2,3),{0x200})
        self.assertEqual(tails,[]);self.assertEqual(scan['state'],'deferred_to_ghidra')
        self.assertFalse(scan['tail_models_applied'])
        native.decode_ranges=Mock(side_effect=ValueError('Invalid unwind chain'))
        with self.assertRaisesRegex(ValueError,'Invalid unwind chain'):tool.scan_tail_calls(native,object(),(1,2,3),{0x200})

    def test_complete_scan_preserves_only_reviewed_explicit_tails(self):
        tool=load('collect-requested-functions')
        native=SimpleNamespace(decode_ranges=lambda image,roots:[dict(instructions=[self.row()])])
        tails,scan=tool.scan_tail_calls(native,object(),(1,2,3),{0x200})
        self.assertEqual(len(tails),1);self.assertEqual(scan,dict(state='complete'))


if __name__ == '__main__':
    unittest.main()
