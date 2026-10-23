import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_vampir_update_targets as fixture

HERE = Path(__file__).parent / 'resource-tools/vampir'


class RequestedFunctionTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        spec = importlib.util.spec_from_file_location('requested_index_test', HERE/'knowledge-index.py')
        self.index = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.index)
        self.tool = self.index.extension('collect-requested-functions')
        raw = fixture.UpdateTargetsTests().image()
        sha = hashlib.sha256(raw).hexdigest()
        self.source = self.root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'
        self.source.parent.mkdir(parents=True); self.source.write_bytes(raw)
        self.at = '0x140001000'
        self.request = dict(source_sha256=sha, source=str(self.source), functions=[dict(address=self.at)])
        self.args = SimpleNamespace(root=self.root, request=self.root/'request.json')
        self.args.request.write_text(json.dumps(self.request),encoding='utf-8')
        lock=json.loads((HERE/'ghidra-tools.lock.json').read_text(encoding='utf-8'))
        for name in ('ghidra','jdk'):
            dest=self.root/'tools/ghidra'/lock[name]['directory']/'.phoneexit-verified.json'
            dest.parent.mkdir(parents=True); dest.write_text(json.dumps(lock[name]),encoding='utf-8')

    def fake_jvm(self, command, *, env, stdout, stderr):
        self.assertIn('-noanalysis',command)
        self.assertEqual(command[-1],self.at)
        self.assertNotIn('-analysisTimeoutPerFile',command)
        output=Path(command[command.index('-postScript')+3])
        (Path(command[1])/'RequestedRelease.gpr').touch()
        (output/'details.json').write_text(json.dumps(dict(new_source_sha256=self.request['source_sha256'],
            functions=[dict(address=self.at,body_bytes=7,instructions=[dict(bytes='488d05f90f0000')])])),encoding='utf-8')
        stdout.write('Save succeeded for processed file: fixture\n' if '-process' in command else 'Save succeeded for: fixture\n')
        return SimpleNamespace(returncode=0)

    def test_import_then_reuse_only_explicit_functions_and_receipts(self):
        with patch.object(self.tool.subprocess,'run',side_effect=self.fake_jvm) as run:
            first=self.tool.collect(self.index.api(),self.args,self.request,[self.at])
            self.assertFalse(first['reused_project'])
            self.assertIn('-import',run.call_args.args[0])
            second=self.tool.collect(self.index.api(),self.args,self.request,[self.at])
            self.assertTrue(second['reused_project'])
            self.assertIn('-process',run.call_args.args[0])
        provenance=Path(second['export']).parent/'provenance.json'
        self.assertFalse(json.loads(provenance.read_text(encoding='utf-8'))['roles_transferred'])

    def test_non_root_or_extra_address_never_launches_jvm(self):
        with patch.object(self.tool.subprocess,'run') as run:
            with self.assertRaises(ValueError): self.tool.collect(self.index.api(),self.args,self.request,['0x140001001'])
            changed=dict(self.request,functions=[dict(address='0x140001001')])
            with self.assertRaisesRegex(ValueError,'not an unwind root'):
                self.tool.collect(self.index.api(),self.args,changed,['0x140001001'])
            run.assert_not_called()

    def test_incomplete_project_is_queued_without_reimport(self):
        dest=self.root/'ghidra/request-projects'/self.request['source_sha256']
        dest.mkdir(parents=True); (dest/'RequestedRelease.gpr').touch()
        with patch.object(self.tool.subprocess,'run') as run:
            result=self.tool.collect(self.index.api(),self.args,self.request,[self.at])
        self.assertEqual(result['state'],'queued'); run.assert_not_called()

    def test_changed_snapshot_is_rejected_before_jvm(self):
        self.source.write_bytes(b'changed')
        with patch.object(self.tool.subprocess,'run') as run:
            with self.assertRaisesRegex(ValueError,'Source changed'):
                self.tool.collect(self.index.api(),self.args,self.request,[self.at])
            run.assert_not_called()

    def test_one_byte_placeholder_is_not_sealed_as_complete_export(self):
        def partial(command, **kwargs):
            result=self.fake_jvm(command, **kwargs)
            output=Path(command[command.index('-postScript')+3])/'details.json'
            data=json.loads(output.read_text(encoding='utf-8'))
            data['functions'][0]['body_bytes']=1
            output.write_text(json.dumps(data),encoding='utf-8')
            return result
        with patch.object(self.tool.subprocess,'run',side_effect=partial):
            with self.assertRaisesRegex(ValueError,'coverage is incomplete'):
                self.tool.collect(self.index.api(),self.args,self.request,[self.at])
        self.assertFalse(list((self.root/'ghidra/request-exports').glob('*/*/provenance.json')))

    def test_real_exports_match_snapshots_and_instruction_shapes(self):
        native=self.index.extension('build-native-entry-code')
        old_sha='98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'
        new_sha='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
        path=native.ROOT/'ghidra/request-exports'/new_sha/'run-e6508b986175/details.json'
        self.assertEqual(self.index.digest(path),'c9923787de462d4bdca9e03cdcf59a9ff333003cae0b574e9ee43c74fb71e101')
        report=json.loads(path.read_text(encoding='utf-8'))
        images=[]
        for sha in (old_sha,new_sha):
            source=native.ROOT/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'
            self.assertEqual(self.index.digest(source),sha)
            images.append(native.Image(source.read_bytes()))
        decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);decoder.detail=True
        for old,new,count in ((0x1444ef840,0x1444ee9d0,652),(0x144504980,0x144503b10,679)):
            normalized=[]
            for image,entry in zip(images,(old,new)):
                root=image.roots[image.containing(entry)]
                rows=[row for fragment in native.decode_ranges(image,{root}) for row in fragment['instructions']]
                self.assertEqual(len(rows),count)
                shape=[]
                for row in rows:
                    raw=bytes.fromhex(row['bytes']);ins=next(decoder.disasm(raw,row['address']));masked=bytearray(raw)
                    if row['rip_references']: masked[ins.disp_offset:ins.disp_offset+ins.disp_size]=bytes(ins.disp_size)
                    if row['direct_target'] is not None: masked[ins.imm_offset:ins.imm_offset+ins.imm_size]=bytes(ins.imm_size)
                    target=row['direct_target']
                    local=target-entry if target is not None and image.pe.base+root[0]<=target<image.pe.base+root[1] else None
                    shape.append((bytes(masked).hex(),local))
                    if image is images[1]:
                        function=next(f for f in report['functions'] if int(f['address'],16)==entry)
                        exported=next(r for r in function['instructions'] if int(r['address'],16)==row['address'])
                        self.assertEqual(exported['bytes'],raw.hex())
                normalized.append(shape)
            self.assertEqual(normalized[0],normalized[1])
        # This deliberately does not assert target identities, global contents or SDK behavior.


if __name__=='__main__': unittest.main()
