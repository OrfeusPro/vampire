"""Selected-source admission and adversarial discovery fixtures; no native run."""
import copy
from contextlib import closing
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import struct
import tempfile
import unittest

HERE = Path(__file__).resolve().parent / 'resource-tools' / 'vampir'
SPEC = importlib.util.spec_from_file_location('knowledge_scope_v2_tests', HERE / 'knowledge-scope-v2.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(MODULE.canonical(value))
    return dict(path=str(path.resolve()), sha256=sha(path.read_bytes()))


def pe_bytes():
    raw = bytearray(0x600)
    raw[:2] = b'MZ';struct.pack_into('<I',raw,60,0x80)
    raw[0x80:0x84] = b'PE\0\0';struct.pack_into('<H',raw,0x86,2)
    struct.pack_into('<H',raw,0x94,0xf0);struct.pack_into('<H',raw,0x98,0x20b)
    struct.pack_into('<Q',raw,0xb0,0x140000000)
    for pos,name,rva,offset in ((0x188,b'.text',0x1000,0x200),(0x1b0,b'.rdata',0x3000,0x400)):
        raw[pos:pos+len(name)] = name
        struct.pack_into('<IIII',raw,pos+8,0x200,rva,0x200,offset)
    raw[0x200:0x206] = bytes.fromhex('b82a000000c3')
    raw[0x210:0x213] = bytes.fromhex('33c0c3')
    raw[0x220:0x225] = bytes.fromhex('7402c390c3')
    return bytes(raw)


class KnowledgeScopeV2(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)/'resources';self.knowledge = Path(self.temp.name)/'knowledge'
        self.root.mkdir();self.knowledge.mkdir()
        self.raw = pe_bytes();self.source_sha = sha(self.raw)
        self.source = self.root/'client-code-snapshots'/self.source_sha/'ProjectRED-Win64-Shipping.exe'
        self.source.parent.mkdir(parents=True);self.source.write_bytes(self.raw)
        self.first,self.second = '0x140001000','0x140001010'
        self.folder = self.root/'ghidra/request-exports'/self.source_sha/'run-fixture'
        self.folder.mkdir(parents=True)
        self.report = self.folder/'details.json';self.receipt = self.folder/'provenance.json'
        self.pseudo = self.folder/'first.c';self.pseudo.write_text('int f(){ return 42; }',encoding='utf-8')
        self.rows = [self.row(self.first,'first.c',[('b82a000000','MOV EAX,0x2a'),('c3','RET')])]
        self.data = dict(new_source_sha256=self.source_sha,functions=self.rows)
        self.publish()
        write_json(self.knowledge/'questions.json',dict(questions=[dict(id='q',next_action='Explicit test')]))

    def row(self, at, pseudo, instructions):
        position = int(at,16);rows=[]
        for raw,text in instructions:
            rows.append(dict(address=hex(position),bytes=raw,text=text,references=[]))
            position += len(bytes.fromhex(raw))
        return dict(address=at,name='candidate',decompilation_completed=True,message='',
            pseudocode_file=pseudo,decompiler_block_starts=[at],block_coverage_complete=True,
            body_bytes=position-int(at,16),instructions=rows)

    def publish(self, receipt_extra=None):
        self.report_pointer=write_json(self.report,self.data)
        files={self.report.name:self.report_pointer['sha256']}
        def row_outputs(row):
            name=row.get('pseudocode_file')
            if name:
                path=self.report.parent/name
                if path.is_file():files[str(path.relative_to(self.receipt.parent)).replace('\\','/')]=sha(path.read_bytes())
        for row in self.data.get('functions',[]):row_outputs(row)
        for pair in self.data.get('pairs',[]):
            for side in ('old','new'):row_outputs(pair[side])
        self.receipt_data=dict(files=files,source_sha256=self.source_sha,source=str(self.source.resolve()))
        self.receipt_data.update(receipt_extra or {})
        self.receipt_pointer=write_json(self.receipt,self.receipt_data)
        self.hint=dict(report=self.report_pointer,receipt=self.receipt_pointer)

    def scope(self, addresses=None, **kwargs):
        return MODULE.Scope.open(self.root,self.knowledge,self.source_sha,
            addresses or [self.first],{},question_id='q',**kwargs)

    def discovery_db(self, *, body='forged', completed=0, observed_at=None):
        dbpath=self.root/'search.sqlite3'
        with closing(sqlite3.connect(dbpath)) as db, db:
            db.executescript('PRAGMA user_version=2;'
                'CREATE TABLE artifacts(path,sha,receipt,receipt_sha,state,detail);'
                'CREATE TABLE observations(artifact,source_sha,address,variant,name,pseudocode,ordinal);'
                'CREATE TABLE variants(id,source_sha,address,pseudocode_sha,completed,message,body_json);')
            db.execute('INSERT INTO artifacts VALUES(?,?,?,?,?,?)',(str(self.report),self.report_pointer['sha256'],
                str(self.receipt),self.receipt_pointer['sha256'],'ready','untrusted'))
            db.execute('INSERT INTO observations VALUES(?,?,?,?,?,?,?)',(str(self.report),self.source_sha,
                observed_at or self.first,'fake','fake','private-capture.bin',200))
            db.execute('INSERT INTO variants VALUES(?,?,?,?,?,?,?)',('fake',self.source_sha,self.first,
                '0'*64,completed,'ready',body))
        return dbpath

    def test_ready_reconstructed_from_checked_outputs_not_discovery_body_or_status(self):
        scope=self.scope();hints=scope.discover_candidates(self.discovery_db())
        selected=scope.select(hints)
        self.assertEqual(selected[0]['state'],'ready')
        variant=selected[0]['variants'][0]
        self.assertNotEqual(variant['variant'],'fake')
        self.assertEqual(json.loads(variant['body_json'])['instructions'],self.rows[0]['instructions'])
        self.assertEqual(variant['pseudocode'],str(self.pseudo.resolve()))
        receipt=scope.finish_barrier()
        self.assertEqual(receipt['inputs'][str(self.source.resolve())],self.source_sha)
        self.assertEqual(receipt['validation_scope'],'selected_materials_only')
        self.assertFalse(receipt['global_history_verified'])
        self.assertFalse(receipt['coverage']['client_semantics_proven'])
        self.assertEqual(receipt['metrics']['scoped_pe_builds'],1)

    def test_order_and_scope_budget_are_explicit(self):
        self.assertEqual(self.scope([self.second,self.first]).addresses,[self.second,self.first])
        for addresses in ([],[self.first,self.first],[hex(0x140000000+i) for i in range(33)]):
            with self.subTest(addresses=addresses),self.assertRaises(ValueError):
                MODULE.Scope.open(self.root,self.knowledge,self.source_sha,addresses,{})

    def test_missing_index_or_forged_address_is_requires_discovery_not_absence_proof(self):
        for index in (None,self.root/'missing.sqlite3',self.discovery_db(observed_at=self.second)):
            scope=self.scope();row=scope.select(scope.discover_candidates(index))[0]
            self.assertEqual(row['state'],'candidate_missing_requires_discovery')
            receipt=scope.finish_barrier()
            self.assertIn(str(self.source.resolve()),receipt['inputs'])
            self.assertFalse(receipt['global_history_verified'])

    def test_source_is_required_even_with_no_candidate_rows(self):
        self.source.write_bytes(self.raw[:-1]+b'!')
        with self.assertRaisesRegex(ValueError,'source SHA changed'):
            self.scope()

    def test_forged_database_report_sha_is_not_a_ready_row(self):
        path=self.discovery_db(completed=1,body='{"instructions":["fake"]}')
        with closing(sqlite3.connect(path)) as db, db:db.execute('UPDATE artifacts SET sha=?',('0'*64,))
        scope=self.scope()
        with self.assertRaisesRegex(ValueError,'differs from completion'):
            scope.select(scope.discover_candidates(path))

    def test_missing_receipt_cannot_admit_or_assert_ready(self):
        scope=self.scope()
        self.assertEqual(scope.select([dict(report=self.report_pointer,receipt=None)])[0]['state'],
            'candidate_missing_requires_discovery')
        with self.assertRaisesRegex(ValueError,'no completion receipt'):
            scope.admit_export_rows(self.report_pointer,None)

    def test_same_size_mtime_restored_selected_pseudocode_corruption_rejected_after_cache_hit(self):
        scope=self.scope();scope.select([self.hint]);scope.select([self.hint])
        self.assertGreater(scope.metrics['read_cache_hits'],0)
        metadata=self.pseudo.stat();original=self.pseudo.read_bytes()
        self.pseudo.write_bytes(b'!'+original[1:]);os.utime(self.pseudo,ns=(metadata.st_atime_ns,metadata.st_mtime_ns))
        with self.assertRaisesRegex(ValueError,'changed during scoped validation'):
            scope.finish_barrier()
        with self.assertRaisesRegex(ValueError,'SHA differs'):
            self.scope().select([self.hint])

    def test_report_receipt_and_source_mutation_fail_final_barriers(self):
        for filename in ('report','receipt','source'):
            with self.subTest(filename=filename):
                path=getattr(self,filename);original=path.read_bytes()
                scope=self.scope();scope.select([self.hint]);path.write_bytes(original+b' ')
                try:
                    with self.assertRaises(ValueError):scope.finish_barrier()
                finally:path.write_bytes(original)

    def test_selected_instruction_must_match_exact_source_bytes(self):
        self.rows[0]['instructions'][0]['bytes']='b82b000000';self.publish()
        with self.assertRaisesRegex(ValueError,'bytes differ from exact source'):
            self.scope().select([self.hint])

    def test_non_file_backed_and_overlapping_instruction_spans_rejected(self):
        for offset in (0x140009000,0x140001001):
            original=copy.deepcopy(self.rows[0]['instructions'])
            self.rows[0]['instructions'][1]['address']=hex(offset);self.publish()
            try:
                with self.assertRaises(ValueError):self.scope().select([self.hint])
            finally:self.rows[0]['instructions']=original
        self.publish()

    def test_block_directflow_and_declared_body_coverage_are_not_false_ready(self):
        for change in (dict(block_coverage_complete=False),dict(direct_flow_coverage_complete=False),
                dict(decompiler_block_starts=[self.second]),dict(body_bytes=1),dict(instructions=[])):
            original=copy.deepcopy(self.rows[0]);self.rows[0].update(change);self.publish()
            with self.subTest(change=change):
                self.assertEqual(self.scope().select([self.hint])[0]['state'],'incomplete')
            self.rows[0].clear();self.rows[0].update(original)

    def test_conditional_fallthrough_required_even_legacy_row_omits_coverage_flag(self):
        row=self.row('0x140001020','first.c',[('7402','JZ 0x140001024')])
        row.pop('block_coverage_complete');self.data['functions']=[row];self.publish()
        selected=self.scope(['0x140001020']).select([self.hint])[0]
        self.assertEqual(selected['state'],'incomplete')
        self.assertIn('fallthrough',selected['variants'][0]['message'])

    def test_decompiler_status_and_completed_pseudocode_are_required(self):
        for key in ('decompilation_completed','pseudocode_file'):
            original=self.rows[0].pop(key);self.publish()
            try:
                with self.subTest(key=key),self.assertRaises(ValueError):self.scope().select([self.hint])
            finally:self.rows[0][key]=original

    def test_unresolved_function_budget_is_incomplete_not_ready(self):
        self.rows[0]=dict(address=self.first,skipped='body_budget')
        self.data['functions']=self.rows;self.publish()
        selected=self.scope().select([self.hint])[0]
        self.assertEqual(selected['state'],'incomplete')
        self.assertEqual(selected['variants'],[])
        self.assertIn('budget',selected['unresolved'][0]['message'])

    def test_duplicate_json_keys_and_oversized_export_are_rejected(self):
        original=self.report.read_bytes()
        for raw in (b'{"functions":[],"functions":[]}',b' '*(MODULE.MAX_JSON+1)):
            with self.subTest(size=len(raw)):
                self.report.write_bytes(raw)
                report=dict(path=str(self.report),sha256=sha(raw))
                receipt=write_json(self.receipt,dict(files={'details.json':report['sha256']}))
                with self.assertRaises(ValueError):self.scope().select([dict(report=report,receipt=receipt)])
        self.report.write_bytes(original)

    def test_receipt_schema_and_report_membership_are_required(self):
        for receipt_data in (dict(schema=2,files=self.receipt_data['files']),dict(files={}),
                dict(files={'details.json':'invalid-sha'})):
            with self.subTest(receipt=receipt_data):
                receipt=write_json(self.receipt,receipt_data)
                with self.assertRaises(ValueError):
                    self.scope().select([dict(report=self.report_pointer,receipt=receipt)])

    def test_unresolved_switch_is_incomplete_without_block_evidence(self):
        self.raw=bytearray(self.raw);self.raw[0x200:0x202]=bytes.fromhex('ffe0')
        self.raw=bytes(self.raw);self.source_sha=sha(self.raw)
        self.source=self.root/'client-code-snapshots'/self.source_sha/'ProjectRED-Win64-Shipping.exe'
        self.source.parent.mkdir(parents=True);self.source.write_bytes(self.raw)
        self.rows[0]=self.row(self.first,'first.c',[('ffe0','JMP RAX')])
        self.rows[0].pop('decompiler_block_starts')
        self.pseudo.write_text('switch(x){case 1: return 0;}',encoding='utf-8')
        self.data=dict(source_sha256=self.source_sha,functions=self.rows);self.publish()
        selected=self.scope().select([self.hint])[0]
        self.assertEqual(selected['state'],'incomplete')
        self.assertIn('Unresolved switch',selected['variants'][0]['message'])

    def test_pseudocode_path_escape_private_capture_and_receipt_path_escape_rejected(self):
        for name in ('../first.c','C:/capture.c','captures/raw.c','/first.c'):
            original=self.rows[0]['pseudocode_file'];self.rows[0]['pseudocode_file']=name
            self.report_pointer=write_json(self.report,self.data)
            receipt=dict(files={'details.json':self.report_pointer['sha256']})
            self.receipt_pointer=write_json(self.receipt,receipt)
            try:
                with self.subTest(name=name),self.assertRaises(ValueError):
                    self.scope().select([dict(report=self.report_pointer,receipt=self.receipt_pointer)])
            finally:self.rows[0]['pseudocode_file']=original
        self.publish();self.receipt_data['files']['../escape.c']='0'*64
        receipt_pointer=write_json(self.receipt,self.receipt_data)
        with self.assertRaises(ValueError):self.scope().select([dict(report=self.report_pointer,receipt=receipt_pointer)])

    def test_wrong_receipt_location_or_source_is_rejected(self):
        other=write_json(self.folder/'other.json',self.receipt_data)
        with self.assertRaisesRegex(ValueError,'receipt location'):
            self.scope().select([dict(report=self.report_pointer,receipt=other)])
        self.publish(dict(source_sha256='0'*64))
        with self.assertRaisesRegex(ValueError,'source SHA differs'):
            self.scope().select([self.hint])

    def test_conflicting_duplicate_and_ambiguous_reports_block(self):
        self.rows.append(copy.deepcopy(self.rows[0]));self.publish()
        self.assertEqual(self.scope().select([self.hint])[0]['variants'][0]['observations'],2)
        self.rows[-1]['message']='different checked observation';self.publish()
        with self.assertRaisesRegex(ValueError,'Conflicting duplicate'):
            self.scope().select([self.hint])
        self.rows.pop();self.publish();original_hint=copy.deepcopy(self.hint)
        other=self.root/'ghidra/request-exports'/self.source_sha/'run-second';other.mkdir()
        (other/'first.c').write_bytes(self.pseudo.read_bytes()+b'\n')
        report=write_json(other/'details.json',self.data)
        receipt=write_json(other/'provenance.json',dict(source_sha256=self.source_sha,
            files={'details.json':report['sha256'],'first.c':sha((other/'first.c').read_bytes())}))
        with self.assertRaisesRegex(ValueError,'ambiguous checked variants'):
            self.scope().select([original_hint,dict(report=report,receipt=receipt)])
        # An incomplete observation also conflicts; a ready row cannot hide it.
        alternative=copy.deepcopy(self.data);alternative['functions'][0]['block_coverage_complete']=False
        report=write_json(other/'details.json',alternative)
        receipt=write_json(other/'provenance.json',dict(files={'details.json':report['sha256'],
            'first.c':sha((other/'first.c').read_bytes())}))
        with self.assertRaisesRegex(ValueError,'ambiguous checked variants'):
            self.scope().select([original_hint,dict(report=report,receipt=receipt)])

    def test_unselected_corruption_is_excluded_but_rejected_when_selected(self):
        second=self.folder/'second.c';second.write_text('int other(){return 0;}',encoding='utf-8')
        self.rows.append(self.row(self.second,'second.c',[('33c0','XOR EAX,EAX'),('c3','RET')]))
        self.publish();second.write_bytes(b'broken unselected history')
        scope=self.scope();self.assertEqual(scope.select([self.hint])[0]['state'],'ready')
        receipt=scope.finish_barrier()
        self.assertNotIn(str(second.resolve()),receipt['inputs'])
        self.assertEqual(receipt['metrics']['selected_pseudocode_reads'],1)
        self.assertFalse(receipt['coverage']['unselected_report_outputs_checked'])
        with self.assertRaisesRegex(ValueError,'SHA differs'):
            self.scope([self.second]).select([self.hint])

    def test_comparison_side_is_selected_by_full_source_sha_not_name_hint(self):
        other_raw=bytearray(self.raw);other_raw[-1]=1;other_sha=sha(other_raw)
        old=copy.deepcopy(self.rows[0]);new=copy.deepcopy(self.rows[0])
        self.data=dict(old_source_sha256=other_sha,new_source_sha256=self.source_sha,
            pairs=[dict(old=old,new=new,old_analyst_name='untrusted-role')]);self.publish()
        row=self.scope().select([self.hint])[0]['variants'][0]
        self.assertEqual(row['side'],'new');self.assertIn('[comparison hint]',row['names'])
        self.data['new_source_sha256']=other_sha;self.publish()
        with self.assertRaisesRegex(ValueError,'another source/comparison side'):
            self.scope().select([self.hint])

    def test_legacy_bootstrap_default_pseudocode_and_parent_receipt(self):
        export=self.folder/'export';export.mkdir();self.report=export/'bootstrap.json'
        row=copy.deepcopy(self.rows[0]);row.pop('pseudocode_file')
        pseudo=export/(self.first+'.c');pseudo.write_bytes(self.pseudo.read_bytes())
        report=write_json(self.report,dict(source_sha256=self.source_sha,functions=[row]))
        receipt=write_json(self.receipt,dict(files={'export/bootstrap.json':report['sha256'],
            'export/'+pseudo.name:sha(pseudo.read_bytes())}))
        selected=self.scope().select([dict(report=report,receipt=receipt)])
        self.assertEqual(selected[0]['state'],'ready')

    def test_selected_context_and_tools_are_pinned_with_final_mutation_guard(self):
        tool=self.knowledge/'reviewed-tool.py';tool.write_bytes(b'pass\n')
        scope=MODULE.Scope.open(self.root,self.knowledge,self.source_sha,[self.first],{str(tool):sha(tool.read_bytes())})
        selected=scope.pin_context('q');self.assertEqual(selected[0]['id'],'q')
        tool.write_bytes(b'#new\n')
        with self.assertRaisesRegex(ValueError,'changed during scoped validation'):scope.finish_barrier()

    def test_explicit_fact_context_checks_selected_evidence_only(self):
        evidence=self.knowledge/'selected-evidence.json';ep=write_json(evidence,dict(result='bounded fixture'))
        fact=dict(id='f',question='q',source_sha256=self.source_sha,addresses=[self.first],
            conclusion='Fixture only',method='static',unknown='Online unknown',next_check='No game action',
            limits=['Explicit selection'],evidence=[ep])
        facts=self.knowledge/'releases'/self.source_sha/'facts.json'
        write_json(facts,dict(source_sha256=self.source_sha,facts=[fact,dict(id='unselected-broken-fact')]))
        scope=self.scope();context=scope.pin_context('q',['f'])
        self.assertEqual(context[1]['payload'],fact)
        receipt=scope.finish_barrier();self.assertIn(str(evidence.resolve()),receipt['inputs'])
        evidence.write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError,'SHA differs'):self.scope().pin_context('q',['f'])

    def test_question_and_selected_fact_source_change_are_rejected(self):
        scope=self.scope();scope.pin_context('q')
        write_json(self.knowledge/'questions.json',dict(questions=[dict(id='q',next_action='Changed')]))
        with self.assertRaisesRegex(ValueError,'changed during scoped validation'):scope.finish_barrier()
        with self.assertRaisesRegex(ValueError,'Unknown or ambiguous'):self.scope().pin_context('unknown')
        write_json(self.knowledge/'releases'/self.source_sha/'facts.json',
            dict(source_sha256='0'*64,facts=[dict(id='f')]))
        with self.assertRaisesRegex(ValueError,'fact registry source'):self.scope().pin_context('q',['f'])

    def test_shared_source_store_reuses_source_and_scoped_pe_without_native_image_pollution(self):
        first=self.scope();first.select([self.hint])
        second=self.scope(source_store=first.source_store);second.select([self.hint])
        self.assertEqual(first.source_store.metrics['source_reads'],1)
        self.assertEqual(second.metrics['scoped_pe_builds'],0)
        self.assertEqual(first.source_store._images,{})
        second.finish_barrier()

    def test_add_outputs_preserves_previously_admitted_rows(self):
        scope=self.scope([self.first,self.second]);scope.select([self.hint])
        second=self.folder/'second.c';second.write_text('int other(){return 0;}',encoding='utf-8')
        old_hint=self.hint
        other=self.root/'ghidra/request-exports'/self.source_sha/'run-new';other.mkdir()
        (other/'second.c').write_bytes(second.read_bytes())
        report=write_json(other/'details.json',dict(source_sha256=self.source_sha,functions=[
            self.row(self.second,'second.c',[('33c0','XOR EAX,EAX'),('c3','RET')])]))
        receipt=write_json(other/'provenance.json',dict(files={'details.json':report['sha256'],
            'second.c':sha(second.read_bytes())}))
        self.assertEqual([r['state'] for r in scope.add_outputs([dict(report=report,receipt=receipt)])],['ready','ready'])


if __name__ == '__main__':
    unittest.main()
