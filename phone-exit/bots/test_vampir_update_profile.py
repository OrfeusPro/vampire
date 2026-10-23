"""Synthetic provenance guards; native report assembly is checked separately."""
import copy
import hashlib
import json
import locale
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_vampir_update_contracts import load,HERE


class UpdateProfileTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.index=load('knowledge-index').api()
        self.workflow=load('research-workflow');self.tool=load('update-profile')
        source=self.root/'install/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe'
        source.parent.mkdir(parents=True);source.write_bytes(b'synthetic source')
        self.sha=self.index.digest(source)
        self.args=SimpleNamespace(root=self.root,install=self.root/'install')
        self.crt=self.root/'ucrtbase.dll';self.crt.write_bytes(b'fixture CRT; never loaded')
        artifact=self.root/'ghidra/fixture.json';artifact.parent.mkdir();artifact.write_text('{}')
        roles=('defaults','override','platform','start','url','headers','nid_base','nid_helpers','geo')
        self.contract=dict(id='launcher',profile_reports={r:dict(pattern='code-clues/'+r+'-*/*/manifest.json',min_cases=1) for r in roles})
        self.reports={};self.paths={}
        for role in roles:
            report=dict(source_sha256=self.sha,cases=[dict(synthetic=True)],
                dependencies={'update-profile.py':self.index.digest(HERE/'update-profile.py')},
                evidence=[dict(path=str(artifact),sha256=self.index.digest(artifact))],limits=['Synthetic; no native execution'])
            if role in ('url','headers'):
                name='sdk_config.py' if role=='url' else 'gmc2_request.py'
                report['portable_helper_sha256']=self.index.digest(HERE.parents[1]/'vampir-shared/vampir_core'/name)
            if role=='nid_helpers':
                report.update(native_primitives=True,primitive_evidence=dict(crt=dict(path=str(self.crt),
                    sha256=self.index.digest(self.crt),locale=locale.setlocale(locale.LC_ALL))))
            self.reports[role]=report;self.paths[role]=self.store(role,report)
        self.outcomes={}
        for name in ('sdk-gmc2','launcher'):
            proof=self.workflow.snapshot(self.root,'check-results',dict(state='passed',
                definition=dict(source_sha256=self.sha,check=dict(id=name))))
            self.outcomes[name]=dict(state='passed',checks=[dict(id=name,state='passed',report=str(proof),sha256=self.index.digest(proof))])
        self.runtime=patch.object(self.workflow,'system_runtime_files',return_value=[self.crt]);self.runtime.start();self.addCleanup(self.runtime.stop)

    def store(self,role,report,suffix='fixture'):
        raw=self.workflow.canonical(report);sha=hashlib.sha256(raw).hexdigest()
        path=self.root/'code-clues'/(role+'-'+suffix)/sha/'manifest.json'
        path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
        return path

    def resolve(self):return self.tool.resolve(self.index,self.workflow,self.args,self.contract,self.outcomes,self.sha)

    def test_profile_remains_offline_and_does_not_change_settings(self):
        active=self.root/'active.json';active.write_text('preserve')
        with patch.object(self.tool,'assemble',return_value=dict(public_gmc2={},nid={})):
            result=self.tool.build(self.index,self.workflow,self.args,self.contract,self.outcomes,self.sha,{})
        package=self.workflow.checked_manifest(self.index,Path(result['profile']))
        self.assertFalse(package['activated']);self.assertFalse(package['live_verified'])
        self.assertFalse(package['profile']['network_ready']);self.assertFalse(package['profile']['game_protocol_verified'])
        self.assertEqual(active.read_text(),'preserve')

    def test_changed_report_changes_profile_stage_inputs(self):
        old=self.tool.inputs(self.index,self.workflow,self.args,self.contract,self.outcomes,self.sha)
        self.paths['defaults'].unlink()
        report=copy.deepcopy(self.reports['defaults']);report['cases'].append(dict(other=True))
        self.store('defaults',report)
        self.assertNotEqual(old,self.tool.inputs(self.index,self.workflow,self.args,self.contract,self.outcomes,self.sha))

    def test_ambiguous_missing_and_corrupt_reports_are_rejected(self):
        duplicate=self.store('defaults',self.reports['defaults'],suffix='second')
        with self.assertRaisesRegex(ValueError,'ambiguous'):self.resolve()
        duplicate.unlink()
        self.paths['url'].write_bytes(b'corrupt')
        with self.assertRaises(ValueError):self.resolve()
        self.paths['url'].unlink()
        with self.assertRaisesRegex(ValueError,'url'):self.resolve()

    def test_failed_proof_and_wrong_check_id_are_rejected(self):
        for state,identifier in [('failed','launcher'),('passed','other')]:
            proof=self.workflow.snapshot(self.root,'check-results',dict(state=state,
                definition=dict(source_sha256=self.sha,check=dict(id=identifier))))
            self.outcomes['launcher']['checks']=[dict(id='launcher',state='passed',report=str(proof),sha256=self.index.digest(proof))]
            with self.subTest(state=state,identifier=identifier),self.assertRaises(ValueError):self.resolve()

    def test_changed_runtime_and_stale_dependency_block_profile(self):
        self.crt.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'CRT'):self.resolve()
        self.crt.write_bytes(b'fixture CRT; never loaded')
        report=copy.deepcopy(self.reports['defaults']);report['dependencies']['update-profile.py']='0'*64
        self.paths['defaults'].unlink();self.store('defaults',report)
        with self.assertRaisesRegex(ValueError,'stale=1'):self.resolve()


if __name__=='__main__':unittest.main()
