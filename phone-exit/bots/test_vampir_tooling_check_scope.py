"""Fixture-only tooling cache reuse must never grant client compatibility."""
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_vampir_research_workflow as fixture


class ToolingScopeTests(fixture.ResearchWorkflowTests):
    def definition(self):
        return dict(id='update-contract-registry', questions=['test-question'], source_sha256=[],
            source_scope='tooling', offline_reviewed=True, test_pattern='test_vampir_update_contracts.py',
            dependencies=[])

    def install_check(self, check):
        (self.knowledge/'research-checks.json').write_text(json.dumps(dict(schema=1,checks=[check])),encoding='utf-8')

    def test_tooling_reuses_exact_report_across_client_sha_but_tracks_code_changes(self):
        check=self.definition();dependency=self.index.HERE.parents[3]/'phone-exit/bots/test_vampir_update_contracts.py'
        self.install_check(check);api=self.index.api();real=api.digest
        with patch.object(self.workflow.subprocess,'run',return_value=SimpleNamespace(returncode=0)) as run:
            first=self.workflow.run_checks(api,self.args,self.sha,'test-question')[0]
            second=self.workflow.run_checks(api,self.args,'a'*64,'test-question')[0]
            self.assertEqual(run.call_count,1);self.assertEqual(first,second)
            self.assertFalse(second['proves_client_compatibility'])
            report=self.index.read_json(second['report'])
            self.assertIsNone(report['definition']['source_sha256'])
            with patch.object(api,'digest',side_effect=lambda p:'b'*64 if p==dependency else real(p)):
                changed=self.workflow.run_checks(api,self.args,'c'*64,'test-question')[0]
            self.assertEqual(run.call_count,2);self.assertNotEqual(first['cache_key'],changed['cache_key'])

    def test_client_check_still_requires_exact_reviewed_source(self):
        check=self.definition();check.pop('source_scope');check['source_sha256']=[self.sha]
        self.install_check(check)
        with patch.object(self.workflow.subprocess,'run') as run:
            result=self.workflow.run_checks(self.index.api(),self.args,'a'*64,'test-question')
        run.assert_not_called();self.assertEqual(result[0]['state'],'requires_port')

    def test_native_or_artifact_check_cannot_opt_itself_into_tooling(self):
        for change in ('native-id','wrong-pattern','client-source','artifact','system-runtime','unreviewed','unknown-scope'):
            check=self.definition()
            if change=='native-id':check['id']='native-login-prepare-context'
            elif change=='wrong-pattern':check['test_pattern']='test_vampir_quest_time_11316.py'
            elif change=='client-source':check['source_sha256']=[self.sha]
            elif change=='artifact':check['artifact_dependencies']=['ghidra/fixture/details.json']
            elif change=='system-runtime':check['system_runtime_files']=['ucrtbase.dll']
            elif change=='unreviewed':check['offline_reviewed']=False
            else:check['source_scope']='any'
            with self.subTest(change=change),self.assertRaises(ValueError):self.workflow.source_scope(check)

    def test_tooling_only_cannot_support_a_bounded_native_fact(self):
        with patch.object(self.workflow,'run_checks',return_value=[]):self.prepare()
        value=self.result();value['method']='bounded_native';self.args.result.write_text(json.dumps(value),encoding='utf-8')
        with patch.object(self.workflow,'run_checks',return_value=[dict(id='tooling',state='passed',source_scope='tooling')]),self.assertRaisesRegex(ValueError,'source-bound client check'):
            self.workflow.finish(self.index.api(),self.args,self.db)
        self.assertFalse((self.knowledge/'releases').exists())


for _name in dir(fixture.ResearchWorkflowTests):
    if _name.startswith('test_') and _name not in ToolingScopeTests.__dict__:setattr(ToolingScopeTests,_name,None)

if __name__=='__main__':unittest.main()
