import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_vampir_research_workflow as fixture


class CheckSourceVariantTests(fixture.ResearchWorkflowTests):
    def variant_check(self):
        return dict(id='variant-check',questions=['test-question'],source_sha256=[self.sha,'a'*64],
            offline_reviewed=True,test_pattern='test_vampir_update_contracts.py',dependencies=[],
            source_variants={self.sha:dict(test_pattern='test_vampir_requested_tail_calls.py',dependencies=[])})

    def test_exact_source_selects_suite_and_cache_without_changing_original(self):
        check=self.variant_check();original=copy.deepcopy(check)
        import json
        (self.knowledge/'research-checks.json').write_text(json.dumps(dict(schema=1,checks=[check])),encoding='utf-8')
        with patch.object(self.workflow.subprocess,'run',return_value=SimpleNamespace(returncode=0)) as run:
            first=self.workflow.run_checks(self.index.api(),self.args,self.sha,'test-question')[0]
            second=self.workflow.run_checks(self.index.api(),self.args,self.sha,'test-question')[0]
            self.assertEqual(run.call_count,1);self.assertEqual(first,second)
            command=run.call_args.args[0]
            self.assertIn('test_vampir_requested_tail_calls.py',command)
            prior=self.workflow.run_checks(self.index.api(),self.args,'a'*64,'test-question')[0]
            self.assertIn('test_vampir_update_contracts.py',run.call_args.args[0])
            self.assertNotEqual(first['cache_key'],prior['cache_key'])
        self.assertEqual(check,original)

    def test_unreviewed_source_never_selects_a_variant(self):
        import json
        check=self.variant_check()
        (self.knowledge/'research-checks.json').write_text(json.dumps(dict(schema=1,checks=[check])),encoding='utf-8')
        with patch.object(self.workflow.subprocess,'run') as run:
            result=self.workflow.run_checks(self.index.api(),self.args,'b'*64,'test-question')
        run.assert_not_called();self.assertEqual(result[0]['state'],'requires_port')

    def test_variants_cannot_override_review_permissions_or_source_scope(self):
        for field in ('offline_reviewed','source_scope','source_sha256','id','command'):
            check=self.variant_check();check['source_variants'][self.sha][field]=False
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'Invalid reviewed source variant'):
                self.workflow.source_definition(check,self.sha)
        check=self.variant_check();check['source_variants']['b'*64]={"dependencies":[]}
        with self.assertRaisesRegex(ValueError,'Invalid reviewed source variant'):
            self.workflow.source_definition(check,self.sha)


if __name__=='__main__':unittest.main()
