"""Выборочные причины перепроверки по точным путям и текущему source variant."""
import copy
from pathlib import Path
import tempfile
import unittest

from test_vampir_update_contracts import load


CURRENT = 'a'*64
OTHER = 'b'*64


class UpdatePlanKeysTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.workspace = Path(directory.name).resolve()
        (self.workspace/'phone-exit/bots').mkdir(parents=True)
        self.engine = load('update-run')
        self.model = load('update-contracts')
        self.workflow = load('research-workflow')
        self.tools = {name:{'fixture':'same'} for name in ('bindings','context','profile')}
        self.checks = [self.check('first-check'), self.check('second-check')]
        rows = [self.contract('first',['first-check']),
            self.contract('second',['second-check']),
            self.contract('dependent',[],['first']),
            self.contract('leaf',[],['dependent']),
            self.contract('unrelated',[])]
        self.contracts = dict(contracts=rows,order=[row['id'] for row in rows])

    def check(self, identifier):
        return dict(id=identifier, source_scope='client', source_sha256=[CURRENT,OTHER],
            test_pattern='test_vampir_'+identifier.replace('-','_')+'.py',
            dependencies=[], artifact_dependencies=[], offline_reviewed=True,
            timeout_seconds=30)

    def contract(self, identifier, checks, dependencies=None):
        return dict(id=identifier, checks=checks, depends_on=dependencies or [],
            recipes=[],resources=[])

    def definitions(self, path, identity):
        return {str((self.workspace/path).resolve()):identity}

    def plan(self, checks=None, *, old_checks=None, before=None, after=None,
            old_sha=CURRENT, current_sha=CURRENT, selected=True, contracts=None):
        checks = self.checks if checks is None else checks
        old_checks = checks if old_checks is None else old_checks
        contracts = self.contracts if contracts is None else contracts
        previous = dict(plan=dict(contracts=copy.deepcopy(contracts),
            checks={c['id']:copy.deepcopy(c) for c in old_checks},
            tools=copy.deepcopy(self.tools),definition_sha256=copy.deepcopy(before or {})))
        if old_sha is not None:
            previous['source_sha256'] = old_sha
        before_call = copy.deepcopy((checks,contracts,previous,self.tools))
        result = self.engine.affected_plan(self.model,contracts,checks,exe_changed=False,
            changes=[],previous=previous,definitions=after or {},tools=self.tools,
            workspace=self.workspace,source_sha=current_sha,
            select_check=self.workflow.source_definition if selected else None)
        self.assertEqual((checks,contracts,previous,self.tools),before_call)
        return result

    def test_same_basename_in_other_directory_does_not_affect_consumer(self):
        path = 'phone-exit/bots/first/helper.py'
        self.checks[0]['dependencies'] = [path]
        unrelated = 'phone-exit/bots/second/helper.py'
        result = self.plan(before=self.definitions(unrelated,'old'),after=self.definitions(unrelated,'new'))
        self.assertEqual(result['affected'],[])
        result = self.plan(before=self.definitions(path,'old'),after=self.definitions(path,'new'))
        self.assertEqual(result['affected'],['first','dependent','leaf'])

    def test_selected_variant_dependency_change_affects_its_consumers(self):
        dependency = 'phone-exit/bots/selected/helper.py'
        self.checks[0]['source_variants'] = {CURRENT:dict(dependencies=[dependency]),
            OTHER:dict(dependencies=['phone-exit/bots/foreign/helper.py'])}
        result = self.plan(before=self.definitions(dependency,'old'),after=self.definitions(dependency,'new'))
        self.assertEqual(result['affected'],['first','dependent','leaf'])
        self.assertEqual(result['reasons']['first'],['check_inputs_changed:first-check'])

    def test_foreign_variant_definition_and_dependency_changes_are_ignored(self):
        self.checks[0]['source_variants'] = {CURRENT:dict(dependencies=['phone-exit/bots/current.py']),
            OTHER:dict(dependencies=['phone-exit/bots/foreign.py'],timeout_seconds=20)}
        previous = copy.deepcopy(self.checks)
        self.checks[0]['source_variants'][OTHER]['timeout_seconds'] = 90
        dependency = 'phone-exit/bots/foreign.py'
        result = self.plan(old_checks=previous,before=self.definitions(dependency,'old'),
            after=self.definitions(dependency,'new'))
        self.assertEqual(result['affected'],[])

    def test_overridden_base_dependency_and_test_pattern_changes_are_ignored(self):
        dependency = 'phone-exit/bots/base.py'
        self.checks[0].update(dependencies=[dependency],test_pattern='test_vampir_base.py',
            source_variants={CURRENT:dict(dependencies=['phone-exit/bots/current.py'],
                test_pattern='test_vampir_current.py')})
        previous = copy.deepcopy(self.checks)
        self.checks[0].update(dependencies=['phone-exit/bots/unused.py'],test_pattern='test_vampir_unused.py')
        result = self.plan(old_checks=previous,before=self.definitions(dependency,'old'),
            after=self.definitions(dependency,'new'))
        self.assertEqual(result['affected'],[])

    def test_selected_variant_definition_change_is_recorded(self):
        self.checks[0]['source_variants'] = {CURRENT:dict(timeout_seconds=20)}
        previous = copy.deepcopy(self.checks)
        self.checks[0]['source_variants'][CURRENT]['timeout_seconds'] = 21
        result = self.plan(old_checks=previous)
        self.assertEqual(result['affected'],['first','dependent','leaf'])

    def test_removed_dependency_file_and_removed_declaration_are_detected(self):
        dependency = 'phone-exit/bots/removed.py'
        self.checks[0]['dependencies'] = [dependency]
        result = self.plan(before=self.definitions(dependency,'old'))
        self.assertEqual(result['affected'],['first','dependent','leaf'])
        previous = copy.deepcopy(self.checks)
        self.checks[0]['dependencies'] = []
        result = self.plan(old_checks=previous,before=self.definitions(dependency,'old'))
        self.assertEqual(result['affected'],['first','dependent','leaf'])

    def test_test_pattern_is_rooted_in_bots_and_rename_changes_definition(self):
        filename = self.checks[0]['test_pattern']
        same_name_elsewhere = 'phone-exit/other/'+filename
        result = self.plan(before=self.definitions(same_name_elsewhere,'old'),
            after=self.definitions(same_name_elsewhere,'new'))
        self.assertEqual(result['affected'],[])
        path = 'phone-exit/bots/'+filename
        result = self.plan(before=self.definitions(path,'old'),after=self.definitions(path,'new'))
        self.assertEqual(result['affected'],['first','dependent','leaf'])
        previous = copy.deepcopy(self.checks)
        self.checks[0]['test_pattern'] = 'test_vampir_renamed.py'
        self.assertEqual(self.plan(old_checks=previous)['affected'],['first','dependent','leaf'])

    def test_shared_helper_affects_both_consumers_and_transitive_dependents(self):
        helper = 'phone-exit/bots/shared/helper.py'
        for check in self.checks:
            check['dependencies'] = [helper]
        result = self.plan(before=self.definitions(helper,'old'),after=self.definitions(helper,'new'))
        self.assertEqual(result['affected'],['first','second','dependent','leaf'])
        self.assertEqual(result['reasons']['leaf'],['dependency_changed:dependent'])
        self.assertNotIn('unrelated',result['reasons'])

    def test_legacy_source_identity_keeps_conservative_variant_comparison(self):
        self.checks[0]['source_variants'] = {OTHER:dict(timeout_seconds=20)}
        previous = copy.deepcopy(self.checks)
        self.checks[0]['source_variants'][OTHER]['timeout_seconds'] = 21
        self.assertEqual(self.plan(old_checks=previous,old_sha=None)['affected'],
            ['first','dependent','leaf'])
        self.assertEqual(self.plan(old_checks=previous)['affected'],[])

    def test_without_selected_source_all_declared_variant_dependencies_remain_relevant(self):
        helper = 'phone-exit/bots/other_source.py'
        self.checks[0]['source_variants'] = {OTHER:dict(dependencies=[helper])}
        for arguments in (dict(current_sha=None),dict(selected=False)):
            with self.subTest(arguments=arguments):
                result = self.plan(before=self.definitions(helper,'old'),
                    after=self.definitions(helper,'new'),**arguments)
                self.assertEqual(result['affected'],['first','dependent','leaf'])


if __name__=='__main__':
    unittest.main()
