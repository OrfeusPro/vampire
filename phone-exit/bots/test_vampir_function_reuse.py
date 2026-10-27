"""Function-only source/closure/cache boundaries through the real PE resolver."""
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from test_vampir_update_bindings import BindingTests
from test_vampir_update_contracts import load

class FunctionReuseTests(unittest.TestCase):
    setUp=BindingTests.setUp
    image=BindingTests.image
    model=BindingTests.model

    def wrapper(self,model):
        module=load('verify-function-reuse');original=module.load
        modules={}
        def selected(name):
            if name=='update-contracts':return SimpleNamespace(load=lambda *args:copy.deepcopy(model))
            if name not in modules:modules[name]=original(name)
            return modules[name]
        module.load=selected
        return module,modules

    def closed_model(self,old):
        model=self.model(old)
        for recipe in model['contracts'][0]['recipes']:
            recipe.update(method='closed_shape',search_window=0x100)
        return model

    def test_actual_resolver_expands_callees_and_reuses_content_addressed_report(self):
        old=self.image(0x1000);new=self.image(0x1020)
        module,modules=self.wrapper(self.closed_model(old))
        first=module.verify(self.root,self.root,new,'fixture',['main'])
        self.assertEqual(first['verified'],2);self.assertEqual(first['requires_review'],0)
        self.assertFalse(first['runtime_activated']);self.assertFalse(first['profile_activated'])
        self.assertFalse(first['reused'])
        report=json.loads(Path(first['report']).read_bytes())
        self.assertEqual(report['scope'],'function_only')
        self.assertEqual(report['verification']['verification']['main']['state'],'moved_verified')
        self.assertEqual(report['verification']['verification']['helper']['state'],'unchanged')
        with patch.object(modules['update-bindings'],'resolve',side_effect=AssertionError('cached result must not rerun resolver')):
            second=module.verify(self.root,self.root,new,'fixture',['main'])
        self.assertTrue(second['reused']);self.assertEqual(Path(first['report']).resolve(),Path(second['report']).resolve())

    def test_corrupt_current_or_baseline_source_cannot_reuse_verified_cache(self):
        old=self.image(0x1000);new=self.image(0x1020)
        module,_=self.wrapper(self.closed_model(old));module.verify(self.root,self.root,new,'fixture',['main'])
        for sha in (old,new):
            path=self.root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'
            previous=path.read_bytes();path.write_bytes(previous+b'changed')
            try:
                with self.subTest(sha=sha),self.assertRaisesRegex(ValueError,'source SHA changed'):
                    module.verify(self.root,self.root,new,'fixture',['main'])
            finally:path.write_bytes(previous)

    def test_tool_identity_change_produces_new_proof_instead_of_old_cache(self):
        old=self.image(0x1000);new=self.image(0x1020)
        module,_=self.wrapper(self.closed_model(old))
        first=module.verify(self.root,self.root,new,'fixture',['main'])
        digest=module.digest
        for name in ('update-bindings.py','research-workflow.py','extract-native-enums.py'):
            def changed(path,name=name):
                return 'f'*64 if Path(path).name==name else digest(path)
            with self.subTest(tool=name),patch.object(module,'digest',side_effect=changed):
                second=module.verify(self.root,self.root,new,'fixture',['main'])
                self.assertFalse(second['reused']);self.assertNotEqual(first['report'],second['report'])
                self.assertEqual(second['verified'],2)

    def test_changed_callee_is_reviewed_not_confirmed_by_outer_similarity(self):
        old=self.image(0x1000);new=self.image(0x1020,callee_value=8)
        module,_=self.wrapper(self.closed_model(old))
        got=module.verify(self.root,self.root,new,'fixture',['main'])
        self.assertEqual(got['verified'],0);self.assertEqual(got['requires_review'],2)
        self.assertFalse(got['runtime_activated'])
        second=module.verify(self.root,self.root,new,'fixture',['main'])
        self.assertTrue(second['reused']);self.assertEqual(second['verified'],0)

    def test_changed_recipe_data_invalidates_cache_and_fails_closed(self):
        old=self.image(0x1000);new=self.image(0x1020)
        model=self.closed_model(old);module,_=self.wrapper(model)
        first=module.verify(self.root,self.root,new,'fixture',['main'])
        model['contracts'][0]['recipes'][0]['calls']={}
        second=module.verify(self.root,self.root,new,'fixture',['main'])
        self.assertFalse(second['reused']);self.assertNotEqual(first['report'],second['report'])
        self.assertEqual(second['verified'],0);self.assertEqual(second['requires_review'],1)

    def test_cache_artifact_tamper_or_path_escape_is_rejected(self):
        old=self.image(0x1000);new=self.image(0x1020)
        module,_=self.wrapper(self.closed_model(old));first=module.verify(self.root,self.root,new,'fixture',['main'])
        report=Path(first['report']);original=report.read_bytes();report.write_bytes(original+b' ')
        with self.assertRaisesRegex(ValueError,'cache artifact changed'):
            module.verify(self.root,self.root,new,'fixture',['main'])
        report.write_bytes(original)
        pointer=next((self.root/'knowledge/function-reuse-cache').glob('*.json'))
        outside=self.root/'outside.json';outside.write_bytes(original)
        pointer.write_text(json.dumps({'report':str(outside)}),encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'cache artifact changed'):
            module.verify(self.root,self.root,new,'fixture',['main'])

    def test_unreviewed_dependency_or_unknown_request_is_not_executed(self):
        old=self.image(0x1000);new=self.image(0x1020)
        model=self.closed_model(old);model['contracts'][0]['recipes'][1]['method']='reviewed'
        module,_=self.wrapper(model)
        for keys,contract in ((['main'],'fixture'),(['missing'],'fixture'),([], 'fixture'),(['main'],'unknown')):
            with self.subTest(keys=keys,contract=contract),self.assertRaises(ValueError):
                module.verify(self.root,self.root,new,contract,keys)

from test_vampir_update_closed_shape import ClosedShapeTests,ClosedShapeSchemaTests
from test_vampir_function_reuse_plan import FunctionReusePlanTests
from test_vampir_update_function_reuse_exports import FunctionReuseExportTests

def load_tests(loader,tests,pattern):
    return unittest.TestSuite(loader.loadTestsFromTestCase(case) for case in (FunctionReuseTests,ClosedShapeTests,ClosedShapeSchemaTests,BindingTests,FunctionReusePlanTests,FunctionReuseExportTests))

if __name__=='__main__':unittest.main()
