"""Selective native-family orchestration and shared cache; all code execution is mocked."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from test_vampir_update_contracts import load


def mocked_publication_cache():
    # Orchestration tests intentionally use synthetic non-native declarations;
    # production never bypasses source/proof admission when source_store is absent.
    return SimpleNamespace(begin=lambda index,args,sha:SimpleNamespace(
        publish=lambda spec,tool,declaration,result:tool.publish(index,args,sha,declaration,result), finish=lambda:{}))


class AdapterDriverTests(unittest.TestCase):
    def test_selected_driver_never_loads_other_family_tools_and_rejects_unregistered_selection(self):
        driver=load('update-native-drivers')
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'native-check-adapters.json').write_text('{}')
            selected=next(spec for spec in driver.SPECS if spec['family']=='version-result')
            tool=SimpleNamespace(plan_inputs=lambda *args:{},discover=lambda *args:dict(state='planned',exports=[]),
                tools=lambda:{},materialize=lambda *args:dict(checks=[],queue=[]))
            allowed={driver.MODULES[selected['adapter']]:tool,'research-workflow':object(),
                'native-publication-cache':mocked_publication_cache(),
                'update-run':SimpleNamespace(collect_batches=lambda *args:[])}
            index=SimpleNamespace(read_json=lambda _:dict(schema=1,adapters=list(driver.SPECS)),
                extension=lambda name:allowed[name])
            journal=SimpleNamespace(stage=lambda name,inputs,action:action());args=SimpleNamespace(root=root,knowledge=root)
            result=driver.run(index,args,'a'*64,journal,root/'unused',families=['version-result'])
            self.assertEqual(result['families'],['version-result'])
            with self.assertRaisesRegex(ValueError,'not registered'):
                driver.run(index,args,'a'*64,journal,root/'unused',families=['unknown'])

    def test_registered_families_have_a_fixed_order_and_no_duplicate_or_arbitrary_modules(self):
        driver=load('update-native-drivers')
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder);(path/'native-check-adapters.json').write_text('{}')
            for selected in ([driver.SPECS[0]],[driver.SPECS[1]],list(driver.SPECS)):
                index=SimpleNamespace(read_json=lambda _,selected=selected:dict(schema=1,adapters=selected))
                self.assertEqual(driver.registry(index,path),selected)
            for selected in (list(reversed(driver.SPECS)),[driver.SPECS[0],driver.SPECS[0]],
                    [dict(driver.SPECS[1],adapter='arbitrary.py')],[]):
                index=SimpleNamespace(read_json=lambda _,selected=selected:dict(schema=1,adapters=selected))
                with self.subTest(selected=selected),self.assertRaises(ValueError):driver.registry(index,path)

    def test_one_family_change_replays_only_that_family_with_real_journal_cache(self):
        driver,engine=load('update-native-drivers'),load('update-run')
        index=load('knowledge-index').api();workflow=load('research-workflow')
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);knowledge=root/'definitions';knowledge.mkdir()
            (knowledge/'native-check-adapters.json').write_bytes(workflow.canonical(dict(schema=1,adapters=list(driver.SPECS))))
            args=SimpleNamespace(root=root,knowledge=knowledge)
            versions={spec['family']:1 for spec in driver.SPECS};executions={name:0 for name in versions}
            def tool(spec):
                family=spec['family']
                def execute(index,args,sha,declaration):
                    executions[family]+=1
                    return dict(id=spec['id'],state='passed')
                return SimpleNamespace(plan_inputs=lambda *args:dict(revision=versions[family]),
                    discover=lambda *args:dict(state='planned',exports=[],revision=versions[family]),
                    tools=lambda:dict(revision=versions[family]),
                    materialize=lambda *args:dict(checks=[dict(id=spec['id'],revision=versions[family])],queue=[]),
                    execute=execute,publish=lambda *args:None)
            modules={driver.MODULES[spec['adapter']]:tool(spec) for spec in driver.SPECS if spec['adapter'] not in ('version-helper-v1','login-metadata-v1','login-input-v1','login-handler-v1','response-v1','login-full-v1','login-composition-v1','registration-v1')}
            modules['update-native-version-helpers']=SimpleNamespace(select=lambda family:tool(next(
                spec for spec in driver.SPECS if spec['family']==family)))
            modules['update-native-login-metadata']=modules['update-native-version-helpers']
            modules['update-native-login-input']=modules['update-native-version-helpers']
            modules['update-native-login-handler']=modules['update-native-version-helpers']
            modules['update-native-response']=modules['update-native-version-helpers']
            modules['update-native-login-full']=modules['update-native-version-helpers']
            modules['update-native-login-composition']=modules['update-native-version-helpers']
            modules['update-native-login-registration']=modules['update-native-version-helpers']
            modules.update({'research-workflow':workflow,'update-run':SimpleNamespace(collect_batches=lambda *args:[]),
                'native-publication-cache':mocked_publication_cache(),
                'update-native-harness':SimpleNamespace(runtime_inputs=lambda:{})})
            original=index.extension;index.extension=lambda name:modules.get(name) or original(name)
            record=dict(state='running',stages={});path=root/'journal.json'
            def run():
                journal=engine.Journal(index,workflow,args,record,path)
                result=driver.run(index,args,'a'*64,journal,root/'unused.sqlite3')
                self.assertFalse(result['queue']);self.assertEqual(len(result['checks']),len(driver.SPECS))
                return journal
            run();self.assertEqual(executions,{spec['family']:1 for spec in driver.SPECS})
            warm=run();self.assertEqual(warm.reused,3*len(driver.SPECS));self.assertFalse(warm.executed)
            versions['archive-wire']=2;selective=run()
            self.assertEqual(executions,{spec['family']:(2 if spec['family']=='archive-wire' else 1) for spec in driver.SPECS})
            self.assertEqual(selective.reused,3*(len(driver.SPECS)-1))

    def test_merge_preserves_base_cache_value_when_caller_passes_a_copy(self):
        import copy
        driver=load('update-native-drivers')
        base=dict(checks=[],queue=[dict(reason='unregistered_native_suite_families',families=['archive-wire','unknown'])],
            family_coverage=[dict(family='archive-wire',adapter='unsupported')])
        revised=copy.deepcopy(base);checks=[]
        metrics=dict(reused=1,validated=0,source_store=dict(image_builds=0))
        driver.merge(revised,checks,dict(families=['archive-wire'],queue=[],declarations=[dict(id='archive')],checks=[dict(state='passed')],publication_cache=metrics))
        self.assertEqual(base['checks'],[]);self.assertEqual(base['queue'][0]['families'],['archive-wire','unknown'])
        self.assertEqual(revised['queue'][0]['families'],['unknown'])
        self.assertEqual(revised['family_coverage'][0]['adapter'],'archive-wire-v1')
        self.assertEqual(revised['publication_cache'],metrics)
        self.assertNotIn('publication_cache',base)


if __name__=='__main__':unittest.main()
