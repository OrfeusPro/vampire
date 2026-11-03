"""Scoped v2 orchestration; semantic execution and publication use explicit doubles."""
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from test_vampir_update_contracts import load

DRIVER=load('update-native-drivers-v2')
INDEX=load('knowledge-index').api()
WORKFLOW=load('research-workflow')


def definitions(folder, families=('version-result','archive-wire')):
    knowledge=Path(folder)/'definitions';directory=knowledge/'native-drivers-v2'
    directory.mkdir(parents=True)
    for family in families:
        source=DRIVER.HERE/'knowledge/native-drivers-v2'/(family+'.json')
        (directory/source.name).write_bytes(source.read_bytes())
    return knowledge


class DescriptorTests(unittest.TestCase):
    def test_registry_exact_35_reviewed_descriptors_without_fixed_family_dispatch(self):
        rows=DRIVER.registry(INDEX,DRIVER.HERE/'knowledge')
        self.assertEqual(len(rows),35)
        self.assertEqual(sum(row['execution_kind']=='portable' for row in rows),34)
        self.assertEqual(len({row['index_relative_path'] for row in rows}),35)
        self.assertEqual([row['order'] for row in rows],list(range(35)))

    def test_registry_rejects_unknown_factory_contract_paths_module_and_bad_identity(self):
        changes=[dict(factory_kind='arbitrary'),dict(publication_contract_id='unknown'),
            dict(module_basename='../escape'),dict(index_relative_path='../outside'),
            dict(index_relative_path='generated-a/../../outside'),dict(order=True),
            dict(id='bad/name'),dict(recipe_id='native-drivers-v1'),dict(extra=True),
            dict(reviewed_rule_pointer=dict(path='wrong.py',sha256='f'*64)),
            dict(reviewed_rule_pointer=dict(path='update-native-version-result.py',sha256='f'*64))]
        for change in changes:
            with self.subTest(change=change),tempfile.TemporaryDirectory() as folder:
                knowledge=definitions(folder,('version-result',));path=knowledge/'native-drivers-v2/version-result.json'
                value=json.loads(path.read_text());value.update(change);path.write_text(json.dumps(value))
                with self.assertRaises((ValueError,OSError)):DRIVER.registry(INDEX,knowledge)

    def test_duplicate_order_and_index_and_filename_are_blockers(self):
        for key in ('order','index_relative_path','family'):
            with self.subTest(key=key),tempfile.TemporaryDirectory() as folder:
                knowledge=definitions(folder);directory=knowledge/'native-drivers-v2'
                left=json.loads((directory/'version-result.json').read_text())
                path=directory/'archive-wire.json';right=json.loads(path.read_text());right[key]=left[key]
                path.write_text(json.dumps(right))
                with self.assertRaises(ValueError):DRIVER.registry(INDEX,knowledge)


class DriverTests(unittest.TestCase):
    def setup_driver(self, directory):
        root=Path(directory);knowledge=definitions(root)
        args=SimpleNamespace(root=root,knowledge=knowledge)
        versions={'version-result':1,'archive-wire':1};executed={name:0 for name in versions}
        materialized=[];collector_calls=[];published=[]
        def model(family):
            descriptor=next(row for row in DRIVER.registry(INDEX,knowledge) if row['family']==family)
            def execute(index,args,sha,declaration):
                executed[family]+=1;return dict(id=descriptor['id'],state='passed')
            def materialize(index,args,sha,plan,database):
                materialized.append((family,database))
                return dict(checks=[dict(id=descriptor['id'],revision=versions[family])],queue=[])
            return SimpleNamespace(plan_inputs=lambda *unused:dict(revision=versions[family]),
                discover=lambda *unused:dict(state='planned',exports=[],revision=versions[family]),
                tools=lambda:dict(revision=versions[family]),materialize=materialize,
                execute=execute,publish=lambda *unused:None)
        models={row['module_basename']:model(row['family']) for row in DRIVER.registry(INDEX,knowledge)}
        def collect(index,workflow,journal,args,database,contexts,sha):
            collector_calls.append(database);args.scoped_database=root/'selected-only.sqlite3';return []
        publication=SimpleNamespace(begin=lambda *unused:SimpleNamespace(
            publish=lambda spec,*unused:published.append(spec),finish=lambda:dict(reused=0,validated=0)))
        modules=dict(models,**{'native-publication-v2':publication,'update-run-v2':SimpleNamespace(collect_batches=collect),
            'research-workflow':WORKFLOW,'update-native-harness':SimpleNamespace(runtime_inputs=lambda:{})})
        original=INDEX.extension
        index=SimpleNamespace(**vars(INDEX));index.extension=lambda name:modules.get(name) or original(name)
        engine=load('update-run');record=dict(state='running',stages={})
        def run(**kwargs):
            journal=engine.Journal(index,WORKFLOW,args,record,root/'journal.json')
            result=DRIVER.run(index,args,'a'*64,journal,root/'discovery-not-admitted.sqlite3',**kwargs)
            return result,journal
        return SimpleNamespace(root=root,args=args,versions=versions,executed=executed,
            materialized=materialized,collector_calls=collector_calls,published=published,run=run,modules=modules)

    def test_selected_materialize_uses_admitted_scoped_database_and_v2_collector(self):
        with tempfile.TemporaryDirectory() as directory:
            f=self.setup_driver(directory);result,journal=f.run(families=['version-result'])
            self.assertFalse(result['queue']);self.assertEqual(result['families'],['version-result'])
            self.assertEqual(f.executed,{'version-result':1,'archive-wire':0})
            self.assertEqual(f.materialized,[('version-result',f.root/'selected-only.sqlite3')])
            self.assertEqual(len(f.published),1)

    def test_cache_only_never_executes_missing_native_plan_context_or_scenario(self):
        with tempfile.TemporaryDirectory() as directory:
            f=self.setup_driver(directory);result,journal=f.run(cache_only=True)
            self.assertTrue(result['queue']);self.assertFalse(any(f.executed.values()))
            self.assertFalse(f.materialized);self.assertFalse(f.collector_calls)

    def test_cached_repeat_and_one_changed_family_retain_original_semantic_stage_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            f=self.setup_driver(directory);result,journal=f.run();self.assertFalse(result['queue'])
            self.assertEqual(f.executed,{'version-result':1,'archive-wire':1})
            warm,journal=f.run(cache_only=True);self.assertFalse(warm['queue'])
            self.assertEqual(journal.reused,6);self.assertFalse(journal.executed)
            f.versions['archive-wire']=2;changed,journal=f.run()
            self.assertFalse(changed['queue']);self.assertEqual(journal.reused,3)
            self.assertEqual(f.executed,{'version-result':1,'archive-wire':2})

    def test_unknown_and_utf8_lineage_only_family_reject_before_semantic_work(self):
        with tempfile.TemporaryDirectory() as directory:
            f=self.setup_driver(directory)
            for family in ('unknown','utf8'):
                with self.subTest(family=family),self.assertRaises(ValueError):f.run(families=[family])
            self.assertFalse(any(f.executed.values()))

    def test_merge_uses_returned_descriptor_and_preserves_input_copy(self):
        base=dict(checks=[],queue=[dict(reason='unregistered_native_suite_families',families=['archive-wire','unknown'])],
            family_coverage=[dict(family='archive-wire',adapter='unsupported')])
        revised=copy.deepcopy(base);checks=[]
        extra=dict(families=['archive-wire'],queue=[],declarations=[dict(id='archive')],checks=[dict(state='passed')],
            descriptors=[dict(family='archive-wire',adapter='archive-wire-v1')],publication_cache=dict(reused=1))
        DRIVER.merge(revised,checks,extra)
        self.assertEqual(base['checks'],[]);self.assertEqual(revised['queue'][0]['families'],['unknown'])
        self.assertEqual(revised['family_coverage'][0]['adapter'],'archive-wire-v1')
        self.assertEqual(revised['publication_cache'],dict(reused=1))


if __name__=='__main__':unittest.main()
