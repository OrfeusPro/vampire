"""Candidate joins preserve unknowns and source identity without promoting them to runtime geometry."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).parent/'resource-tools/vampir'
spec=importlib.util.spec_from_file_location('candidate_layer',HERE/'scan-ui-candidate-layer.py')
layer=importlib.util.module_from_spec(spec);spec.loader.exec_module(layer)


def fixture():
    path='/Game/RED/UI/Test/WBP_TestUI';task='UI-W-'+layer.sha(path.encode())[:12]
    variants={f:dict(paths=[path],file='variants/'+f,source=dict(catalog_sha256=f[0]*64)) for f in ['a.json','b.json']}
    exports={}
    rows=[]
    for file in variants:
        raw={1:dict(index=1,name='Panel',type='GridPanel',sha256='a'*64),
            2:dict(index=2,name='Child',type='Image',sha256='b'*64),
            3:dict(index=3,name='Grid',type='GridSlot',sha256='c'*64),
            4:dict(index=4,name='Named',type='NamedSlot',sha256='d'*64,outer=5,serialized_hex='01030000000000000000'),
            5:dict(index=5,name='Tree',type='WidgetTree',sha256='e'*64)}
        exports[file]=raw
        rows.append(dict(task_id=task,resource_path=path,catalog_file=file,export=3,name='Grid',type='GridSlot',
            sha256='c'*64,status='candidate_evidence_reproduced',automatic_check_passed=True,
            geometry_verified=False,implementation_verified=False,candidate_parse_complete=True,
            interpretation='fixture candidate',decoded=dict(explicit_properties=dict(Parent=1,Content=2,Padding=dict(left=0,right=20)),
                serialized_fields=['Parent','Content','Padding'],omitted_properties=['Row','Column']),
            parent=raw[1],content=raw[2]))
    rows.append(dict(task_id=task,resource_path=path,catalog_file='a.json',export=4,name='Named',type='NamedSlot',sha256='d'*64,
        status='container_candidate_classified',automatic_check_passed=True,geometry_verified=False,implementation_verified=False,
        candidate_parse_complete=False,inherited_properties_decoded=False,interpretation='fixture container',
        raw_serialization_hex=exports['a.json'][4]['serialized_hex']))
    return dict(dataset_id='base',datasets={'base':dict(variants=variants)}),dict(records=rows),exports


class CandidateLayerTests(unittest.TestCase):
    def test_variants_stay_separate_and_nested_values_remain_atomic_candidates(self):
        base,report,exports=fixture();original=copy.deepcopy((base,report))
        index,files=layer.compile_layer(base,report,exports.__getitem__)
        self.assertEqual(index['statistics'],dict(nodes=3,parsed_candidates=2,container_classifications=1,property_observations=6,omitted_property_observations=4,relations=5))
        self.assertEqual(len(index['properties']),5)
        self.assertEqual(len(index['nodes']),3)
        for prop in index['properties'].values():
            absent=prop['field'] in ['Row','Column']
            self.assertEqual(prop['observations'],0 if absent else 2)
            self.assertEqual(prop['omitted_observations'],2 if absent else 0)
            if absent:
                self.assertEqual(prop['types'],[])
                self.assertEqual(files[prop['occurrences']],[])
                self.assertEqual(len(files[prop['omissions']]),2)
            self.assertEqual(prop['status'],'requires_review_not_runtime_verified')
            self.assertNotIn('.left',prop['field'])
        nodes=[n for name,v in files.items() if name.startswith('variants/') for n in v['nodes'].values()]
        parsed=[n for n in nodes if n['candidate_parse_complete']]
        self.assertEqual(parsed[0]['observed_properties']['Padding'],dict(left=0,right=20))
        self.assertEqual(parsed[0]['omitted_properties'],['Row','Column'])
        self.assertIn('nested_field_explicitness_requires_review',parsed[0]['unknowns'])
        self.assertTrue(all(not n['geometry_verified'] and not n['implementation_verified'] for n in nodes))
        self.assertEqual((base,report),original)

    def test_named_payload_is_preserved_and_each_relation_has_both_indices(self):
        base,report,exports=fixture();index,files=layer.compile_layer(base,report,exports.__getitem__)
        named=next(n for n in files['variants/a.json']['nodes'].values() if n['kind']=='NamedSlot')
        self.assertFalse(named['candidate_parse_complete'])
        self.assertIsNone(named['omitted_properties'])
        self.assertEqual(named['observed_properties'],{})
        self.assertIn('opaque_inherited_payload',named['unknowns'])
        self.assertEqual(named['raw_serialization_hex'],exports['a.json'][4]['serialized_hex'])
        relations=files['relations.json'];reverse=files['reverse-relations.json']
        self.assertEqual(sum(map(len,reverse.values())),len(relations))
        for rid,row in relations.items():
            self.assertIn(rid,reverse[row['target_key']])
            node=index['nodes'][row['source']];self.assertIn(rid,files[node['ref']]['nodes'][row['source']]['relations'])

    def test_source_task_and_role_drift_are_rejected(self):
        for mutation in ['sha','task','promotion','link','duplicate','opaque']:
            base,report,exports=fixture()
            if mutation=='sha':report['records'][0]['sha256']='f'*64
            elif mutation=='task':report['records'][0]['task_id']='UI-W-invented'
            elif mutation=='promotion':report['records'][0]['geometry_verified']=True
            elif mutation=='link':report['records'][0]['decoded']['explicit_properties']['Parent']=2
            elif mutation=='duplicate':report['records'].append(copy.deepcopy(report['records'][0]))
            else:report['records'][-1]['raw_serialization_hex']='00'
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                layer.compile_layer(base,report,exports.__getitem__)

    def test_unresolved_resource_remains_in_layer_without_invented_path(self):
        base,report,exports=fixture()
        base['datasets']['base']['variants']['a.json']['paths']=[]
        path='unresolved:a.json'
        for row in report['records']:
            if row['catalog_file']=='a.json':
                row['resource_path']=path;row['task_id']='UI-W-'+layer.sha(path.encode())[:12]
        index,files=layer.compile_layer(base,report,exports.__getitem__)
        self.assertEqual(len(index['resources'][path]),2)
        self.assertTrue(all(not node['resource_path_resolved'] for node in files['variants/a.json']['nodes'].values()))

    def test_publish_reuses_matching_files_and_refuses_tampering(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);files={'index.json':dict(statistics=dict(nodes=1)),'data.json':dict(value=1)}
            with patch.object(layer,'materialize',return_value=('test-dataset',files)):
                first=layer.build(root,root/'base',root/'report','a'*64,root/'output')
                second=layer.build(root,root/'base',root/'report','a'*64,root/'output')
                self.assertFalse(first['reused']);self.assertTrue(second['reused'])
                (Path(first['output'])/'data.json').write_text(json.dumps(dict(value=2)))
                with self.assertRaisesRegex(ValueError,'file differs'):
                    layer.build(root,root/'base',root/'report','a'*64,root/'output')
                self.assertEqual(json.loads((Path(first['output'])/'data.json').read_text())['value'],2)

    def test_checklist_has_stable_open_ids_for_every_candidate_property(self):
        base,report,exports=fixture();index,_=layer.compile_layer(base,report,exports.__getitem__)
        index['dataset_id']='fixture-layer'
        text=layer.checklist(index)
        self.assertEqual(text.count('- [ ] '),len(index['properties']))
        for pid in index['properties']:self.assertIn('- [ ] '+pid+'.',text)
        report['records'][0]['decoded']['explicit_properties']['Padding']['right']=25
        next_index,_=layer.compile_layer(base,report,exports.__getitem__)
        self.assertEqual(index['properties'].keys(),next_index['properties'].keys())

    def test_unknown_input_schema_cannot_reuse_old_join_rules(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);base=root/'base';base.mkdir()
            (base/'index.json').write_text(json.dumps(dict(schema=2,phase='property_inventory')))
            with patch.object(layer.base_verifier,'verify') as check:
                with self.assertRaisesRegex(ValueError,'Unsupported base'):
                    layer.materialize(root,base,root/'missing-report','0'*64)
                check.assert_not_called()
            (base/'index.json').write_text(json.dumps(dict(schema=1,phase='property_inventory')))
            raw=layer.encoded(dict(schema=2,kind='slot_candidate_evidence_reconciliation'))
            report=root/'report.json';report.write_bytes(raw)
            with patch.object(layer.base_verifier,'verify'),patch.object(layer.reconciliation,'build') as repeat:
                with self.assertRaisesRegex(ValueError,'Unsupported reconciliation'):
                    layer.materialize(root,base,report,layer.sha(raw))
                repeat.assert_not_called()


if __name__=='__main__':unittest.main()
