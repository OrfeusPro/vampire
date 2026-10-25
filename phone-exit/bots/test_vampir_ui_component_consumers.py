"""Shared classes keep distinct controls/variants while prioritizing unique resource consumers."""
import importlib.util
from pathlib import Path
import unittest
import copy

p=Path(__file__).parent/'resource-tools/vampir/ui_component_consumers.py'
s=importlib.util.spec_from_file_location('consumer_index',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)


class ConsumerTests(unittest.TestCase):
    def fixture(self):
        def edge(i,kind,candidates):return dict(control=dict(export=i,type=kind,name='Button',sha256='a'*64),candidates=candidates,status='candidate')
        return dict(nodes={
            'window-old':dict(resource_path='/Window',resource_id='W-one',dependencies=[edge(1,'Button_C',['button-a','button-b']),edge(2,'Button_C',['button-a','button-b'])]),
            'window-new':dict(resource_path='/Window',resource_id='W-one',dependencies=[edge(1,'Button_C',['button-a','button-b'])]),
            'second':dict(resource_path='/Second',resource_id='W-two',dependencies=[edge(1,'Button_C',['button-a','button-b']),edge(2,'Missing_C',[])]),
            'button-a':dict(resource_path='/Button',resource_id='W-b',dependencies=[]),
            'button-b':dict(resource_path='/Button',resource_id='W-b',dependencies=[])})

    def test_resource_priority_does_not_merge_controls_or_variants(self):
        graph=self.fixture();original=copy.deepcopy(graph);result=m.compile_consumers(graph)
        button=result['classes']['Button_C']
        self.assertEqual(button['consumer_resource_count'],2)
        self.assertEqual(button['edge_count'],4)
        self.assertEqual(button['candidate_variants'],['button-a','button-b'])
        self.assertEqual(len(result['reverse_variants']['button-a']),4)
        self.assertFalse(button['runtime_binding_verified'])
        self.assertEqual(result['priority'][0],'Button_C')
        self.assertEqual(graph,original)

    def test_missing_class_is_retained_and_missing_target_rejected(self):
        graph=self.fixture();result=m.compile_consumers(graph)
        self.assertTrue(result['classes']['Missing_C']['unresolved'])
        graph['nodes']['second']['dependencies'][0]['candidates']=['unknown']
        with self.assertRaisesRegex(ValueError,'Unknown component'):m.compile_consumers(graph)


if __name__=='__main__':unittest.main()
