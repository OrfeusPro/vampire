"""Rule changes, removed sources, reverse consumers and conservative gaps."""
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / 'resource-tools/vampir'))
import ui_composition_graph as graph
import ui_rule_impact as impact


def fixture():
    records = []
    for name, children in [('Leaf', []), ('Page', ['Leaf']), ('Shell', ['Page']), ('Other', [])]:
        records.append(dict(id='W-' + name, path='/Game/' + name, name=name, variants=[dict(
            file=name + '.json', sha256='a' * 64,
            controls=[dict(name=c, type=c + '_C', export=i, sha256='b' * 64) for i, c in enumerate(children)])]))
    ready = dict(providers={'leaf.py': 'a' * 64, 'page.py': 'b' * 64}, rules=[
        dict(id='leaf', provider='leaf.py', version=1, dependencies=[], widget_types=['Leaf_C'], criteria=['03']),
        dict(id='page', provider='page.py', version=1, dependencies=['leaf'], widget_types=['Page_C'], criteria=['02'])])
    return graph.compile_graph(records), ready


class ImpactTests(unittest.TestCase):
    def test_priority_coverage_is_transitive_and_preserves_missing_classes(self):
        g, _ = fixture()
        result = impact.priority_coverage(g, ['Leaf_C', 'Missing_C'])
        self.assertEqual(result['Leaf_C']['resources'], 3)
        self.assertEqual(result['Leaf_C']['source_variants'], 1)
        self.assertEqual(result['Missing_C']['source_variants'], 0)
        self.assertFalse(result['Leaf_C']['runtime_binding_verified'])

    def test_unchanged_does_not_close_previous_tasks(self):
        g, r = fixture()
        result = impact.compile_impact(g, g, r, r)
        self.assertFalse(result['queue'])
        self.assertFalse(result['tasks_closed'])
        self.assertIn('прежние открытые', impact.markdown(result))

    def test_rule_change_propagates_to_dependent_rules_and_consumers(self):
        g, r = fixture()
        newer = copy.deepcopy(r)
        newer['providers']['leaf.py'] = 'c' * 64
        result = impact.compile_impact(g, g, r, newer)
        self.assertEqual(result['affected_rules'], ['leaf', 'page'])
        self.assertEqual(set(result['queue']), {'UI-W-Leaf', 'UI-W-Page', 'UI-W-Shell'})
        self.assertEqual(result['queue']['UI-W-Shell']['criteria'], ['02', '03'])
        self.assertNotIn('UI-W-Other', result['queue'])

    def test_removed_source_keeps_old_consumers(self):
        g, r = fixture()
        newer = copy.deepcopy(g)
        del newer['nodes']['/Game/Leaf|Leaf.json']
        # Also remove the candidate from the current consumer to model catalog removal.
        newer['nodes']['/Game/Page|Page.json']['dependencies'][0]['candidates'] = []
        result = impact.compile_impact(g, newer, r, r)
        self.assertEqual(set(result['queue']), {'UI-W-Leaf', 'UI-W-Page', 'UI-W-Shell'})
        self.assertTrue(result['queue']['UI-W-Leaf']['variants']['/Game/Leaf|Leaf.json']['removed'])
        self.assertEqual(result['queue']['UI-W-Shell']['criteria'], impact.CRITERIA)

    def test_unknown_rule_scope_queues_all_without_hiding_gap(self):
        g, r = fixture()
        newer = copy.deepcopy(r)
        del newer['rules'][0]['widget_types']
        result = impact.compile_impact(g, g, r, newer)
        self.assertEqual(result['statistics']['resources'], 4)
        self.assertEqual(result['rule_scope_unknowns'], ['leaf'])

    def test_invalid_rule_contract_rejected(self):
        g, r = fixture()
        for change in ('dependency', 'sha', 'criterion', 'duplicate'):
            newer = copy.deepcopy(r)
            if change == 'dependency': newer['rules'][0]['dependencies'] = ['missing']
            if change == 'sha': newer['providers']['leaf.py'] = 'short'
            if change == 'criterion': newer['rules'][0]['criteria'] = ['99']
            if change == 'duplicate': newer['rules'].append(newer['rules'][0])
            with self.subTest(change=change), self.assertRaises(ValueError):
                impact.compile_impact(g, g, r, newer)

    def test_cycles_and_multiple_variants_preserve_unique_resource_tasks(self):
        g, r = fixture()
        newer = copy.deepcopy(g)
        leaf = newer['nodes']['/Game/Leaf|Leaf.json']
        leaf['dependencies'] = [dict(control=dict(name='shell', type='Shell_C', export=8, sha256='c' * 64),
                                     candidates=['/Game/Shell|Shell.json'], status='candidate')]
        duplicate = copy.deepcopy(leaf)
        duplicate['file'] = 'Leaf-archive.json'
        newer['nodes']['/Game/Leaf|Leaf-archive.json'] = duplicate
        result = impact.compile_impact(g, newer, r, r)
        self.assertEqual(set(result['queue']), {'UI-W-Leaf', 'UI-W-Page', 'UI-W-Shell'})
        self.assertEqual(len(result['queue']['UI-W-Leaf']['variants']), 2)
        self.assertEqual(result, impact.compile_impact(g, newer, r, r))


if __name__ == '__main__':
    unittest.main()
