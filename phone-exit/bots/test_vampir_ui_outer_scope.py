"""Serialized Outer roots must never be inferred from names or confused with slot parenting."""
import copy
import importlib.util
from pathlib import Path
import unittest
import tempfile
from unittest.mock import patch

HERE=Path(__file__).parent/'resource-tools/vampir'
spec=importlib.util.spec_from_file_location('outer_scope',HERE/'ui_outer_scope.py')
outer=importlib.util.module_from_spec(spec);spec.loader.exec_module(outer)
spec=importlib.util.spec_from_file_location('outer_scanner',HERE/'scan-ui-outer-scopes.py')
scanner=importlib.util.module_from_spec(spec);spec.loader.exec_module(scanner)


def fixture():
    def e(i,name,kind,parent):return dict(index=i,name=name,type=kind,outer=parent,sha256=str(i)*4)
    exports=[e(1,'First_C','WidgetBlueprintGeneratedClass',0),e(2,'Second_C','WidgetBlueprintGeneratedClass',0),
        e(3,'WidgetTree','WidgetTree',1),e(4,'WidgetTree','WidgetTree',2),
        e(5,'Canvas','CanvasPanel',3),e(6,'Button','NkButton',4),e(7,'CanvasSlot','CanvasPanelSlot',5),
        e(8,'ButtonSlot','ButtonSlot',6),e(9,'Image','Image',3),e(10,'Image','Image',4),
        e(11,'Default__First_C','local_export_1',0),e(12,'Broken','Image',99),
        e(13,'Cycle','ButtonSlot',14),e(14,'CycleParent','Border',13)]
    rows={e['index']:e for e in exports}
    slot=lambda i,p,c:dict(provenance=dict(slot_export=i,sha256=rows[i]['sha256']),decoded=dict(parent_export=p,content_export=c))
    catalog=dict(root_export=rows[1],controls=[dict(export=i,sha256=rows[i]['sha256']) for i in [5,6,9,10,11]],
        decoded_slots=[slot(7,5,9),slot(8,6,10)],excluded_slots=[dict(provenance=dict(slot_export=13,sha256=rows[13]['sha256']))])
    return exports,catalog


class OuterScopeTests(unittest.TestCase):
    def test_two_roots_partition_the_same_names_by_indices(self):
        exports,catalog=fixture();original=copy.deepcopy((exports,catalog))
        ownership=outer.compile_ownership(exports);result=outer.partition(catalog,ownership)
        self.assertEqual(result['groups']['controls'],dict(selected=[5,9],foreign=[6,10],unowned=[11],unresolved=[]))
        self.assertEqual(result['groups']['decoded_slots']['selected'],[7])
        self.assertEqual(result['groups']['decoded_slots']['foreign'],[8])
        self.assertEqual(ownership['exports']['9']['chain'],[9,3,1])
        self.assertIsNone(result['runtime_visible_root']);self.assertFalse(result['geometry_verified'])
        self.assertEqual((exports,catalog),original)

    def test_unowned_cycle_and_missing_outer_stay_explicit(self):
        exports,catalog=fixture();ownership=outer.compile_ownership(exports)
        self.assertIsNone(ownership['exports']['11']['owner_root'])
        self.assertEqual(ownership['exports']['12']['state'],'dangling_outer')
        self.assertEqual(ownership['exports']['13']['state'],'outer_cycle')
        result=outer.partition(catalog,ownership)
        self.assertEqual(result['groups']['excluded_slots']['unresolved'],[13])

    def test_slot_crossing_roots_is_flagged_not_silently_reassigned(self):
        exports,catalog=fixture();catalog['decoded_slots'][0]['decoded']['content_export']=10
        result=outer.partition(catalog,outer.compile_ownership(exports))
        self.assertEqual(len(result['cross_scope_relations']),1)
        self.assertEqual(result['cross_scope_relations'][0]['endpoints']['content']['owner_root'],2)
        self.assertEqual(result['groups']['decoded_slots']['selected'],[7])

    def test_duplicate_ids_and_wrong_source_root_are_rejected(self):
        exports,catalog=fixture()
        with self.assertRaisesRegex(ValueError,'Duplicate'):outer.compile_ownership(exports+[exports[0]])
        catalog['root_export']=dict(index=1,sha256='wrong')
        with self.assertRaisesRegex(ValueError,'root differs'):outer.partition(catalog,outer.compile_ownership(exports))

    def test_source_projection_quarantines_foreign_and_unowned_without_runtime_promotion(self):
        exports,catalog=fixture();view=outer.partition(catalog,outer.compile_ownership(exports))
        variant=dict(controls=catalog['controls'],slots=catalog['decoded_slots'],excluded_slots=catalog['excluded_slots'])
        original=copy.deepcopy(variant)
        projected,scope=outer.project_variant(variant,view)
        self.assertEqual([c['export'] for c in projected['controls']],[5,9])
        self.assertEqual([s['provenance']['slot_export'] for s in projected['slots']],[7])
        self.assertEqual(scope['quarantine']['controls']['foreign'],[6,10])
        self.assertEqual(scope['quarantine']['controls']['unowned'],[11])
        self.assertTrue(scope['requires_review'])
        self.assertIsNone(scope['runtime_visible_root'])
        self.assertEqual(variant,original)

    def test_single_available_root_does_not_claim_orphan_by_name(self):
        exports,_=fixture()
        exports=[e for e in exports if e['index'] in [1,3,5,9,11]]
        result=outer.compile_ownership(exports)
        self.assertEqual(len(result['roots']),1)
        self.assertIsNone(result['exports']['11']['owner_root'])

    def test_immutable_publication_reuses_exact_data_and_refuses_changed_branch(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);files={'index.json':dict(statistics=dict(variants=1)),'branch.json':dict(source_root=1)}
            with patch.object(scanner,'derive',return_value=('fixture',files)):
                first=scanner.build(root,root/'audit','a'*64,root/'out')
                self.assertFalse(first['reused'])
                self.assertTrue(scanner.build(root,root/'audit','a'*64,root/'out')['reused'])
                target=Path(first['output'])/'branch.json';target.write_bytes(scanner.encoded(dict(source_root=2)))
                with self.assertRaisesRegex(ValueError,'file differs'):
                    scanner.build(root,root/'audit','a'*64,root/'out')
                self.assertEqual(target.read_bytes(),scanner.encoded(dict(source_root=2)))


if __name__=='__main__':unittest.main()
