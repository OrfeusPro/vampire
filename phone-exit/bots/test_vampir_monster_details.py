"""Monster details preserve conditional reward chains and Battle variants."""
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('monster_details', Path(__file__).parent / 'resource-tools/vampir/build-monster-details.py')
details = importlib.util.module_from_spec(spec)
spec.loader.exec_module(details)


class MonsterDetailsTests(unittest.TestCase):
    def test_portraits_only_follow_explicit_fields_and_exact_profile_npc_id(self):
        image=dict(file='a.png',asset_path='/Game/Portrait')
        npc=dict(Id='1',Img='',Blueprint='BP_Similar',provenance=dict(csv_record=2))
        profiles=[dict(NpcInfoId='1',GroupId='g',Img='Portrait',UseSkillId='999',provenance=dict(csv_record=3)),
                  dict(NpcInfoId='2',GroupId='other',Img='Wrong')]
        icons={'Portrait':dict(status='exact_unique_name',images=[image]),'Wrong':dict(status='exact_unique_name',images=[dict(file='wrong.png',asset_path='/Game/Wrong')])}
        result=details.npc_portraits(npc,profiles,icons)
        self.assertEqual([x['file'] for x in result['images']],['a.png'])
        self.assertEqual(result['sources'][0]['group_id'],'g')
        self.assertEqual(result['sources'][0]['record']['UseSkillId'],'999')
        self.assertFalse(result['runtime_appearance_verified'])
        self.assertFalse(result['family_match_used'])
        self.assertNotIn('field_sources',image)
        self.assertEqual(details.npc_portraits(npc,[],icons)['status'],'not_declared')

    def test_portrait_duplicates_keep_both_field_sources_and_distinct_paths_are_retained(self):
        npc=dict(Id='1',Img='Portrait')
        profiles=[dict(NpcInfoId='1',GroupId='g',Img='Portrait')]
        icons={'Portrait':dict(status='ambiguous_paths',images=[dict(file='a.png',asset_path='/Game/A/Portrait'),dict(file='b.png',asset_path='/Game/B/Portrait')])}
        result=details.npc_portraits(npc,profiles,icons)
        self.assertEqual(len(result['images']),2)
        self.assertEqual(result['images'][0]['field_sources'],[0,1])
        self.assertEqual(result['images'][1]['field_sources'],[0,1])
        missing=details.npc_portraits(dict(Id='1',Img='NotFound'),[],icons)
        self.assertEqual(missing['status'],'missing')
        self.assertEqual(missing['images'],[])

    def test_reverse_passive_items_keep_exact_group_all_rows_and_no_activation_claim(self):
        groups={'g':dict(skills=[dict(id='s',set_record=dict(GroupId='g',SkillInfoId='s',Index='1')),
            dict(id='s',set_record=dict(GroupId='g',SkillInfoId='s',Index='2')),
            dict(id='other',set_record=dict(GroupId='wrong',SkillInfoId='other'))])}
        items={'i':dict(data=dict(PassiveSkillGroupId='g',provenance=dict(csv_record=2)),names_en=[dict(Name='Item')]),
            'i2':dict(data=dict(PassiveSkillGroupId='g')), 'unrelated':dict(data=dict(PassiveSkillGroupId='missing'))}
        result=details.skill_passive_item_index(groups,items)
        self.assertEqual(set(result),{'s'})
        self.assertEqual([r['item_id'] for r in result['s']],['i','i2'])
        self.assertEqual(len(result['s'][0]['set_records']),2)
        self.assertEqual(result['s'][0]['provenance'],dict(csv_record=2))
        self.assertTrue(result['s'][0]['relation_verified'])
        self.assertFalse(result['s'][0]['runtime_activation_verified'])
        self.assertEqual(details.skill_passive_item_index({},items),{})

    def test_skill_books_reverse_only_verified_ids_and_keep_all_variants(self):
        books={iid:dict(relation_verified=True,skill_id='12',record=dict(provenance=dict(csv_record=n))) for n,iid in enumerate(['b1','b2'],2)}
        books['candidate']=dict(relation_verified=False,skill_id='12')
        books['missing_item']=dict(relation_verified=True,skill_id='12')
        items={'b1':dict(names_en=[dict(Name='Book'),dict(Name='Book')],icon=dict(images=[]),rarity=dict(id='3')),
               'b2':dict(names_en=[])}
        result=details.skill_book_index(books,items)
        self.assertEqual([b['item_id'] for b in result['12']],['b1','b2'])
        self.assertEqual(result['12'][0]['label'],'Book')
        self.assertEqual(result['12'][1]['label'],'Книга b2')
        self.assertEqual(result['12'][0]['provenance'],dict(csv_record=2))
        self.assertTrue(result['12'][0]['relation_verified'])
        self.assertFalse(result['12'][0]['acquisition_verified'])

    def test_missing_skill_record_does_not_erase_verified_book_target(self):
        result=details.skill_book_index({'b':dict(relation_verified=True,skill_id='missing',record={})},{'b':{}})
        self.assertEqual(result['missing'][0]['item_id'],'b')
        self.assertEqual(details.skill_book_index({'b':dict(relation_verified=True,skill_id=None)},{'b':{}}),{})

    def test_reverse_skill_index_preserves_variants_and_exact_ids(self):
        npcs={'n1':dict(BattleGroupId='b'),'n2':dict(BattleGroupId='b'),'n3':dict(BattleGroupId='other')}
        battles={'b':[dict(SkillIdList='1, 11,1'),dict(SkillIdList='2,,')],
                 'other':[dict(SkillIdList='11')]}
        self.assertEqual(details.skill_npc_index(npcs,battles),
            {'1':['n1','n2'],'11':['n1','n2','n3'],'2':['n1','n2']})

    def test_skill_names_prefer_nonempty_english_and_preserve_korean_source(self):
        english=[dict(Name=''),dict(Name='Shield Wall',provenance=dict(csv_record=3))]
        korean=[dict(Name='###기본 공격 01',provenance=dict(csv_record=9))]
        named=details.skill_display_names(english,korean)
        self.assertEqual([n['text'] for n in named],['Shield Wall'])
        self.assertEqual(named[0]['language'],'en')
        translated=details.skill_display_names([dict(Name=' ')],korean+korean)
        self.assertEqual(len(translated),1)
        self.assertEqual(translated[0]['text'],'Базовая атака 01')
        self.assertEqual(translated[0]['original'],'###기본 공격 01')
        self.assertTrue(translated[0]['translated'])
        self.assertTrue(translated[0]['source_marked'])
        self.assertEqual(translated[0]['provenance']['csv_record'],9)
        other=details.skill_display_names([],[dict(Name='###독 뱉기')])[0]
        self.assertEqual(other['text'],'###독 뱉기')
        self.assertFalse(other['translated'])
        self.assertEqual(details.skill_display_names([dict(Name='')],[]),[])

    def test_target_and_condition_domains_are_separate_and_fallbacks_are_unknown(self):
        semantics = dict(targets={'4':dict(name='Enemy',name_offset=12),'0':dict(name='All',name_offset=13)},
            target_conditions={'4':dict(name='Npc',name_offset=14),'0':dict(name='LowHpRate',name_offset=15)},
            unknown_target_value=15,unknown_target_condition_value=17)
        self.assertEqual(details.target_detail('4',semantics)['name'],'Enemy')
        self.assertEqual(details.target_detail('4',semantics,True)['name'],'Npc')
        self.assertEqual(details.target_detail('0',semantics,True)['name'],'LowHpRate')
        self.assertEqual(details.target_detail('0',semantics)['name'],'All')
        for value,condition in [('15',False),('17',True)]:
            result=details.target_detail(value,semantics,condition)
            self.assertIsNone(result['name'])
            self.assertEqual(result['status'],'parser_fallback')
            self.assertFalse(result['runtime_predicate_verified'])
        self.assertEqual(details.target_detail('99',semantics)['status'],'unknown')
        self.assertIsNone(details.target_detail('',semantics))
        self.assertIsNone(details.target_detail('4',None))

    def test_condition_zero_is_always_but_parser_fallback_is_not(self):
        semantics = dict(conditions={'0':dict(name='Always',name_offset=123)},unknown_parser_value=43)
        base = dict(FireCondition='0',FireConditionParam1='17',FireConditionParam2='0',FireConditionParam3='')
        known = details.condition_detail(base,semantics)
        self.assertEqual(known['name'],'Always')
        self.assertEqual(known['parameters'],['17','0',''])
        self.assertFalse(known['runtime_predicate_verified'])
        for value,status in [('43','parser_fallback'),('255','unknown')]:
            unknown = details.condition_detail(dict(base,FireCondition=value),semantics)
            self.assertIsNone(unknown['name'])
            self.assertEqual(unknown['status'],status)
        self.assertIsNone(details.condition_detail(base,None))

    def test_battle_variants_not_overwritten_by_group_id(self):
        rows = [dict(GroupId='battle1', HP='100'), dict(GroupId='battle1', HP='900')]
        grouped = details.group_battles(rows)
        self.assertEqual([r['HP'] for r in grouped['battle1']], ['100', '900'])
        self.assertEqual([r['provenance']['csv_record'] for r in grouped['battle1']], [2, 3])

    def test_conditional_chains_not_merged_or_converted_to_percentages(self):
        chain1 = dict(npc_id='n1', min_count='1', max_count='2', raw_rate='10000', acquisition_method_type='1', chance_percent=None)
        chain2 = dict(npc_id='n1', min_count='10', max_count='10', raw_rate='30', acquisition_method_type='9', chance_percent=None)
        grouped = details.drops_by_npc({'coin': [chain1, chain2]})
        self.assertEqual(grouped['n1']['coin'], [chain1, chain2])

    def test_same_item_for_different_npcs_keeps_separate_chains(self):
        a, b = dict(npc_id='a', min_count='1'), dict(npc_id='b', min_count='99')
        grouped = details.drops_by_npc({'item': [a, b]})
        self.assertEqual(grouped['a']['item'], [a])
        self.assertEqual(grouped['b']['item'], [b])


if __name__ == '__main__':
    unittest.main()
