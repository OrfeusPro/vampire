"""Passive links preserve all source rows and unresolved references."""
import importlib.util
import unittest
from pathlib import Path

spec=importlib.util.spec_from_file_location('item_details',Path(__file__).parent/'resource-tools/vampir/build-item-details.py')
details=importlib.util.module_from_spec(spec);spec.loader.exec_module(details)


class PassiveTests(unittest.TestCase):
    def test_material_uses_group_exact_items_per_recipe_but_keep_separate_cost_rows_and_outcomes(self):
        def material(iid,rowid,value):return dict(item_id=iid,item_target_verified=True,record=dict(Id=rowid,CostType='2',CostValue=value))
        a,b=material('12','a','2'),material('12','b','9')
        crafts=[dict(Id='r'),dict(Id='r2')]
        paths={'out':[dict(craft=crafts[0],outcome='SuccessRewardGroupId',reward_chain=[dict(Id='1')],relation_verified=True),
                      dict(craft=crafts[0],outcome='BigSuccessRewardGroupId',reward_chain=[dict(Id='2')],relation_verified=True)],
               '12':[dict(craft=crafts[1],outcome='FailRewardGroupId',reward_chain=[dict(Id='3')],relation_verified=True)]}
        uses=details.craft_material_uses(crafts,[dict(Id='r',Name='Recipe',provenance=dict(csv_record=2))],
            {'r':[a,b,material('123','c','1')],'r2':[material('12','d','0')]},paths)
        self.assertEqual(len(uses['12']),2)
        first=uses['12'][0]
        self.assertEqual([e['record']['CostValue'] for e in first['material_rows']],['2','9'])
        self.assertEqual([e['outcome'] for e in first['results']],['SuccessRewardGroupId','BigSuccessRewardGroupId'])
        self.assertEqual(first['names_en'][0]['provenance'],dict(csv_record=2))
        self.assertFalse(first['runtime_available_verified'])
        self.assertEqual(uses['123'][0]['material_rows'][0]['item_id'],'123')
        self.assertNotIn('results',crafts[0])
        reversed_uses=details.craft_material_uses(crafts,[dict(Id='r',Name='Recipe',provenance=dict(csv_record=2))],
            {'r':[a,b,material('123','c','1')],'r2':[material('12','d','0')]},dict(reversed(list(paths.items()))))
        self.assertEqual(uses,reversed_uses)

    def test_material_uses_exclude_unproven_targets_assets_and_missing_recipe_groups(self):
        craft=dict(Id='r')
        bad=[dict(item_id='12',item_target_verified=False,record=dict(CostType='2')),
             dict(item_id='12',item_target_verified=True,record=dict(CostType='1')),
             dict(item_id=None,item_target_verified=True,record=dict(CostType='2'))]
        orphan=dict(item_id='13',item_target_verified=True,record=dict(CostType='2'))
        self.assertEqual(details.craft_material_uses([craft],[],{'r':bad,'orphan':[orphan]},{}),{})
    def test_craft_materials_use_exact_group_not_empty_craft_info_or_id_prefix(self):
        proof=dict(relation_verified=True,item_target_verified=True)
        rows=[dict(Id='1',GroupId='12',CostType='2',CostParam='45',CostValue='9',CostEnchantLevel='3',UsingGroupId='0',CraftInfoId='',provenance=dict(csv_record=2)),
              dict(Id='2',GroupId='123',CostType='1',CostParam='Gold',CostValue='0',CostEnchantLevel='',UsingGroupId='1',CraftInfoId='12'),
              dict(Id='12suffix',GroupId='missing',CostType='2',CostParam='45',CostValue='2',CraftInfoId='12')]
        groups,issues=details.craft_material_groups([dict(Id='12'),dict(Id='123'),dict(Id='empty')],rows,proof)
        self.assertEqual([r['record']['Id'] for r in groups['12']],['1'])
        self.assertEqual(groups['12'][0]['item_id'],'45')
        self.assertEqual(groups['12'][0]['record']['provenance'],dict(csv_record=2))
        self.assertEqual(groups['12'][0]['record']['CostEnchantLevel'],'3')
        self.assertFalse(groups['12'][0]['runtime_cost_enforcement_verified'])
        self.assertEqual(groups['123'][0]['record']['CostValue'],'0')
        self.assertIsNone(groups['123'][0]['item_id'])
        self.assertEqual(groups['empty'],[])
        self.assertEqual(issues,[dict(kind='material_without_recipe',record=rows[2])])

    def test_craft_material_item_targets_require_proof_type_and_complete_positive_int32(self):
        base=dict(GroupId='c',CostType='2',CostValue='2',UsingGroupId='0')
        params=['0','-1','12tail','2147483648','','0012']
        rows=[dict(base,Id=str(i),CostParam=p) for i,p in enumerate(params)]
        rows.append(dict(base,Id='other',CostType='3',CostParam='12'))
        groups,_=details.craft_material_groups([dict(Id='c')],rows,dict(relation_verified=True,item_target_verified=True))
        self.assertEqual([r['item_id'] for r in groups['c']],[None,None,None,None,None,'12',None])
        self.assertNotIn('item_id',rows[0])
        with self.assertRaises(ValueError):details.craft_material_groups([],rows,dict(relation_verified=False))

    def test_craft_sources_cover_nonbook_items_and_preserve_multiple_paths(self):
        craft=dict(Id='c',FailRewardGroupId='f',SuccessRewardGroupId='s',BigSuccessRewardGroupId='')
        rewards=[dict(Id='1',GroupId='f',Type='1',Param='material',MinCount='2',MaxCount='3',Rate='7'),
            dict(Id='2',GroupId='s',Type='1',Param='armor',MinCount='1',MaxCount='1',Rate='9'),
            dict(Id='3',GroupId='s',Type='1',Param='armor',MinCount='2',MaxCount='2',Rate='11')]
        result,issues=details.craft_origins({'armor','material'},[craft],rewards,[])
        self.assertEqual(issues,[])
        self.assertEqual(len(result['armor']),2)
        self.assertEqual(result['material'][0]['outcome'],'FailRewardGroupId')
        self.assertEqual([x['reward_chain'][-1]['Rate'] for x in result['armor']],['9','11'])
        self.assertFalse(result['armor'][0]['material_link_verified'])
        self.assertIsNone(result['armor'][0]['chance_percent'])

    def test_craft_expansion_bounds_keep_siblings_and_fail_on_excess(self):
        craft=dict(Id='c',FailRewardGroupId='',SuccessRewardGroupId='g',BigSuccessRewardGroupId='')
        rewards=[dict(Id='1',GroupId='g',Type='12',Param='nested'),dict(Id='2',GroupId='g',Type='1',Param='item'),
            dict(Id='3',GroupId='nested',Type='1',Param='item')]
        result,issues=details.craft_origins({'item'},[craft],rewards,[],max_depth=1)
        self.assertEqual(len(result['item']),1)
        self.assertEqual(issues[0]['kind'],'depth_limit')
        with self.assertRaisesRegex(ValueError,'bound'):
            details.craft_origins({'item'},[craft],rewards,[],max_paths=1)

    def test_book_native_binding_links_target_without_guaranteeing_acquisition(self):
        binding=dict(relation_verified=True,effect_type=4,excluded_item_types=[58])
        items=[dict(Id='b',Type='31',EffectType='4',EffectParams='00012'),dict(Id='missing',Type='31',EffectType='4',EffectParams='42')]
        result=details.skill_books(items,[dict(Id='12')],[dict(Id='12',Name='Skill')],{'31':dict(name='EItemType::SkillBook')},binding)
        self.assertEqual(result['b']['skill_id'],'12')
        self.assertEqual(result['b']['skill'],dict(Id='12'))
        self.assertEqual(result['b']['skill_names_en'][0]['Name'],'Skill')
        self.assertTrue(result['missing']['relation_verified'])
        self.assertIsNone(result['missing']['skill'])
        self.assertFalse(result['b']['acquisition_verified'])

    def test_book_binding_rejects_wrong_effect_malformed_and_overflow_targets(self):
        binding=dict(relation_verified=True,effect_type=4,excluded_item_types=[58])
        for effect,param in [('1','12'),('4','12tail'),('4',''),('4','0'),('4','2147483648'),('4','１２')]:
            row=dict(Id='b',Type='31',EffectType=effect,EffectParams=param)
            result=details.skill_books([row],[dict(Id=param)],[],{'31':dict(name='EItemType::SkillBook')},binding)['b']
            self.assertFalse(result['relation_verified'])
            self.assertIsNone(result['skill_id'])
            self.assertIsNone(result['skill'])

    def test_craft_outcomes_keep_distinct_reward_paths_and_raw_counts(self):
        craft=dict(Id='c',FailRewardGroupId='f',SuccessRewardGroupId='s',BigSuccessRewardGroupId='b',SuccessRate='900000')
        rewards=[dict(Id='1',GroupId='f',Type='1',Param='other'),dict(Id='2',GroupId='s',Type='12',Param='nested'),dict(Id='3',GroupId='nested',Type='1',Param='book',MinCount='1',MaxCount='2'),dict(Id='4',GroupId='b',Type='1',Param='book',MinCount='3',MaxCount='3')]
        result,issues=details.craft_origins({'book','missing'},[craft],rewards,[dict(Id='c',Name='Recipe')])
        self.assertFalse(issues)
        self.assertEqual(result['missing'],[])
        success,big=result['book']
        self.assertEqual(success['outcome'],'SuccessRewardGroupId')
        self.assertEqual([r['Id'] for r in success['reward_chain']],['2','3'])
        self.assertEqual(big['outcome'],'BigSuccessRewardGroupId')
        self.assertEqual(big['reward_chain'][-1]['MinCount'],'3')
        self.assertEqual(success['craft']['SuccessRate'],'900000')
        self.assertTrue(success['relation_verified'])
        self.assertIsNone(success['chance_percent'])
        self.assertFalse(success['runtime_available_verified'])
        self.assertFalse(success['material_link_verified'])

    def test_craft_cycles_and_missing_groups_are_visible_and_do_not_hide_siblings(self):
        crafts=[dict(Id='c',FailRewardGroupId='absent',SuccessRewardGroupId='g',BigSuccessRewardGroupId='')]
        rewards=[dict(Id='1',GroupId='g',Type='12',Param='g'),dict(Id='2',GroupId='g',Type='1',Param='book')]
        result,issues=details.craft_origins({'book'},crafts,rewards,[])
        self.assertEqual(len(result['book']),1)
        self.assertEqual({i['kind'] for i in issues},{'cycle','missing_group'})
        self.assertEqual(result['book'][0]['names_en'],[])

    def test_books_require_native_type_and_do_not_promote_numeric_match(self):
        items=[dict(Id='b',Type='31',EffectParams='s'),dict(Id='c',Type='30',EffectParams='s'),dict(Id='missing',Type='31',EffectParams='unknown')]
        result=details.skill_books(items,[dict(Id='s')],[dict(Id='s',Name='Name')],{'31':dict(name='EItemType::SkillBook')})
        self.assertEqual(set(result),{'b','missing'})
        self.assertEqual(result['b']['candidate_skill']['Id'],'s')
        self.assertFalse(result['b']['relation_verified'])
        self.assertFalse(result['b']['acquisition_verified'])
        self.assertIsNone(result['missing']['candidate_skill'])
        self.assertEqual(result['missing']['candidate_names'],[])
        self.assertEqual(details.skill_books(items,[],[],{}),{})

    def test_restrictions_keep_zero_codes_all_rows_and_unresolved_links(self):
        items=[dict(LimitGroupId='g',ItemUseLimitId='u'),dict(LimitGroupId='absent',ItemUseLimitId='missing')]
        semantics=dict(item_limits={'0':dict(name='DisableEnchant')},room_limits={'0':dict(name='UseOnly')})
        result=details.restriction_groups(items,[dict(GroupId='g',LimitType='0'),dict(GroupId='g',LimitType='99')],
            [dict(Id='u',WorldIdMultiString='10015, 20001',RoomLimitType='0',RoomTypeList='World,UnknownRoom')],semantics)
        self.assertEqual(result['item_limits']['g'][0]['kind']['name'],'DisableEnchant')
        self.assertIsNone(result['item_limits']['g'][1]['kind'])
        self.assertEqual(result['item_limits']['absent'],[])
        self.assertIsNone(result['use_limits']['missing'])
        self.assertEqual(result['use_limits']['u']['world_ids'],['10015','20001'])
        self.assertEqual(result['use_limits']['u']['room_types'],['World','UnknownRoom'])
        self.assertFalse(result['use_limits']['u']['runtime_rule_verified'])

    def test_missing_semantics_does_not_turn_room_fallback_into_no_restriction(self):
        result=details.restriction_groups([dict(LimitGroupId='',ItemUseLimitId='u')],[],
            [dict(Id='u',WorldIdMultiString='20001',RoomLimitType='2',RoomTypeList='')],None)
        self.assertIsNone(result['use_limits']['u']['room_mode'])
        self.assertEqual(result['use_limits']['u']['record']['RoomLimitType'],'2')
        self.assertEqual(result['item_limits'],{})

    def test_multiple_skills_and_localizations_are_preserved(self):
        rows=details.passive_groups([dict(PassiveSkillGroupId='g')],
            [dict(GroupId='g',SkillInfoId='s1'),dict(GroupId='g',SkillInfoId='s2'),dict(GroupId='other',SkillInfoId='s3')],
            [dict(Id='s1'),dict(Id='s2')],[dict(Id='s1',Name='one'),dict(Id='s1',Name='alternate')],
            [dict(SkillId='s1',OperationParam1='12'),dict(SkillId='s1',OperationParam1='42')])
        self.assertEqual(list(rows),['g'])
        skills=rows['g']['skills']
        self.assertEqual([s['id'] for s in skills],['s1','s2'])
        self.assertEqual(len(skills[0]['names_en']),2)
        self.assertEqual([r['OperationParam1']for r in skills[0]['operations']],['12','42'])
        self.assertFalse(rows['g']['runtime_activation_verified'])

    def test_missing_group_and_skill_are_explicit(self):
        rows=details.passive_groups([dict(PassiveSkillGroupId='missing'),dict(PassiveSkillGroupId='g'),dict(PassiveSkillGroupId='')],
            [dict(GroupId='g',SkillInfoId='absent')],[],[],[])
        self.assertEqual(rows['missing']['skills'],[])
        self.assertIsNone(rows['g']['skills'][0]['record'])
        self.assertEqual(rows['g']['skills'][0]['names_en'],[])
        self.assertNotIn('',rows)


if __name__=='__main__':
    unittest.main()
