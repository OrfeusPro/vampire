import importlib.util
import unittest
from pathlib import Path

spec=importlib.util.spec_from_file_location('item_boxes_test',Path(__file__).parent/'resource-tools/vampir/item-box-links.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class ItemBoxTests(unittest.TestCase):
    def test_verified_mode_names_do_not_claim_runtime_selection(self):
        types={'0':dict(name='Fixed',value=0),'2':dict(name='Random',value=2),'7':dict(name='Max',value=7)}
        for code,name in [('0','Fixed'),('2','Random'),('7',None),('99',None),('',None)]:
            box=self.box();box['RewardGroupType']=code
            result=module.boxes([dict(Id='box')],[box],[],mode_types=types)['box']
            self.assertEqual(result['reward_group_mode']['name'] if result['reward_group_mode'] else None,name)
            self.assertEqual(result['reward_group_mode_verified'],name is not None)
            self.assertFalse(result['runtime_selection_verified'])
            self.assertFalse(result['runtime_opening_verified'])
            self.assertEqual(result['reward_group_type_raw'],code)

    def box(self,**extra):
        return dict(ItemId='box',RewardGroupId='g',RewardGroupType='2',**extra)

    def test_nested_branches_preserve_rates_counts_and_nonitem_rewards(self):
        rewards=[dict(Id='a',GroupId='g',Type='12',Param='nested',Rate='100'),
                 dict(Id='b',GroupId='g',Type='2',Param='500',MinCount='1',MaxCount='1',Rate='7'),
                 dict(Id='c',GroupId='nested',Type='1',Param='item',MinCount='2',MaxCount='4',Rate='25')]
        result=module.boxes([dict(Id='box'),dict(Id='item')],[self.box()],rewards)['box']
        self.assertEqual(len(result['paths']),2)
        item_path=next(p for p in result['paths'] if p['item_id']=='item')
        self.assertEqual([r['Rate'] for r in item_path['reward_chain']],['100','25'])
        self.assertEqual(item_path['reward_chain'][-1]['MaxCount'],'4')
        self.assertIsNone(item_path['chance_percent'])
        self.assertFalse(item_path['runtime_available_verified'])
        self.assertIsNone(next(p for p in result['paths'] if p['item_id'] is None)['item_present'])
        self.assertFalse(result['reward_group_mode_verified'])

    def test_same_item_paths_not_merged_and_key_is_not_reward(self):
        rewards=[dict(Id=str(i),GroupId='g',Type='1',Param='item',MinCount='1',MaxCount='1',Rate=str(i)) for i in [1,2]]
        result=module.boxes([dict(Id=x) for x in ['box','item','key']],[self.box(KeyItemInfoId='key',KeyItemCount='3')],rewards)['box']
        self.assertEqual([p['item_id'] for p in result['paths']],['item','item'])
        self.assertEqual(result['key_item_id'],'key')
        self.assertEqual(result['key_count'],'3')
        self.assertEqual(result['issues'],[])

    def test_cycle_missing_group_and_item_do_not_hide_valid_sibling(self):
        rewards=[dict(Id='1',GroupId='g',Type='12',Param='g'),dict(Id='2',GroupId='g',Type='12',Param='absent'),dict(Id='3',GroupId='g',Type='1',Param='missing')]
        result=module.boxes([dict(Id='box')],[self.box(KeyItemInfoId='missing-key')],rewards)['box']
        self.assertEqual(len(result['paths']),1)
        self.assertFalse(result['paths'][0]['item_present'])
        self.assertEqual({r['kind'] for r in result['issues']},{'cycle','missing_group','missing_item','missing_key_item'})

    def test_depth_and_expansion_bounds_and_duplicate_box(self):
        rewards=[dict(Id='1',GroupId='g',Type='12',Param='other'),dict(Id='2',GroupId='other',Type='1',Param='item')]
        rows=[dict(Id='box'),dict(Id='item')]
        result=module.boxes(rows,[self.box()],rewards,max_depth=1)['box']
        self.assertEqual(result['issues'][0]['kind'],'depth_limit')
        with self.assertRaisesRegex(ValueError,'bound'):
            module.boxes(rows,[self.box()],rewards,max_paths=1)
        with self.assertRaisesRegex(ValueError,'Duplicate'):
            module.boxes(rows,[self.box(),self.box()],rewards)

    def test_reverse_sources_keep_branch_count_and_exclude_missing_nonitem(self):
        groups={'box':dict(paths=[dict(item_id='book',item_present=True),dict(item_id='book',item_present=True),dict(item_id='missing',item_present=False),dict(item_id=None,item_present=None)])}
        result=module.sources(groups)
        self.assertEqual(result,{'book':[dict(box_item_id='box',path_count=2)]})


if __name__=='__main__':unittest.main()
