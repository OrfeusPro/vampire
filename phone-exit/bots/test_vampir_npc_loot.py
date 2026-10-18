"""Do not guess icon paths or silently tone-map nonstandard float resources."""
import importlib.util
import struct
import unittest
from pathlib import Path
import numpy as np


def load(name,file):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).parent/'resource-tools/vampir'/file)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


loot=load('npc_loot','build-npc-loot.py');floats=load('float_icons','export-float-icons.py')


class NpcLootTests(unittest.TestCase):
    def test_multiline_source_values_keep_crlf_inside_quoted_fields(self):
        raw='Id,MovePath\r\n1,"{\r\npath\r\n}"\r\n'.encode('utf-8-sig')
        self.assertEqual(list(loot.csv_reader(raw)),[dict(Id='1',MovePath='{\r\npath\r\n}')])

    def reward(self,id,kind,param,rate='200'):
        return dict(Id=id,Type=kind,Param=param,Rate=rate,RewardGroup='2',MinCount='1',MaxCount='3')

    def parent(self,id='p',npc='npc',group='g'):
        return dict(Id=id,GroupId=npc,RewardType='12',RewardParam=group,RewardRate='90',
                    AcquisitionGroupType='3',AcquisitionMethodType='9',provenance=dict(entry=1415,csv_record=2))

    def test_item_origins_keep_two_roll_paths_and_raw_rates(self):
        groups={'g':[self.reward('a','1','item'),self.reward('b','1','item','400')]}
        origins,issues=loot.item_origins([self.parent()],groups)
        self.assertEqual(len(origins['item']),2)
        self.assertEqual([r['raw_rate'] for r in origins['item']],['200','400'])
        self.assertTrue(all(r['chance_percent'] is None for r in origins['item']))
        self.assertEqual(origins['item'][0]['raw_reward_rate'],'90')
        self.assertEqual(issues,[])

    def test_nested_groups_preserve_chain_and_cycle_stops(self):
        groups={'g':[self.reward('a','12','nested')],
                'nested':[self.reward('b','1','item'),self.reward('c','12','g')]}
        origins,issues=loot.item_origins([self.parent()],groups)
        self.assertEqual(origins['item'][0]['reward_chain'],[dict(group_id='g',reward_id='a'),dict(group_id='nested',reward_id='b')])
        self.assertEqual(issues[0]['kind'],'cycle')

    def test_no_invented_source_for_missing_group_or_nonitem_reward(self):
        origins,issues=loot.item_origins([self.parent()],{})
        self.assertEqual(origins,{})
        self.assertEqual(issues[0]['kind'],'missing_group')
        origins,issues=loot.item_origins([self.parent()],{'g':[self.reward('a','0','Gold')]})
        self.assertEqual(origins,{})
        self.assertEqual(issues,[])

    def image(self,path,patch=0):return dict(asset_path=path,patch=patch,file=path+str(patch))

    def test_full_paths_remain_ambiguous_despite_matching_basename(self):
        rows=[self.image('/Item/IMG_Coin'),self.image('/Other/IMG_Coin')]
        result=loot.resolve_icon('IMG_Coin',rows)
        self.assertEqual(result['status'],'ambiguous_paths')
        self.assertEqual(len(result['images']),2)

    def test_newer_patch_selected_only_within_same_full_path(self):
        rows=[self.image('/Item/IMG_Coin',1),self.image('/Item/IMG_Coin',5),self.image('/Other/IMG_Coin',2)]
        result=loot.resolve_icon('IMG_Coin',rows)
        self.assertEqual(sorted(r['patch'] for r in result['images']),[2,5])

    def test_similar_case_or_partial_name_not_accepted(self):
        rows=[self.image('/Item/img_coin'),self.image('/Item/IMG_Coin_01')]
        self.assertEqual(loot.resolve_icon('IMG_Coin',rows)['status'],'missing')
        self.assertEqual(loot.resolve_icon('',rows)['status'],'not_declared')

    def fixture(self,value):
        values=np.empty((16,16,4),dtype='<f2');values[:]=value
        return bytes(16)+struct.pack('<iii',16,16,1)+bytes(4)+b'PF_FloatRGBA\0'.ljust(16,b'\0')+values.tobytes()+struct.pack('<iii',16,16,1)

    def test_float_decode_preserves_alpha_and_both_color_options(self):
        direct,srgb,meta=floats.decode(self.fixture([.5,.25,0,.25]))
        self.assertEqual(direct[0,0].tolist(),[128,64,0,64])
        self.assertEqual(srgb[0,0].tolist(),[188,137,0,64])
        self.assertEqual(meta['width'],16)

    def test_nan_and_hdr_not_silently_clipped(self):
        for value in [[float('nan'),0,0,1],[2,0,0,1],[-1,0,0,1]]:
            with self.assertRaises(ValueError):floats.decode(self.fixture(value))

    def test_truncated_mip_rejected(self):
        with self.assertRaises(ValueError):floats.decode(self.fixture([.5,.5,.5,1])[:-40])


if __name__=='__main__':unittest.main()
