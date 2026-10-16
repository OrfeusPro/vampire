import importlib.util,json
from pathlib import Path
import unittest
from unittest.mock import patch
s=importlib.util.spec_from_file_location('bag_replay',Path(__file__).parent/'resource-tools/vampir/replay-shop.py')
r=importlib.util.module_from_spec(s);s.loader.exec_module(r)
class BagExit(unittest.TestCase):
 def test_single_exit_scaled_and_shifted(self):
  ref=json.loads((r.MODULE/'bag-exit-reference.json').read_text('utf-8'))
  if not Path(ref['source']).exists():self.skipTest('External frame unavailable')
  src=r.cv2.imread(ref['source'])
  for tag,f,dx,dy in r.TRANSFORMS:
   with self.subTest(tag=tag):
    image=r.cv2.resize(src,None,fx=f,fy=f)
    if dx or dy:image=r.cv2.warpAffine(image,r.np.float32([[1,0,dx],[0,1,dy]]),(image.shape[1],image.shape[0]))
    bot=r.load('bag_'+tag,r.MODULE/'bot.py');host=r.ReplayHost(r.MODULE);state={};settings={'quest_enabled':True,'autostart_enabled':True,'quest_shop_enabled':False}
    for now in (1000,1003,1006,1014):
     host.capture(image,tag)
     with patch.object(bot.time,'monotonic',return_value=now):result=bot.tick(host,settings,state,str(r.MODULE))
    self.assertEqual(len(host.taps),1,result);self.assertTrue(result['pause']);self.assertEqual(result['error'],'screen_exit_not_confirmed')
    self.assertAlmostEqual(host.taps[0]['args']['x'],1239*f+dx,delta=5)
 def test_tutorial_inventory_cannot_close(self):
  source=r.ROOT/'phone-tests/tutorial4007-2026-10-16/equipment.jpg'
  if not source.exists():self.skipTest('External frame unavailable')
  bot=r.load('bag_tutorial',r.MODULE/'bot.py');host=r.ReplayHost(r.MODULE);host.capture(r.cv2.imread(str(source)),'tutorial')
  with patch.object(bot.time,'monotonic',return_value=1000):result=bot.tick(host,{'quest_enabled':True,'autostart_enabled':True,'quest_shop_enabled':False},{},str(r.MODULE))
  self.assertEqual(result['step'],'quest_tutorial_enhance_select');self.assertNotEqual(result['step'],'screen_exit_bag')
if __name__=='__main__':unittest.main()
