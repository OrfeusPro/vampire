import importlib.util,json
from pathlib import Path
import unittest
from unittest.mock import patch
s=importlib.util.spec_from_file_location('buff_replay',Path(__file__).parent/'resource-tools/vampir/replay-shop.py')
r=importlib.util.module_from_spec(s);s.loader.exec_module(r)
class Buff(unittest.TestCase):
 def test_exact_prompt_target_and_highlight_scaled_shifted(self):
  proof=json.loads((r.MODULE/'adrenaline-buff-reference.json').read_text('utf-8'))
  if not Path(proof['source']).exists():self.skipTest('External frame unavailable')
  src=r.cv2.imread(proof['source'])
  for tag,f,dx,dy in r.TRANSFORMS:
   with self.subTest(tag=tag):
    image=r.cv2.resize(src,None,fx=f,fy=f)
    if dx or dy:image=r.cv2.warpAffine(image,r.np.float32([[1,0,dx],[0,1,dy]]),(image.shape[1],image.shape[0]))
    bot=r.load('buff_'+tag,r.MODULE/'bot.py');host=r.ReplayHost(r.MODULE);host.capture(image,tag)
    with patch.object(bot.time,'monotonic',return_value=1000):result=bot.tick(host,{'quest_enabled':True,'autostart_enabled':True,'quest_shop_enabled':False},{},str(r.MODULE))
    self.assertEqual(result['step'],'quest_tutorial_adrenaline_buff');self.assertEqual(len(host.taps),1,result)
    self.assertIn('tutorial:4002/step:18',result['activePoint'])
 def test_missing_highlight_blocks_input(self):
  proof=json.loads((r.MODULE/'adrenaline-buff-reference.json').read_text('utf-8'))
  if not Path(proof['source']).exists():self.skipTest('External frame unavailable')
  image=r.cv2.imread(proof['source']);image[550:580,290:320]=0
  bot=r.load('buff_no_corner',r.MODULE/'bot.py');host=r.ReplayHost(r.MODULE);host.capture(image,'missing')
  with patch.object(bot.time,'monotonic',return_value=1000):result=bot.tick(host,{'quest_enabled':True,'autostart_enabled':True,'quest_shop_enabled':False},{},str(r.MODULE))
  self.assertEqual(result['error'],'quest_tutorial_conditions_not_verified');self.assertFalse(host.taps)
if __name__=='__main__':unittest.main()
