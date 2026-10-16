import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
s=importlib.util.spec_from_file_location('adrenaline_replay',Path(__file__).parent/'resource-tools/vampir/replay-shop.py')
r=importlib.util.module_from_spec(s);s.loader.exec_module(r)
class Adrenaline(unittest.TestCase):
 def test_mask_ignores_skill_art_and_accepts_scaled_shifted_border(self):
  proof=json.loads((r.MODULE/'adrenaline-frame-reference.json').read_text('utf-8'))
  if not Path(proof['source']).exists():self.skipTest('External frame unavailable')
  src=r.cv2.imread(proof['source'])
  for tag,f,dx,dy in r.TRANSFORMS:
   with self.subTest(tag=tag):
    image=r.cv2.resize(src,None,fx=f,fy=f)
    if dx or dy:image=r.cv2.warpAffine(image,r.np.float32([[1,0,dx],[0,1,dy]]),(image.shape[1],image.shape[0]))
    # Remove the central skill picture; retain only the visible border.
    x1,y1,x2,y2=[round(n*f) for n in (310,617,398,689)];image[y1+dy:y2+dy,x1+dx:x2+dx]=0
    bot=r.load('adrenaline_'+tag,r.MODULE/'bot.py');host=r.ReplayHost(r.MODULE);host.capture(image,tag)
    with patch.object(bot.time,'monotonic',return_value=1000):result=bot.tick(host,{'quest_enabled':True,'autostart_enabled':True,'quest_shop_enabled':False},{},str(r.MODULE))
    self.assertEqual(result['step'],'quest_tutorial_adrenaline');self.assertEqual(len(host.taps),1,result)
    x,y=host.taps[0]['args']['x'],host.taps[0]['args']['y']
    self.assertTrue(293*f+dx<x<414*f+dx and 597*f+dy<719*f+dy)
 def test_prompt_without_border_does_not_tap(self):
  proof=json.loads((r.MODULE/'adrenaline-frame-reference.json').read_text('utf-8'))
  if not Path(proof['source']).exists():self.skipTest('External frame unavailable')
  image=r.cv2.imread(proof['source']);image[590:720,280:430]=0
  bot=r.load('adrenaline_missing',r.MODULE/'bot.py');host=r.ReplayHost(r.MODULE);host.capture(image,'missing');state={}
  with patch.object(bot.time,'monotonic',return_value=1000):result=bot.tick(host,{'quest_enabled':True,'autostart_enabled':True,'quest_shop_enabled':False},state,str(r.MODULE))
  self.assertEqual(result['step'],'quest_tutorial_adrenaline');self.assertFalse(host.taps)
  with patch.object(bot.time,'monotonic',return_value=1021):result=bot.tick(host,{'quest_enabled':True,'autostart_enabled':True,'quest_shop_enabled':False},state,str(r.MODULE))
  self.assertEqual(result['error'],'quest_tutorial_target_not_found');self.assertFalse(host.taps)
if __name__=='__main__':unittest.main()
