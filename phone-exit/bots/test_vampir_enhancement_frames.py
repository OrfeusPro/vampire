import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
s=importlib.util.spec_from_file_location('enhance_replay',Path(__file__).parent/'resource-tools/vampir/replay-shop.py')
r=importlib.util.module_from_spec(s);s.loader.exec_module(r)
class EnhancementFrames(unittest.TestCase):
 def test_four_source_steps_scaled_and_shifted(self):
  folder=r.ROOT/'phone-tests/tutorial4007-2026-10-16'
  if not (folder/'attempt.jpg').exists():self.skipTest('External frames unavailable')
  for label in ('equipment','info','material','attempt'):
   src=r.cv2.imread(str(folder/(label+'.jpg')))
   for tag,f,dx,dy in r.TRANSFORMS:
    with self.subTest(label=label,transform=tag):
     image=r.cv2.resize(src,None,fx=f,fy=f)
     if dx or dy:image=r.cv2.warpAffine(image,r.np.float32([[1,0,dx],[0,1,dy]]),(image.shape[1],image.shape[0]))
     bot=r.load('frame_'+label+tag,r.MODULE/'bot.py');host=r.ReplayHost(r.MODULE);host.capture(image,label);state={}
     settings={'quest_enabled':True,'autostart_enabled':True,'quest_shop_enabled':False}
     with patch.object(bot.time,'monotonic',return_value=1000):result=bot.tick(host,settings,state,str(r.MODULE))
     self.assertEqual(len(host.taps),1,result)
     self.assertIn('tutorial:4007',result['activePoint'])
     if label=='attempt':
      with patch.object(bot.time,'monotonic',return_value=1010):result=bot.tick(host,settings,state,str(r.MODULE))
      self.assertTrue(result['pause']);self.assertEqual(len(host.taps),1)
if __name__=='__main__':unittest.main()
