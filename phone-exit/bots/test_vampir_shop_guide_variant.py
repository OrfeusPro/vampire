import importlib.util,json,unittest,tempfile,shutil
from pathlib import Path
from unittest.mock import patch
s=importlib.util.spec_from_file_location('guide_replay',Path(__file__).parent/'resource-tools/vampir/replay-shop.py')
r=importlib.util.module_from_spec(s);s.loader.exec_module(r)
class GuideVariant(unittest.TestCase):
 def run_frame(self, erased=False):
  ref=json.loads((r.MODULE/'shop-guide-variant-reference.json').read_text('utf-8'))
  if not Path(ref['source']).exists():self.skipTest('External frame unavailable')
  source=r.cv2.imread(ref['source'])
  if erased:source[145:177,885:1140]=0
  for tag,f,dx,dy in r.TRANSFORMS:
   with self.subTest(tag=tag):
    image=r.cv2.resize(source,None,fx=f,fy=f)
    if dx or dy:image=r.cv2.warpAffine(image,r.np.float32([[1,0,dx],[0,1,dy]]),(image.shape[1],image.shape[0]))
    bot=r.load('guide_'+tag+str(erased),r.MODULE/'bot.py');host=r.ReplayHost(r.MODULE);host.capture(image,tag)
    with patch.object(bot.time,'monotonic',return_value=1000):result=bot.tick(host,{'quest_enabled':True,'autostart_enabled':True},{},str(r.MODULE))
    if erased:self.assertEqual(host.taps,[],result)
    else:
     self.assertEqual(result['step'],'quest_shop_open');self.assertEqual(len(host.taps),1)
     self.assertAlmostEqual(host.taps[0]['args']['x'],997*f+dx,delta=5)
 def test_guide_opens_at_all_reviewed_scales(self):self.run_frame()
 def test_task_without_guide_title_never_opens_shop(self):self.run_frame(True)
 def test_reserved_purchase_is_completed_without_another_buy(self):
  ref=json.loads((r.MODULE/'shop-guide-completed-reference.json').read_text('utf-8'))
  if not Path(ref['source']).exists():self.skipTest('External frame unavailable')
  source=r.cv2.imread(ref['source'])
  for tag,f,dx,dy in r.TRANSFORMS:
   with self.subTest(tag=tag), tempfile.TemporaryDirectory() as temporary:
    directory=Path(temporary)/'payload';shutil.copytree(r.MODULE,directory,ignore=shutil.ignore_patterns('__pycache__'))
    journal=directory.parent/('vampir-purchases.'+'a'*32+'.json');journal.write_text('{"901030010":"reserved"}')
    image=r.cv2.resize(source,None,fx=f,fy=f)
    if dx or dy:image=r.cv2.warpAffine(image,r.np.float32([[1,0,dx],[0,1,dy]]),(image.shape[1],image.shape[0]))
    bot=r.load('complete_'+tag,directory/'bot.py');host=r.ReplayHost(directory);state={}
    for now in (1000,1003):
     host.capture(image,tag)
     with patch.object(bot.time,'monotonic',return_value=now):result=bot.tick(host,{'quest_enabled':True,'autostart_enabled':True,'purchase_context_id':'a'*32},state,str(directory))
    self.assertEqual(json.loads(journal.read_text()),{'901030010':'completed'},result)
    # Only the observed reward line can be clicked, never the Buy button.
    for tap in host.taps:
     self.assertLess(tap['args']['y'],220*f+dy)
 def test_missing_completion_anchor_keeps_reservation(self):
  ref=json.loads((r.MODULE/'shop-guide-completed-reference.json').read_text('utf-8'))
  if not Path(ref['source']).exists():self.skipTest('External frame unavailable')
  source=r.cv2.imread(ref['source'])
  for rectangle in ([885,145,1140,174],[885,178,1120,203],[1150,155,1185,195]):
   with self.subTest(rectangle=rectangle), tempfile.TemporaryDirectory() as temporary:
    directory=Path(temporary)/'payload';shutil.copytree(r.MODULE,directory,ignore=shutil.ignore_patterns('__pycache__'))
    journal=directory.parent/'vampir-purchases.json';journal.write_text('{"901030010":"reserved"}')
    image=source.copy();l,t,rr,b=rectangle;image[t:b,l:rr]=0
    bot=r.load('completion_negative',directory/'bot.py');host=r.ReplayHost(directory);host.capture(image,'negative')
    with patch.object(bot.time,'monotonic',return_value=1000):result=bot.tick(host,{'quest_enabled':True,'autostart_enabled':True},{},str(directory))
    self.assertEqual(json.loads(journal.read_text()),{'901030010':'reserved'},result)
    self.assertEqual(host.taps,[])
if __name__=='__main__':unittest.main()
