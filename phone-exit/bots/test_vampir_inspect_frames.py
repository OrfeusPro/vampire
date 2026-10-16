"""Real bot replay of the observed termination popup at different sizes/offsets."""
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT=Path(__file__).parent
spec=importlib.util.spec_from_file_location('inspect_replay', ROOT/'resource-tools/vampir/replay-shop.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

class InspectFrames(unittest.TestCase):
    def test_confirm_scales_and_moving_window_once_then_checks_result(self):
        reference=json.loads((r.MODULE/'inspect-confirm-reference.json').read_text('utf-8'))
        if not Path(reference['source']).exists():self.skipTest('External source screenshot unavailable')
        src=r.cv2.imread(reference['source'])
        cases=list(r.TRANSFORMS)+[('wide',1,0,0)]
        for tag,f,dx,dy in cases:
            with self.subTest(tag=tag):
                image=r.cv2.resize(src,None,fx=f,fy=f)
                if tag=='wide':
                    image=r.cv2.copyMakeBorder(image,40,40,80,80,r.cv2.BORDER_CONSTANT)
                elif dx or dy:
                    image=r.cv2.warpAffine(image,r.np.float32([[1,0,dx],[0,1,dy]]),(image.shape[1],image.shape[0]))
                bot=r.load('inspect_'+tag,r.MODULE/'bot.py');host=r.ReplayHost(r.MODULE);state={}
                host.capture(image,tag)
                with patch.object(bot.time,'monotonic',return_value=1000):
                    result=bot.tick(host,{'autostart_enabled':True},state,str(r.MODULE))
                if tag=='wide':
                    self.assertEqual(len(host.taps),0)
                    self.assertNotEqual(result['step'],'inspect_confirm_wait')
                    continue
                self.assertEqual(result['step'],'inspect_confirm_wait')
                self.assertEqual(len(host.taps),1)
                self.assertAlmostEqual(host.taps[0]['args']['x'],640*f+(80 if tag=='wide' else dx),delta=5)
                self.assertAlmostEqual(host.taps[0]['args']['y'],448*f+(40 if tag=='wide' else dy),delta=5)
                with patch.object(bot.time,'monotonic',return_value=1012):
                    result=bot.tick(host,{'autostart_enabled':True},state,str(r.MODULE))
                self.assertTrue(result['pause']);self.assertEqual(len(host.taps),1)
                self.assertEqual(result['error'],'inspect_confirm_outcome_unknown')

if __name__=='__main__':unittest.main()
