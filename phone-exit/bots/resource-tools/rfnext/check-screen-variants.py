"""Offline projection regression with synthetic screen shifts/aspect ratios.
These cases supplement, and never replace, tests on real devices.
"""
import importlib.util,json,tempfile
from pathlib import Path
import cv2,numpy as np

spec=importlib.util.spec_from_file_location('registration',Path(__file__).with_name('register-map.py'))
registration=importlib.util.module_from_spec(spec);spec.loader.exec_module(registration)
root=Path(__file__).resolve().parents[3];source=root/'.tools/rf-map-ground-hold.png'
image=cv2.imread(str(source));reference=registration.register(source);matrix=np.array(reference['matrix'])
target=matrix[:,:2]@np.array([830.,650.])+matrix[:,2]
cases=[('shift',1.,45,25,2400,1080),('smaller_ui',.85,110,80,2400,1080),('16_9_letterbox',.8,0,90,1920,1080)]
with tempfile.TemporaryDirectory(prefix='rf-screen-') as tmp:
 for name,scale,dx,dy,w,h in cases:
  transform=np.array([[scale,0,dx],[0,scale,dy]],dtype=float)
  changed=cv2.warpAffine(image,transform,(w,h));file=Path(tmp)/(name+'.png');cv2.imwrite(str(file),changed)
  fit=registration.register(file);m=np.array(fit['matrix']);actual=np.linalg.solve(m[:,:2],target-m[:,2]);expected=np.array([830.,650.])*scale+[dx,dy]
  error=float(np.linalg.norm(actual-expected));assert error<5,(name,error)
  print(name,'projection error',round(error,3),'screen px;',fit['inliers'],'inliers')
