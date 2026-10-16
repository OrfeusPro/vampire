"""Observed tutorial border; the skill graphic is transparent and never matched."""
from pathlib import Path
import cv2,json,hashlib,numpy as np
MODULE=Path(__file__).resolve().parents[2]/'vampir'
reference=MODULE/'adrenaline-frame-reference.json';proof=json.loads(reference.read_text('utf-8'))
source=Path(proof['source'])
if hashlib.sha256(source.read_bytes()).hexdigest()!=proof['sha256']:raise ValueError('Frame changed')
image=cv2.imread(str(source));records=[]
for suffix,f in [('',1),('_compact',.75),('_large',1.25)]:
 scaled=cv2.resize(image,None,fx=f,fy=f);crop=[round(n*f) for n in [293,597,414,706]];l,t,r,b=crop
 tpl=cv2.cvtColor(scaled[t:b,l:r],cv2.COLOR_BGR2BGRA);mask=np.zeros(tpl.shape[:2],np.uint8);w=max(2,round(3*f));h,tw=mask.shape
 cv2.line(mask,(w,w),(tw-w-1,w),255,w);cv2.line(mask,(w,w),(w,h-1),255,w);cv2.line(mask,(tw-w-1,w),(tw-w-1,h-1),255,w)
 tpl[:,:,3]=mask;name='tutorial_adrenaline_frame'+suffix;file=MODULE/'templates'/(name+'.png');cv2.imwrite(str(file),tpl)
 records.append({'name':name,'factor':f,'crop':crop,'sha256':hashlib.sha256(file.read_bytes()).hexdigest(),'mask':'top/left/right3px,inset3px; bottom excluded for near-edge shifts; center alpha0'})
proof['variants']=records;reference.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n','utf-8');print('3 masked Adrenaline frames rebuilt')
