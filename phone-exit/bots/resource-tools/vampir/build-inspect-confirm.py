"""Extract observed Confirm variants; no native widget binding is claimed."""
import cv2
import hashlib
import json
import os
from pathlib import Path
ROOT=Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES','F:/PhoneExit Resources/Vampir'))
MODULE=Path(__file__).resolve().parents[2]/'vampir'
reference=MODULE/'inspect-confirm-reference.json'
proof=json.loads(reference.read_text('utf-8'))
src=Path(proof['source'])
if hashlib.sha256(src.read_bytes()).hexdigest()!=proof['source_sha256']:raise ValueError('Source screenshot changed')
image=cv2.imread(str(src));config=json.loads((MODULE/'vision.json').read_text('utf-8'))
variants=[]
for suffix,factor in [('',1),('_compact',.75),('_large',1.25)]:
 scaled=cv2.resize(image,None,fx=factor,fy=factor,interpolation=cv2.INTER_LINEAR)
 left,top,right,bottom=[round(n*factor) for n in proof['crop']]
 name='connection_terminated_confirm'+suffix;target=MODULE/'templates'/f'{name}.png'
 cv2.imwrite(str(target),scaled[top:bottom,left:right])
 size=[scaled.shape[1],scaled.shape[0]]
 config['templates'][name]={'file':target.name,'threshold':.94,'region':[.25,.45,.75,.75],'scales':[.95,1,1.05],'reference_size':size}
 variants.append({'name':name,'factor':factor,'crop':[left,top,right,bottom],'reference_size':size,'sha256':hashlib.sha256(target.read_bytes()).hexdigest()})
config.setdefault('match_alternatives',{})['connection_terminated_confirm']=[v['name'] for v in variants[1:]]
proof['variants']=variants
reference.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n','utf-8')
(MODULE/'vision.json').write_text(json.dumps(config,ensure_ascii=False,indent=2)+'\n','utf-8')
print('Confirm variants extracted with provenance: 3')
