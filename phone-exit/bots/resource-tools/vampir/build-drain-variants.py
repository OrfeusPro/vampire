"""Reproduce the observed Drain text variants, keeping the original source action."""
import cv2,json,hashlib
from pathlib import Path
MODULE=Path(__file__).resolve().parents[2]/'vampir'
ref=json.loads((MODULE/'drain-variant-reference.json').read_text('utf-8'))
source=Path(ref['source'])
if hashlib.sha256(source.read_bytes()).hexdigest()!=ref['sha256']:raise ValueError('Frame changed')
image=cv2.imread(str(source))
for record in ref['variants']:
 scaled=cv2.resize(image,None,fx=record['factor'],fy=record['factor']);l,t,r,b=record['crop'];ok,data=cv2.imencode('.png',scaled[t:b,l:r])
 if not ok or hashlib.sha256(data.tobytes()).hexdigest()!=record['sha256']:raise ValueError('Template changed')
 (MODULE/'templates'/(record['name']+'.png')).write_bytes(data.tobytes())
print('3 Drain variants rebuilt and verified')
