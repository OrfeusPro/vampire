"""Rebuild only the observed idle-message templates from their hashed frame."""
import cv2
import hashlib
import json
from pathlib import Path
MODULE=Path(__file__).resolve().parents[2]/'vampir'
proof=json.loads((MODULE/'idle-confirm-reference.json').read_text('utf-8'))
source=Path(proof['source'])
if hashlib.sha256(source.read_bytes()).hexdigest()!=proof['source_sha256']:
    raise ValueError('Idle source frame changed')
image=cv2.imread(str(source))
for variant in proof['variants']:
    scaled=cv2.resize(image,None,fx=variant['factor'],fy=variant['factor'])
    left,top,right,bottom=variant['crop']
    ok,encoded=cv2.imencode('.png',scaled[top:bottom,left:right])
    if not ok or hashlib.sha256(encoded.tobytes()).hexdigest()!=variant['sha256']:
        raise ValueError('Idle template changed')
    (MODULE/'templates'/ (variant['name']+'.png')).write_bytes(encoded.tobytes())
print('Verified and rebuilt 3 idle templates')
