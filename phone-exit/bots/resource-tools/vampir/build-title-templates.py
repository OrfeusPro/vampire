"""Recreate reviewed title templates without inferring coordinates from WBP."""
import argparse
import cv2
import hashlib
import json
from pathlib import Path
MODULE=Path(__file__).resolve().parents[2]/'vampir'
parser=argparse.ArgumentParser()
parser.add_argument('reference',nargs='?',default='title-entry-reference.json',choices=['title-entry-reference.json','character-entry-reference.json'])
args=parser.parse_args()
proof=json.loads((MODULE/args.reference).read_text('utf-8'))
source=Path(proof['source'])
if hashlib.sha256(source.read_bytes()).hexdigest()!=proof['source_sha256']:
    raise ValueError('Title source changed')
image=cv2.imread(str(source))
for record in proof['templates']:
    scaled=cv2.resize(image,None,fx=record['factor'],fy=record['factor'])
    l,t,r,b=record['crop'];ok,encoded=cv2.imencode('.png',scaled[t:b,l:r])
    if not ok or hashlib.sha256(encoded.tobytes()).hexdigest()!=record['sha256']:
        raise ValueError('Title template changed')
    (MODULE/'templates'/(record['name']+'.png')).write_bytes(encoded.tobytes())
print(str(len(proof['templates']))+' title templates verified and rebuilt')
