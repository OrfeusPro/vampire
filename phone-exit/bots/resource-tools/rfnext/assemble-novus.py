from pathlib import Path
from PIL import Image,ImageChops,ImageStat
import re,json,hashlib
import os
root=Path(os.environ.get('PHONEEXIT_RF_RESOURCES', r'F:\PhoneExit Resources\RF Online Next'));out=root/'maps';out.mkdir(exist_ok=True);images={}
for item in json.loads((root/'archive-image-latest.json').read_text('utf-8')):
 if not item['asset_path'].rsplit('/',1)[-1].startswith('NovusWorld_101_') or item['width']!=4096 or item['height']!=4096:continue
 p=root/item['file']
 m=re.match(r'NovusWorld_101_(-?\d+)_(-?\d+)-',p.name)
 if m:images[tuple(map(int,m.groups()))]=p
xs=sorted({p[0] for p in images});ys=sorted({p[1] for p in images});assert len(images)==len(xs)*len(ys),'Incomplete tile grid'
size=Image.open(next(iter(images.values()))).size;assert size[0]==size[1]
def seam(a,b,axis):
 import numpy as np
 with Image.open(a) as ia,Image.open(b) as ib:
  if axis=='x':a=ia.crop((size[0]-1,0,size[0],size[1]));b=ib.crop((0,0,1,size[1]))
  else:a=ia.crop((0,size[1]-1,size[0],size[1]));b=ib.crop((0,0,size[0],1))
  aa=np.asarray(a.convert('RGBA'));bb=np.asarray(b.convert('RGBA'));mask=(aa[:,:,3]>0)&(bb[:,:,3]>0)
  if mask.mean()<.1:return float('inf')
  return float(np.abs(aa[:,:,:3].astype(float)-bb[:,:,:3].astype(float))[mask].mean())
orientations=[]
for xx in (xs,list(reversed(xs))):
 for yy in (ys,list(reversed(ys))):
  scores=[seam(images[(xx[i],y)],images[(xx[i+1],y)],'x') for y in yy for i in range(len(xx)-1)]+[seam(images[(x,yy[i])],images[(x,yy[i+1])],'y') for x in xx for i in range(len(yy)-1)]
  orientations.append((sum(scores)/len(scores),xx,yy))
score,x_order,y_order=min(orientations);print('Tile layout',x_order,y_order,'edge mismatch',round(score,3),flush=True)
canvas=Image.new('RGBA',(len(xs)*size[0],len(ys)*size[1]),(0,0,0,0))
for yi,y in enumerate(y_order):
 for xi,x in enumerate(x_order):
  with Image.open(images[(x,y)]) as tile:canvas.paste(tile,(xi*size[0],yi*size[1]))
crop=canvas.getbbox();canvas=canvas.crop(crop);output_size=canvas.size;full=out/'novus-world.png';canvas.save(full,compress_level=3);canvas.thumbnail((1800,1800));canvas.save(out/'novus-world-preview.png')
meta={'id':'NovusWorld_101','width':output_size[0],'height':output_size[1],'tile_canvas':[len(xs)*size[0],len(ys)*size[1]],'crop':crop,'tile_size':size,'x_order':x_order,'y_order':y_order,'edge_mismatch_mean':score,'orientation_method':'lowest adjacent-edge RGB difference across four axis orderings','tiles':[{'x':x,'y':y,'file':str(p.resolve()),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for (x,y),p in images.items()],'file':str(full),'sha256':hashlib.sha256(full.read_bytes()).hexdigest(),'navigation_calibrated':False};(out/'novus-world.json').write_text(json.dumps(meta,ensure_ascii=False,indent=2),encoding='utf-8')
print('Novus map saved',meta['width'],meta['height'],flush=True)
