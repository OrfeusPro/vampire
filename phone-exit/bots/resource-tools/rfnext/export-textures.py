from pathlib import Path
import json,struct,collections,re,hashlib,io
from PIL import Image
import os
ROOT=Path(os.environ.get('PHONEEXIT_RF_RESOURCES', r'F:\PhoneExit Resources\RF Online Next'))

def export_all():
 out=ROOT/'archive-images';out.mkdir(exist_ok=True);result=[];errors=[];latest={}
 previous={}
 try:previous={r['file']:r for r in json.loads((ROOT/'archive-image-catalog.json').read_text('utf-8'))}
 except (FileNotFoundError,json.JSONDecodeError):pass
 for folder in sorted((ROOT/'pak-extracted').iterdir(), key=lambda p:(not p.name.startswith('pakchunk952'),p.name)):
  metadata=folder/'entries.json'
  if not metadata.exists():continue
  try:rows=json.loads(metadata.read_text('utf-8'))
  except json.JSONDecodeError:continue
  for row in rows:
   if not row.get('pixel_formats'):continue
   entry=row['entry'];owner=next((r for r in reversed(rows[max(0,entry-2):entry]) if r.get('uasset') and r.get('paths')),None)
   if not owner:continue
   paths=owner['paths'];path=collections.Counter(paths).most_common(1)[0][0]
   if not path.startswith('/Game/') or not any(s in path for s in ('/UI/','WorldMapTexture','Minimap','MiniMap')):continue
   try:
    b=Path(row['saved']).read_bytes();pos=b.find(b'PF_');fmt=re.match(rb'PF_[A-Za-z0-9_]+',b[pos:]).group().decode();w,h,slices=struct.unpack_from('<iii',b,pos-16)
    if not 1<=w<=8192 or not 1<=h<=8192 or slices!=1:continue
    if fmt=='PF_B8G8R8A8':n=w*h*4
    elif fmt=='PF_DXT1':n=((w+3)//4)*((h+3)//4)*8
    elif fmt in ('PF_DXT5','PF_BC7'):n=((w+3)//4)*((h+3)//4)*16
    else:continue
    marker=b.find(struct.pack('<iii',w,h,1),pos+16+n);start=marker-n
    if marker<0 or start<pos+16:continue
    raw=b[start:marker]
    if fmt=='PF_B8G8R8A8':image=Image.frombytes('RGBA',(w,h),raw,'raw','BGRA')
    else:
     fourcc=b'DXT1' if fmt=='PF_DXT1' else b'DXT5' if fmt=='PF_DXT5' else b'DX10'
     hdr=struct.pack('<7I',124,0x81007,h,w,n,0,1)+bytes(44)+struct.pack('<II4s5I',32,4,fourcc,0,0,0,0,0)+struct.pack('<5I',0x1000,0,0,0,0)
     if fmt=='PF_BC7':hdr+=struct.pack('<5I',98,3,0,1,0)
     image=Image.open(io.BytesIO(b'DDS '+hdr+raw));image.load()
    name=re.sub('[^a-zA-Z0-9_-]','_',path.rsplit('/',1)[-1]);key=hashlib.sha256((path+folder.name).encode()).hexdigest()[:8];dest=out/(name+'-'+key+'.png');relative=str(dest.relative_to(ROOT)).replace('\\','/');pixel_hash=hashlib.sha256(raw).hexdigest()
    if not dest.exists() or previous.get(relative,{}).get('encoded_pixel_sha256')!=pixel_hash:image.save(dest)
    patch=re.search(r'_(\d+)_P$',folder.name);patch=int(patch[1]) if patch else -1
    record={'asset_path':path,'file':str(dest.relative_to(ROOT)).replace('\\','/'),'width':w,'height':h,'format':fmt,'source':folder.name+'.pak','entry':entry,'offset':row['offset'],'uasset_entry':owner['entry'],'origin':'decoded-unreal-texture','sha256':hashlib.sha256(dest.read_bytes()).hexdigest(),'encoded_pixel_sha256':hashlib.sha256(raw).hexdigest(),'patch':patch}
    result.append(record)
    if path not in latest or patch>latest[path]['patch']:latest[path]=record
   except Exception as error:errors.append({'source':folder.name,'entry':entry,'error':type(error).__name__})
 (ROOT/'archive-image-catalog.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8');(ROOT/'archive-image-latest.json').write_text(json.dumps(list(latest.values()),ensure_ascii=False,indent=2),encoding='utf-8');(ROOT/'texture-export-errors.json').write_text(json.dumps(errors,indent=2),encoding='utf-8')
 print('Exported PNGs',len(result),'unique current assets',len(latest),'map tiles',sum('WorldMapTileTex' in r['asset_path'] for r in latest.values()),'errors',len(errors),flush=True)
if __name__=='__main__':export_all()
