import json,importlib.util,hashlib,time
from pathlib import Path
import os
root=Path(os.environ.get('PHONEEXIT_RF_RESOURCES', r'F:\PhoneExit Resources\RF Online Next'));spec=importlib.util.spec_from_file_location('pakscan',Path(__file__).resolve().parent/'scan-pak.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
inventory=json.loads((root/'pc-pak-inventory.json').read_text('utf-8'));base=Path(inventory['source']);seen=set();progress=[]
items=[r for r in inventory['packages'] if r.get('version')==11]
items.sort(key=lambda r:(not ('pakchunk0-' in r['path']),r['bytes']))
for i,item in enumerate(items):
 path=base/item['path']
 with path.open('rb') as f:
  first=f.read(4096);f.seek(-512,2);tail=f.read()
 fingerprint=hashlib.sha256(str(item['bytes']).encode()+first+tail).hexdigest()
 if fingerprint in seen:continue
 seen.add(fingerprint);folder=root/'pak-extracted'/path.stem;metadata=folder/'entries.json'
 if metadata.exists():
  rows=json.loads(metadata.read_text('utf-8'))
 else:
  rows=mod.scan(path,folder)
 texture_paths=[]
 for row in rows:
  if row.get('texture'):
   for p in row.get('paths',[]):
    if p.startswith('/Game/') and any(x in p.lower() for x in ('worldmap','world_map','minimap','mini_map','maptexture','map_texture','/map/','/maps/')):texture_paths.append(p)
 progress.append({'file':str(path),'fingerprint':fingerprint,'entries':len(rows)-1,'map_candidates':sorted(set(texture_paths))})
 (root/'pak-scan-progress.json').write_text(json.dumps(progress,ensure_ascii=False,indent=2),encoding='utf-8')
 if texture_paths:print('MAP CANDIDATES',path.name,sorted(set(texture_paths))[:8],flush=True)
 if i%20==0:print('Progress',i+1,'/',len(items),'unique scanned',len(progress),flush=True)
print('Archive scan finished',len(progress),'unique packages',flush=True)
