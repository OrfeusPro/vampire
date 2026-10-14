"""Preserve native RFT tables, select latest per name, retain archive provenance."""
import json,re,hashlib,importlib.util
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('pak',HERE/'scan-pak.py');pak=importlib.util.module_from_spec(spec);spec.loader.exec_module(pak)
ROOT=pak.ROOT;OUT=ROOT/'data-study/rft';OUT.mkdir(parents=True,exist_ok=True)
def extract():
 inv=json.loads((ROOT/'pc-pak-inventory.json').read_text('utf-8'));archives={Path(r['path']).stem:Path(inv['source'])/r['path'] for r in inv['packages']};catalog=[];latest={}
 for folder in sorted((ROOT/'pak-extracted').glob('pakchunk941*')):
  rows=json.loads((folder/'entries.json').read_text('utf-8'));source=archives[folder.name]
  patch=re.search(r'_(\d+)_P$',folder.name);rank=int(patch[1])+1 if patch else 0
  with source.open('rb') as f:
   for r in rows[:-1]:
    if r.get('encrypted'):continue
    b=pak.decode(f,pak.header(f,r['offset'],rows[-1]['index_offset']))
    if not b or not b.startswith(b'RFT'):continue
    match=re.search(rb'RF_[A-Za-z0-9_]+',b[:200])
    if not match:continue
    name=match.group().decode('ascii');file=OUT/folder.name/(str(r['entry']).zfill(6)+'-'+name+'.rft');file.parent.mkdir(exist_ok=True);file.write_bytes(b)
    strings=[s.decode('ascii')[:200] for s in re.findall(rb'[A-Za-z_][A-Za-z0-9_/.: -]{3,}',b[:20000])]
    row=dict(name=name,pak=str(source),pak_bytes=source.stat().st_size,entry=r['entry'],pak_offset=r['offset'],bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),file=str(file),patch_rank=rank,header_strings=strings[:100]);catalog.append(row)
    if name not in latest or latest[name]['patch_rank']<rank:latest[name]=row
  print(folder.name,'tables',len(catalog),flush=True)
 (OUT/'catalog.json').write_text(json.dumps(catalog,ensure_ascii=False,indent=2),encoding='utf-8')
 (OUT/'latest.json').write_text(json.dumps(list(latest.values()),ensure_ascii=False,indent=2),encoding='utf-8')
 chosen=[r for r in latest.values() if re.search(r'(?i)(MapInfo|MapRegion|MapArea|WorldMap|Teleport|Portal|Spawn|Region|Minimap)',r['name'])]
 (OUT/'map-tables.json').write_text(json.dumps(chosen,ensure_ascii=False,indent=2),encoding='utf-8')
 print('Latest',len(latest),'map related',len(chosen),flush=True)
 for r in chosen:print(r['name'],r['bytes'],r['header_strings'][:10],flush=True)
if __name__=='__main__':extract()
