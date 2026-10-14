"""Inspect non-image PAK records; preserve selected map/table data with provenance."""
import json,re,hashlib,importlib.util,sys,collections
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('pak',HERE/'scan-pak.py');pak=importlib.util.module_from_spec(spec);spec.loader.exec_module(pak)
ROOT=pak.ROOT;OUT=ROOT/'data-study';OUT.mkdir(exist_ok=True)
def inspect(prefix='pakchunk0-'):
 inv=json.loads((ROOT/'pc-pak-inventory.json').read_text('utf-8'))
 archives={Path(r['path']).stem:Path(inv['source'])/r['path'] for r in inv['packages']}
 report=[];signatures=collections.Counter()
 for folder in sorted((ROOT/'pak-extracted').iterdir()):
  if not folder.name.startswith(prefix) or folder.name not in archives:continue
  rows=json.loads((folder/'entries.json').read_text('utf-8'));source=archives[folder.name]
  with source.open('rb') as f:
   limit=rows[-1]['index_offset']
   for row in rows[:-1]:
    if row.get('pixel_formats') or row.get('encrypted') or row['uncompressed']>16*1024*1024:continue
    h=pak.header(f,row['offset'],limit)
    if not h:continue
    b=pak.decode(f,h)
    if not b:continue
    signatures[b[:8].hex()]+=1
    strings=[s.decode('ascii') for s in re.findall(rb'[ -~]{5,}',b)]
    keys=[s for s in strings if re.search(r'(?i)(RF_MapInfo|WorldMap|MapTable|Teleport|Portal|MapPosition|Location|MapID|RegionID|SpawnPoint|DataTable|\.csv|\.json|\.bytes)',s)]
    special=b.startswith((b'SQLite format 3',b'{',b'[',b'\x1f\x8b',b'PK\x03\x04'))
    if not keys and not special:continue
    item=dict(pak=str(source),pak_bytes=source.stat().st_size,entry=row['entry'],offset=row['offset'],size=len(b),sha256=hashlib.sha256(b).hexdigest(),magic=b[:16].hex(),matches=keys[:200],paths=row.get('paths',[]))
    report.append(item)
    # Save table/map records, excluding generic animation/sound portal resources.
    if special or any(re.search(r'(?i)(RF_MapInfo|MapTable|DataTable|WorldMapCharacterIconTable)',s) for s in keys):
     target=OUT/folder.name;target.mkdir(exist_ok=True);file=target/(str(row['entry']).zfill(6)+'.bin');file.write_bytes(b);item['saved']=str(file)
  print(folder.name,'candidates',len(report),flush=True)
 (OUT/(prefix.rstrip('-')+'-report.json')).write_text(json.dumps(dict(records=report,signatures=signatures),ensure_ascii=False,indent=2),encoding='utf-8')
 print('Saved',len(report),'candidate records',flush=True)
if __name__=='__main__':inspect(sys.argv[1] if len(sys.argv)>1 else 'pakchunk0-')
