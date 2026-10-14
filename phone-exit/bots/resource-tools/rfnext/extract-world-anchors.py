"""Extract bounded SceneComponent transform candidates from an actual Novus package.

Only observed serialization layouts are accepted. These are engine component
coordinates, not named farm POIs; schema and world-to-atlas mapping remain unverified.
"""
import json,struct,math,hashlib,importlib.util
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('pak',HERE/'scan-pak.py');pak=importlib.util.module_from_spec(spec);spec.loader.exec_module(pak)
ROOT=pak.ROOT;OUT=ROOT/'data-study';OUT.mkdir(exist_ok=True)
def extract():
 folder='pakchunk506_s9-Windows_0_P';entry=151
 rows=json.loads((ROOT/'pak-extracted'/folder/'entries.json').read_text('utf-8'))
 inv=json.loads((ROOT/'pc-pak-inventory.json').read_text('utf-8'))
 archive=Path(inv['source'])/next(r['path'] for r in inv['packages'] if Path(r['path']).stem==folder)
 with archive.open('rb') as f:
  def record(i):return pak.decode(f,pak.header(f,rows[i]['offset'],rows[-1]['index_offset']))
  asset=record(entry);body=record(entry-1)
 n=struct.unpack_from('<i',asset,32)[0];summary=36+n
 count,at=struct.unpack_from('<ii',asset,summary+4);names=[]
 for i in range(count):
  length=struct.unpack_from('<i',asset,at)[0];at+=4
  if length>0:s=asset[at:at+length-1].decode('utf-8');at+=length
  else:s=asset[at:at-length*2-2].decode('utf-16le');at-=length*2
  at+=4;names.append(s)
 ec,eo,ic,io=struct.unpack_from('<iiii',asset,summary+28)
 assert eo+ec*96<=len(asset) and io+ic*32<=len(asset)
 exports=[]
 for i in range(ec):
  p=eo+i*96;cls,sup,tmp,outer,ni,num,flags=struct.unpack_from('<iiiiiiI',asset,p)
  size,offset=struct.unpack_from('<qq',asset,p+28);typ=''
  if cls<0:
   ci=struct.unpack_from('<i',asset,io+(-cls-1)*32+20)[0];typ=names[ci]
  exports.append(dict(export=i,name=names[ni],type=typ,outer=outer,size=size,offset=offset))
 assert len(body)==sum(e['size'] for e in exports)+4,'Wrong export-body pairing'
 base=len(asset);result=[];skipped=[]
 for e in exports:
  if e['type']!='SceneComponent':continue
  start=e['offset']-base;b=body[start:start+e['size']]
  if len(b)!=e['size'] or b[:6] not in (bytes.fromhex('000000000503'),bytes.fromhex('000000000505')) or len(b)<30:
   skipped.append(dict(export=e['export'],name=e['name'],size=e['size'],reason='unrecognized or default transform layout'));continue
  xyz=struct.unpack_from('<ddd',b,6)
  if not all(math.isfinite(v) and abs(v)<1e8 for v in xyz):raise ValueError('Invalid transform candidate')
  parent=exports[e['outer']-1] if e['outer']>0 else None
  result.append(dict(export=e['export'],component=e['name'],parent=None if not parent else {k:parent[k] for k in ('export','name','type')},xyz=list(xyz),serialized_offset=e['offset']+6,serialized_sha256=hashlib.sha256(b).hexdigest(),layout=b[:6].hex(),semantic='SceneComponent relative location candidate',schema_verified=False,world_to_atlas_verified=False))
 report=dict(game_version='1.30.7',source_pak=str(archive),pak_bytes=archive.stat().st_size,asset_entry=entry,asset_pak_offset=rows[entry]['offset'],asset_sha256=hashlib.sha256(asset).hexdigest(),body_entry=entry-1,body_pak_offset=rows[entry-1]['offset'],body_sha256=hashlib.sha256(body).hexdigest(),coordinate_space='Unreal SceneComponent local/relative transform; origin, scale and atlas mapping not verified',points=result,skipped=skipped,export_types={t:sum(e['type']==t for e in exports) for t in sorted({e['type'] for e in exports})})
 (OUT/'novus-world-anchors.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
 (OUT/'novus-world.uasset').write_bytes(asset);(OUT/'novus-world.uexp').write_bytes(body)
 print('Extracted',len(result),'transform candidates;',len(skipped),'layouts skipped')
 for r in result[:8]:print(r['parent'],[round(v,2) for v in r['xyz']])
if __name__=='__main__':extract()
