"""Join map spawn positions, NPC identities and RU names; preserve source offsets."""
import json, os, re, math
from pathlib import Path

ROOT=Path(os.environ.get('PHONEEXIT_RF_RESOURCES',r'F:\PhoneExit Resources\RF Online Next'))
DATA=ROOT/'data-study/rft/decoded'
OUT=Path(__file__).resolve().parents[3]/'pc/assets/maps/rfonlinenext'

def build():
 load=lambda name:json.loads((DATA/(name+'.json')).read_text('utf-8'))
 spawn=load('RF_MapInfoTable_Spawn');npc=load('RF_NPCTable');strings=load('RF_StringTable_RU')
 ns={r['values']['NPCIndex']:r for r in npc['records']}
 tr={r['values']['StringID']:re.sub(r'\\u([0-9a-fA-F]{4})',lambda m:chr(int(m[1],16)),r['values']['KO_KR']) for r in strings['records']}
 native=json.loads((OUT/'native-points.json').read_text('utf-8'))
 matrices={r['map_index']:r['matrix_world_to_atlas_pixels'] for r in native['calibration']}
 editor=json.loads((OUT/'index-native.json').read_text('utf-8'));w,h=editor['original_size']
 regions={r['region_index']:r for r in editor['locations']};targets=[]
 for row in spawn['records']:
  v=row['values'];n=ns.get(v['NPCIndex'])
  if not n or v['MapIndex'] not in matrices or v['RegionIndex'] not in regions:continue
  nv=n['values']
  if nv['NPCType']!=2:continue
  positions=[]
  for field in ('TargetPosition1','TargetPosition2','TargetPosition3'):
   xyz=v[field]
   if not any(xyz):continue
   if not all(math.isfinite(c) and abs(c)<1e8 for c in xyz):raise ValueError('Invalid spawn coordinate')
   m=matrices[v['MapIndex']];x=sum(m[0][i]*c for i,c in enumerate([*xyz[:2],1]))/w;y=sum(m[1][i]*c for i,c in enumerate([*xyz[:2],1]))/h
   positions.append(dict(field=field,world_xyz=xyz,x=x,y=y,inside_atlas=0<=x<1 and 0<=y<1))
  targets.append(dict(id='spawn_'+str(v['Key']),npc_index=v['NPCIndex'],label=tr.get(nv['NameStringIndex'],nv['NameStringIndex']),name_string_id=nv['NameStringIndex'],level=nv['Level'],map_index=v['MapIndex'],region_index=v['RegionIndex'],location_id=regions[v['RegionIndex']]['id'],location_label=regions[v['RegionIndex']]['label'],positions=positions,spawn_value=v['SpawnValue'],npc_subtype=nv['NPCSubType'],spawn_row_offset=row['offset'],npc_row_offset=n['offset'],navigation_verified=False,ui_list_membership_verified=False))
 if len({r['id'] for r in targets})!=len(targets):raise ValueError('Duplicate spawn keys')
 # Entire list cross-checked by scrolling the actual RU game panel on USB-vivo.
 observed=['Ониксовый ящер','Древний ониксовый ящер','Ониксовый глат','Ониксовый рекс-каннибал','Ониксовый эш','Огненный ониксовый эш','Адская ониксовая личинка','Ониксовый фанатик','Ониксовый Архивариус','Ониксовый Firestarter','Ониксовый Очиститель','Дикий Сплинтер','Дикий каннибал','Бушующий призрак']
 black=[r for r in targets if r['region_index']==68001]
 if [r['label'] for r in black]!=observed or any(r['level']!=55 for r in black):raise ValueError('Game panel cross-check failed')
 for r in black:r['ui_list_membership_verified']=True
 result=dict(version=1,game_version='1.30.7',study_date='2026-10-14',targets=targets,provenance={name:dict(sha256=t['sha256'],archive=t['archive_provenance']) for name,t in [('RF_MapInfoTable_Spawn',spawn),('RF_NPCTable',npc),('RF_StringTable_RU',strings)]},calibration_source='native-points.json',ui_check=dict(region_index=68001,observed_monsters=observed,screenshots=['rf-monster-list.png','rf-monsters-middle.png','rf-monsters-page2.png'],note='All 14 monsters and order checked in this region. Preview: Black Plain is a separate non-monster entry. Spawn coordinates are candidates, not confirmed teleport destinations.'))
 for path in [OUT/'monster-catalog.json',ROOT/'maps/monster-catalog.json']:path.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
 for loc in editor['locations']:loc['monster_targets']=[r for r in targets if r['region_index']==loc['region_index']]
 editor['monster_catalog']='monster-catalog.json'
 (OUT/'index-native.json').write_text(json.dumps(editor,ensure_ascii=False,indent=2),encoding='utf-8')
 print('Saved',len(targets),'monster spawn entries across',len({r['region_index'] for r in targets}),'Novus regions; Black Plain:',len(black))

if __name__=='__main__':build()
