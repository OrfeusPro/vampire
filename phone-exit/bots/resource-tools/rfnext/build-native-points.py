"""Join native map coordinates with Russian localization and calibrate to the atlas."""
import json,re,math,hashlib,os
from pathlib import Path
import numpy as np
import cv2
ROOT=Path(os.environ.get('PHONEEXIT_RF_RESOURCES',r'F:\PhoneExit Resources\RF Online Next'));DATA=ROOT/'data-study/rft/decoded'
OUT=Path(__file__).resolve().parents[3]/'pc/assets/maps/rfonlinenext'
def build():
 def load(name):return json.loads((DATA/(name+'.json')).read_text('utf-8'))
 strings=load('RF_StringTable_RU');unescape=lambda s:re.sub(r'\\u([0-9a-fA-F]{4})',lambda m:chr(int(m[1],16)),s)
 tr={r['values']['StringID']:unescape(r['values']['KO_KR']) for r in strings['records']}
 regions=load('RF_RegionTable');region_locations={r['values']['RegionIndex']:r['values']['Location'] for r in regions['records']}
 table=load('RF_MapInfoTable');survey=json.loads((OUT/'index.json').read_text('utf-8'));w,h=survey['original_size']
 normalize=lambda s:re.sub(r'\s+',' ',s.replace('ё','е').replace('Ё','Е')).strip().lower()
 manual={normalize(r['label']):r for r in survey['locations']};rows=[]
 for r in table['records']:
  v=dict(r['values']);xyz=v['Location'];v['location_source']='RF_MapInfoTable.Location'
  if not any(xyz) and v['RegionIndex'] in region_locations:
   xyz=region_locations[v['RegionIndex']];v['Location']=xyz;v['location_source']='RF_RegionTable.Location'
  if not all(math.isfinite(n) and abs(n)<1e8 for n in xyz):raise ValueError('Bad native coordinate')
  label=tr.get(v['MapInfoNameString'],v['MapInfoNameString']);rows.append(dict(**v,label=label,source_row_offset=r['offset']))
 matrices={};fits=[];review_ids=set()
 for mapid in (101,103):
  candidates=[r for r in rows if r['MapIndex']==mapid and normalize(r['label']) in manual and any(r['Location'])]
  src=np.float64([r['Location'][:2] for r in candidates]);dst=np.float64([[manual[normalize(r['label'])]['x']*w,manual[normalize(r['label'])]['y']*h] for r in candidates])
  if len(candidates)<4:raise ValueError('Insufficient named calibration anchors for '+str(mapid))
  matrix,mask=cv2.estimateAffine2D(src,dst,method=cv2.RANSAC,ransacReprojThreshold=12,maxIters=10000)
  if matrix is None or mask.sum()<4:raise ValueError('No terrain calibration')
  residual=np.linalg.norm(src@matrix[:,:2].T+matrix[:,2]-dst,axis=1)
  review_ids.update(r['MapInfoIndex'] for i,r in enumerate(candidates) if not mask[i][0])
  matrices[mapid]=matrix;fits.append(dict(map_index=mapid,matrix_world_to_atlas_pixels=matrix.tolist(),anchors=[dict(map_info_index=r['MapInfoIndex'],label=r['label'],world_xyz=r['Location'],survey_id=manual[normalize(r['label'])]['id'],residual_px=float(residual[i]),inlier=bool(mask[i][0])) for i,r in enumerate(candidates)],median_residual_px=float(np.median(residual[mask.ravel()==1])),inliers=int(mask.sum()),navigation_verified=False))
  print('Map',mapid,'anchors',len(candidates),'inliers',int(mask.sum()),'median',round(float(np.median(residual[mask.ravel()==1])),2),'px')
 mapped=[]
 for r in rows:
  if r['MapIndex'] not in matrices or not any(r['Location']) or r['MapInfoNameString'].startswith('Map_Name_Test'):continue
  xy=matrices[r['MapIndex']]@np.array([*r['Location'][:2],1]);x,y=float(xy[0]/w),float(xy[1]/h)
  if not (0<=x<1 and 0<=y<1):continue
  old=manual.get(normalize(r['label']));mapped.append(dict(id='native_'+str(r['MapInfoIndex']),label=r['label'],level=old['level'] if old else '',kind=old['kind'] if old else 'location',x=x,y=y,map_info_index=r['MapInfoIndex'],map_index=r['MapIndex'],region_index=r['RegionIndex'],region_group_index=r['RegionGroupIndex'],world_xyz=r['Location'],map_info_icon=r['MapInfoIcon'],jump_to=r['JumpTo'],source_table='RF_MapInfoTable',location_source=r['location_source'],source_row_offset=r['source_row_offset'],source_sha256=table['sha256'],position_source='native RFT Location; calibrated world-to-atlas',navigation_verified=False))
 result=dict(version=1,game_version='1.30.7',study_date='2026-10-14',native_table_records=len(rows),locations=mapped,all_map_records=rows,calibration=fits,table_provenance=table['archive_provenance'],table_sha256=table['sha256'],localization_provenance=strings['archive_provenance'],localization_sha256=strings['sha256'],atlas_sha256=survey['original_sha256'])
 for point in mapped:
  point['atlas_position_source']='native RFT calibrated position'
  if point['map_info_index'] in review_ids:
   old=manual[normalize(point['label'])];point['native_atlas_candidate']=[point['x'],point['y']];point['x']=old['x'];point['y']=old['y'];point['atlas_position_source']='survey fallback: native position disagrees with game screenshot';point['calibration_review_required']=True
 (ROOT/'maps/native-points.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
 (OUT/'native-points.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
 editor=dict(survey);editor['locations']=mapped;editor['position_source']='native RFT map/region tables';editor['native_source']='native-points.json';editor['native_table_sha256']=table['sha256'];editor['region_table_sha256']=regions['sha256'];editor['native_calibration']=fits
 (OUT/'index-native.json').write_text(json.dumps(editor,ensure_ascii=False,indent=2),encoding='utf-8')
 print('Saved',len(mapped),'native Novus POIs;',len(rows),'total game map markers')
if __name__=='__main__':build()
