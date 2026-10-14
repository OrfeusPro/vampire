"""Build PC map assets from preserved texture library and manually verified markers."""
import json, hashlib, re
from pathlib import Path
import numpy as np
from PIL import Image
from importlib.util import spec_from_file_location,module_from_spec
HERE=Path(__file__).resolve().parent
spec=spec_from_file_location('registration',HERE/'register-map.py');reg=module_from_spec(spec);spec.loader.exec_module(reg)
ROOT=reg.root
OUT=HERE.parents[2]/'pc/assets/maps/rfonlinenext'

def build():
    OUT.mkdir(parents=True,exist_ok=True)
    rows=json.loads((HERE/'map-labels.json').read_text('utf-8'))['views'];locations=[];views=[]
    atlas_hash=hashlib.sha256((ROOT/'maps/novus-world.png').read_bytes()).hexdigest()
    for view,markers in rows.items():
        source=ROOT/(view+'.png') if view=='map-title-ready' else ROOT/'maps/survey'/(view+'.png')
        checksum=hashlib.sha256(source.read_bytes()).hexdigest();cache=ROOT/'maps/survey'/(view+'.registration.json')
        r=json.loads(cache.read_text('utf-8')) if cache.exists() else {}
        if r.get('sha256')!=checksum or r.get('atlas_sha256')!=atlas_hash:
            r=reg.register(source);r['sha256']=checksum;r['atlas_sha256']=atlas_hash
            cache.write_text(json.dumps(r,indent=2,ensure_ascii=False),encoding='utf-8')
        print(view, r['inliers'],'inliers',round(r['median_residual_atlas_px'],2),'px',flush=True)
        matrix=np.array(r['matrix']);views.append(dict(view=view,sha256=checksum,matrix=r['matrix'],inliers=r['inliers'],median_residual_atlas_px=r['median_residual_atlas_px']))
        for label,level,kind,x,y in markers:
            xy=matrix@np.array([x*r['source_size'][0]/2048,y*r['source_size'][1]/922,1.])
            assert all(0<=n<1 for n in xy), (label,xy)
            locations.append(dict(id='poi_'+hashlib.sha256(label.encode()).hexdigest()[:12],label=label,level=level,kind=kind,x=round(float(xy[0]),7),y=round(float(xy[1]),7),source_view=view,source_preview_point=[x,y],source_frame_point=[round(x*r['source_size'][0]/2048,3),round(y*r['source_size'][1]/922,3)],source_sha256=checksum,provenance='manually transcribed icon center and label from game screenshot; terrain registration; not game-world coordinates',navigation_verified=False))
    assert len({r['id'] for r in locations})==len(locations),'Duplicate labels'
    locations.sort(key=lambda r:(r['kind']!='town',r['label']))
    with Image.open(ROOT/'maps/novus-world.png') as im:
        width,height=im.size;im.thumbnail((4096,4096));im.save(OUT/'novus-world.png',compress_level=6)
    index=dict(version=1,id='novus_world_101',label='Мир Novus',image='novus-world.png',original_size=[width,height],original_sha256=hashlib.sha256((ROOT/'maps/novus-world.png').read_bytes()).hexdigest(),image_sha256=hashlib.sha256((OUT/'novus-world.png').read_bytes()).hexdigest(),coordinate_space='normalized original cropped atlas; x and y in [0,1)',game_version='1.30.7',study_date='2026-10-14',source_package='com.netmarble.rfnext',labels_sha256=hashlib.sha256((HERE/'map-labels.json').read_bytes()).hexdigest(),locations=locations,registration=views,navigation_verified=False,coverage='Surveyed visible Novus POIs; unobserved markers are not invented')
    (OUT/'index.json').write_text(json.dumps(index,indent=2,ensure_ascii=False),encoding='utf-8')
    (ROOT/'maps/novus-locations.json').write_text(json.dumps(index,indent=2,ensure_ascii=False),encoding='utf-8')
    print('Saved',len(locations),'locations to',OUT,flush=True)
if __name__=='__main__':build()
