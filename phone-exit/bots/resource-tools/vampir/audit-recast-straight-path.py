"""Independent funnel geometry and source-pinned native straight-path replays."""
import hashlib
import importlib.util
import json
import math
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
linked_audit=load('straight_link_geometry','audit-recast-linked-path.py')

def equal(a,b,epsilon=3.725290298461914e-9):return sum((x-y)**2 for x,y in zip(a,b))<epsilon
def area(a,b,c):return (c[0]-a[0])*(b[2]-a[2])-(b[0]-a[0])*(c[2]-a[2])

def funnel(start,end,portals):
    gates=[(start,start)]+portals+[(end,end)];result=[start];apex=left=right=start;ai=li=ri=0;i=1;steps=0
    while i<len(gates):
        steps+=1
        if steps>10000:raise ValueError('Independent funnel loop bound')
        new_left,new_right=gates[i]
        if area(apex,right,new_right)<=0:
            if equal(apex,right) or area(apex,left,new_right)>0:right=new_right;ri=i
            else:
                result.append(left);apex=left;ai=li;left=right=apex;li=ri=ai;i=ai+1;continue
        if area(apex,left,new_left)>=0:
            if equal(apex,left) or area(apex,right,new_left)<0:left=new_left;li=i
            else:
                result.append(right);apex=right;ai=ri;left=right=apex;li=ri=ai;i=ai+1;continue
        i+=1
    if not equal(result[-1],end):result.append(end)
    return result

def model_path(raws,scene):
    polys=[linked_audit.polygons(raw) for raw in raws];links=scene['state']['links'];vertices=scene['state']['vertices']
    result=[];start=scene['start'];gates=[]
    for a,b in zip(scene['corridor'],scene['corridor'][1:]):
        matches=[l for l in links if l['source']==a and l['target']==b];assert len(matches)==1
        gate=linked_audit.portal(matches[0],polys,vertices,links)
        special=polys[a[0]][a[1]]['kind'] or polys[b[0]][b[1]]['kind']
        if special:
            assert gate[0]==gate[1]
            segment=funnel(start,gate[0],gates)
            for point in segment:
                if not result or not equal(result[-1],point):result.append(point)
            gates=[];start=gate[0]
        else:gates.append(gate)
    for point in funnel(start,scene['end'],gates):
        if not result or not equal(result[-1],point):result.append(point)
    return result

def on_ordered_polyline(points,line):
    last=0.
    for point in points:
        possible=[]
        for i,(a,b) in enumerate(zip(line,line[1:])):
            dx,dz=b[0]-a[0],b[2]-a[2];den=dx*dx+dz*dz
            t=((point[0]-a[0])*dx+(point[2]-a[2])*dz)/den if den else 0.
            if -1e-8<=t<=1+1e-8 and math.hypot(point[0]-a[0]-t*dx,point[2]-a[2]-t*dz)<1e-6 and i+t>=last-1e-8:possible.append(i+t)
        assert possible,('Point outside independently calculated XZ path',point,line)
        last=min(possible)

def check_scene(raws,scene):
    expected=model_path(raws,scene);baseline=scene['results'][0]
    assert baseline['options']==0 and baseline['status']==0x40000000
    actual=[p['point_nav'] for p in baseline['points']]
    assert len(actual)==len(expected),(scene['kind'],actual,expected)
    for a,b in zip(actual,expected):assert math.dist(a,b)<1e-6,(scene['kind'],a,b)
    for result in scene['results']:
        points=result['points'];assert result['status']==0x40000000 and points
        assert points[0]['flags']&1 and points[-1]['flags']&2 and points[-1]['polygon'] is None
        assert math.dist(points[0]['point_nav'],scene['start'])<1e-6 and math.dist(points[-1]['point_nav'],scene['end'])<1e-6
        on_ordered_polyline([p['point_nav'] for p in points],expected)
        polys=[linked_audit.polygons(raw) for raw in raws]
        for link in scene['state']['links']:
            if not any(link['source']==a and link['target']==b for a,b in zip(scene['corridor'],scene['corridor'][1:])):continue
            target=link['target']
            if polys[target[0]][target[1]]['kind']:
                portal=linked_audit.portal(link,polys,scene['state']['vertices'],scene['state']['links'])
                assert any(p['flags']&4 and p['polygon']==target and math.dist(p['point_nav'],portal[0])<1e-6 for p in points)

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    path=root/'code-clues/recast-straight-path-evidence.json';report_raw=path.read_bytes();report=json.loads(report_raw)
    exe=Path(report['source']).read_bytes();assert sha(exe)==report['sha256']
    reports={}
    for file,digest in report['input_reports'].items():
        raw=(root/'code-clues'/file).read_bytes();assert sha(raw)==digest;reports[file]=json.loads(raw)
    for file,digest in report['dependencies'].items():assert sha((HERE/file).read_bytes())==digest
    for fragment in report['fragments']:
        off=fragment['file_offset'];length=fragment['end_rva']-fragment['begin_rva'];assert sha(exe[off:off+length])==fragment['sha256']
    for page in report['native_pages']:assert sha(exe[page['file_offset']:page['file_offset']+4096])==page['sha256']
    epsilon=report['epsilon_initializer'];raw=bytes.fromhex(epsilon['raw_hex']);assert exe[epsilon['file_offset']:epsilon['file_offset']+8]==raw
    assert epsilon['value']==3.725290298461914e-9
    emulator=load('straight_audit_native','recast-straight-path-emulator.py').StraightPathEmulator(root)
    assert report['synthetic_environment']==dict(gs_base=emulator.teb,tls_vector=emulator.teb+0x1000,tls_block=emulator.tls,
        tls_index=0,epoch_offset=0x101184,tls_epoch=0,static_guard_epoch=0,
        static_values={hex(a):dict(size=size,raw_hex=raw.hex()) for a,(size,raw) in emulator.static_values.items()})
    buffers={}
    def tile_raw(tile):
        file=tile['buffer_file']
        if file not in buffers:
            raw=(root/'maps/navigation-study/tile-buffer-hypothesis-97'/file).read_bytes();assert sha(raw)==tile['buffer_sha256'];buffers[file]=raw
        raw=buffers[file][tile['offset']:tile['offset']+tile['length']];assert sha(raw)==tile['sha256'];return raw
    for scene in report['scenes']:
        source=reports[scene['source_report']];case=source['cases'][scene['source_case']];tiles={t['id']:t for t in source['tiles']}
        assert source['sha256']==report['sha256']
        if scene['kind']=='internal':
            raw=tile_raw(tiles[case['tile']]);raws=[raw,raw];assert scene['corridor']==[[0,p] for p in case['result']['corridor']]
        else:
            raws=[tile_raw(tiles[i]) for i in case['selection']['tiles']];assert scene['corridor']==case['result']['corridor'] and scene['options']==case['options']
        check_scene(raws,scene)
        emulator.prepare_pair(raws,**scene['options'])
        start_ref=[0,case['start']] if scene['kind']=='internal' else case['start']
        end_ref=[0,case['end']] if scene['kind']=='internal' else case['end']
        assert scene['start']==emulator.centers_pair[start_ref[0]][start_ref[1]] and scene['end']==emulator.centers_pair[end_ref[0]][end_ref[1]]
        if scene['kind']=='external':emulator.connect_external(case['selection']['side'])
        elif scene['kind']=='special':emulator.connect_special(case['selection']['side'],same_tile=case['selection']['same_tile'])
        assert emulator.snapshot()==scene['state']
        for result in scene['results']:
            emulator.counts={};assert emulator.straight(scene['corridor'],scene['start'],scene['end'],result['options'])==result
    result=dict(source_report_sha256=sha(report_raw),scenes=len(report['scenes']),native_replays=report['summary']['native_cases'],
        independent_funnel_corners_special_endpoints_and_ordered_crossings_checked=True,straight_path_executed=True,routes_verified=0,navigation_ready=False)
    (path.parent/'recast-straight-path-audit.json').write_text(json.dumps(result,indent=2),'utf-8');print(json.dumps(result));return result

if __name__=='__main__':main()
