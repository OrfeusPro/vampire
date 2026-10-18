"""Independent XZ clamp/detail-height model and exact projection replays."""
import hashlib
import importlib.util
import json
import math
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()

def sections(raw):
    cursor=88;result={}
    for ptr,size in [(24,24*struct.unpack_from('<H',raw,6)[0]),(16,32*struct.unpack_from('<H',raw,4)[0]),
        (32,16*struct.unpack_from('<H',raw,16)[0]),(40,(6*struct.unpack_from('<H',raw,18)[0]+7)&~7),
        (48,24*struct.unpack_from('<H',raw,20)[0]),(56,(4*struct.unpack_from('<H',raw,22)[0]+7)&~7)]:
        result[ptr]=cursor;cursor+=size
    return result

def triangle_height(point,vertices):
    a,b,c=vertices;x,z=point[0],point[2]
    bx,bz=b[0]-a[0],b[2]-a[2];cx,cz=c[0]-a[0],c[2]-a[2]
    determinant=bx*cz-cx*bz
    if abs(determinant)<1e-20:return None
    u=((x-a[0])*cz-cx*(z-a[2]))/determinant
    v=(bx*(z-a[2])-(x-a[0])*bz)/determinant
    if u>=-1e-6 and v>=-1e-6 and u+v<=1+1e-6:return a[1]+u*(b[1]-a[1])+v*(c[1]-a[1])
    return None

def closest_point(raw,polygon,point):
    s=sections(raw);off=s[16]+32*polygon;count=raw[off+30]
    ids=struct.unpack_from('<6H',raw,off+4)[:count]
    vertices=[struct.unpack_from('<3d',raw,88+24*i) for i in ids]
    inside=False;closest=None;distance=math.inf
    for a,b in zip(vertices,vertices[1:]+vertices[:1]):
        dx,dz=b[0]-a[0],b[2]-a[2];den=dx*dx+dz*dz
        t=min(1.,max(0.,((point[0]-a[0])*dx+(point[2]-a[2])*dz)/den)) if den else 0.
        candidate=[a[i]+(b[i]-a[i])*t for i in range(3)]
        d=(point[0]-candidate[0])**2+(point[2]-candidate[2])**2
        if d<distance:closest=candidate;distance=d
        if (a[2]>point[2])!=(b[2]>point[2]) and point[0]<(b[0]-a[0])*(point[2]-a[2])/(b[2]-a[2])+a[0]:inside=not inside
    result=list(point) if inside or distance<1e-16 else closest
    vertex_base,triangle_base,detail_vertices,triangles=struct.unpack_from('<HHBB',raw,s[40]+6*polygon)
    for t in range(triangles):
        indices=raw[s[56]+4*(triangle_base+t):s[56]+4*(triangle_base+t)+3]
        triangle=[vertices[index] if index<count else struct.unpack_from('<3d',raw,s[48]+24*(vertex_base+index-count)) for index in indices]
        height=triangle_height(result,triangle)
        if height is not None:result[1]=height;break
    return result

def check_projection(raws,case,minimum_extent):
    point=case['point'];extent=[max(v,minimum_extent) for v in case['extents']];grid=case['grid'];options=case['options'];expected=[]
    for ti,raw in enumerate(raws):
        gx,gz=struct.unpack_from('<ii',raw,8)
        if not (math.floor((point[0]-extent[0]-grid['origin'][0])/grid['widths'][0])<=gx<=math.floor((point[0]+extent[0]-grid['origin'][0])/grid['widths'][0]) and
            math.floor((point[2]-extent[2]-grid['origin'][2])/grid['widths'][1])<=gz<=math.floor((point[2]+extent[2]-grid['origin'][2])/grid['widths'][1])):continue
        s=sections(raw)
        for p in range(struct.unpack_from('<H',raw,4)[0]):
            off=s[16]+32*p;flags=struct.unpack_from('<H',raw,off+28)[0];area=raw[off+31]&63
            if raw[off+31]>=64 or not flags&options['include'] or flags&options['exclude']:continue
            if options['travel'][area]>=float.fromhex('0x1.fffffep127') or options['entering'][area]>=float.fromhex('0x1.fffffep127'):continue
            candidate=closest_point(raw,p,point)
            if any(abs(candidate[i]-point[i])>extent[i]+1e-7 for i in range(3)):continue
            expected.append((math.dist(candidate,point)**2,[ti,p],candidate))
    result=case['result'];assert result['status']==0x40000000 and not result['capacity_saturated']
    assert bool(expected)==(result['polygon'] is not None),(case['name'],expected,result)
    if expected:
        selected=next(row for row in expected if row[1]==result['polygon'])
        assert math.isclose(selected[0],min(row[0] for row in expected),rel_tol=2e-10,abs_tol=1e-6)
        assert math.dist(selected[2],result['point_nav'])<1e-6,(case['name'],selected,result)
    return len(expected)

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    path=root/'code-clues/recast-projection-evidence.json';report_raw=path.read_bytes();report=json.loads(report_raw)
    exe=Path(report['source']).read_bytes();assert sha(exe)==report['sha256']
    for file,digest in report['dependencies'].items():assert sha((HERE/file).read_bytes())==digest
    linked_raw=(root/'code-clues/recast-linked-path-evidence.json').read_bytes();assert sha(linked_raw)==report['source_linked_report_sha256'];linked=json.loads(linked_raw)
    assert linked['sha256']==report['sha256']
    for fragment in report['fragments']:
        off=fragment['file_offset'];length=fragment['end_rva']-fragment['begin_rva'];assert sha(exe[off:off+length])==fragment['sha256']
    for page in report['native_pages']:assert sha(exe[page['file_offset']:page['file_offset']+4096])==page['sha256']
    literal=report['minimum_extent'];data=bytes.fromhex(literal['raw_hex']);assert exe[literal['file_offset']:literal['file_offset']+8]==data
    assert struct.unpack('<d',data)[0]==literal['value']==1e-6
    buffers={};tiles={};source_index={t['id']:t for t in linked['tiles']}
    for tile in report['tiles']:
        assert tile==source_index[tile['id']]
        file=tile['buffer_file']
        if file not in buffers:
            raw=(root/'maps/navigation-study/tile-buffer-hypothesis-97'/file).read_bytes();assert sha(raw)==tile['buffer_sha256'];buffers[file]=raw
        raw=buffers[file][tile['offset']:tile['offset']+tile['length']];assert sha(raw)==tile['sha256'];tiles[tile['id']]=raw
    spec=importlib.util.spec_from_file_location('project_audit_native',HERE/'recast-projection-emulator.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);em=module.ProjectionEmulator(root)
    for case in report['cases']:
        selection=case['selection'];assert selection in linked['external_selections'];raws=[tiles[i] for i in selection['tiles']]
        previous=next(c for c in linked['cases'] if c['kind']=='external' and c['name']=='forward' and c['selection']==selection)
        assert case['options']==dict(previous['options'],exclude=65535 if case['name']=='all_flags_excluded' else 0)
        assert case['grid']==dict(origin=[0.,0.,0.],widths=[1000.,1000.],mask=0,loaded_tiles=2)
        check_projection(raws,case,literal['value'])
        em.prepare_pair(raws,**case['options'])
        if case['name']!='all_flags_excluded':em.connect_external(selection['side'])
        em.configure_grid(case['grid']['origin'],case['grid']['widths'])
        assert em.project(case['point'],case['extents'])==case['result']
    spec=importlib.util.spec_from_file_location('project_route_audit',HERE/'audit-recast-linked-path.py')
    linked_audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(linked_audit)
    for route in report['projected_routes']:
        selection=route['selection'];assert selection in linked['external_selections'];raws=[tiles[i] for i in selection['tiles']]
        result=route['result']
        for point,projection in [(route['start'],result['start_projection']),(route['end'],result['end_projection'])]:
            check_projection(raws,dict(point=point,extents=route['extents'],grid=route['grid'],options=route['options'],name='projected_route',result=projection),literal['value'])
        linked_audit.check_corridor(raws,dict(start=result['start_projection']['polygon'],end=result['end_projection']['polygon'],
            kind='projected_route',name='forward',options=route['options'],state=route['state'],result=result['corridor_query']),
            endpoint_positions=[result['start_projection']['point_nav'],result['end_projection']['point_nav']])
        em.prepare_pair(raws,**route['options']);em.connect_external(selection['side']);em.configure_grid(route['grid']['origin'],route['grid']['widths'])
        assert em.route_between_points(route['start'],route['end'],route['extents'])==result
        assert em.snapshot()==route['state']
    result=dict(source_report_sha256=sha(report_raw),native_replays=len(report['cases']),
        projected_corridor_replays=len(report['projected_routes']),
        independent_horizontal_clamp_detail_height_and_nearest_selection_checked=True,
        straight_path_executed=False,routes_verified=0,navigation_ready=False)
    (path.parent/'recast-projection-audit.json').write_text(json.dumps(result,indent=2),'utf-8');print(json.dumps(result));return result

if __name__=='__main__':main()
