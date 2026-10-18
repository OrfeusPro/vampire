"""Query original endpoints with the native no-BV fallback; retain uncertainty."""
import hashlib,importlib.util,json,math,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent

def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def intersects(point,extent,bounds):
    return all(point[i]+extent[i]>=bounds[i] and point[i]-extent[i]<=bounds[i+3] for i in range(3))

def radial_accept(point,candidate,radius):
    return (point[0]-candidate[0])**2+(point[2]-candidate[2])**2<=radius**2

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    emulator=load('nearest_candidates_emu','recast-nearest-emulator.py').NearestEmulator(root)
    fixtures=load('nearest_candidates_fixture','build-recast-portal-evidence.py')
    native_rows={r['address']:r for f in emulator.nearest_fragments for r in f['instructions']};anchors=[]
    for address,mnemonic,operands in [
        (0x1452455df,'call','0x1452513c0'),(0x145245654,'call','0x14523e360'),
        (0x145245697,'jae','0x1452456a7'),(0x1452456db,'comisd','xmm0, xmmword ptr [rax + 8]'),
        (0x1452456e0,'cmova','rbp, rdx'),(0x145251406,'test','r10, r10'),
        (0x145251409,'je','0x145251681'),(0x145251717,'cmp','byte ptr [r9 + 0x1f], 0x40'),
        (0x145251722,'cmp','word ptr [r9 + 0x1c], 0'),(0x14525172a,'cmp','byte ptr [rsp + 0x120], 0'),
        (0x14524559a,'mov','dword ptr [rsp + 0x28], 0x80')]:
        row=native_rows[address]
        if (row['mnemonic'],row['operands'])!=(mnemonic,operands):raise ValueError('Changed nearest anchor '+hex(address))
        anchors.append(row)
    synthetics=[]
    for name,point,extent,kind,flags,expected in [
        ('inside',[.75,0,.25],[.1,.1,.1],10,1,[.75,0,.25]),
        ('height_boundary',[.75,.5,.25],[1,.5,1],10,1,[.75,0,.25]),
        ('above_height',[.75,.5001,.25],[1,.5,1],10,1,None),
        ('outside_edge',[1.2,0,.25],[.3,1,.3],10,1,[1,0,.25]),
        ('special_excluded',[.75,0,.25],[1,1,1],127,1,None),
        ('zero_polygon_flags_excluded',[.75,0,.25],[1,1,1],10,0,None)]:
        raw=bytearray(fixtures.triangle_tile());raw[160+31]=kind;struct.pack_into('<H',raw,160+28,flags)
        emulator.load_tiles(bytes(raw),bytes(raw));result=emulator.nearest(point,extent)
        if expected is None:
            if result['polygon'] is not None:raise ValueError('Synthetic exclusion failed '+name)
        elif result['polygon']!=0 or math.dist(expected,result['point_nav'])>1e-12:raise ValueError('Synthetic nearest mismatch '+name)
        synthetics.append(dict(name=name,point=point,extents=extent,expected_point=expected,result=result))
    study=root/'maps/navigation-study';read=lambda path:json.loads(path.read_bytes())
    point_path=study/'special-links/index.json';points=read(point_path)
    grid_path=study/'geometry-hypothesis-97/grid-inventory.json';grid=read(grid_path)
    if hashlib.sha256(grid_path.read_bytes()).hexdigest()!=points['source_grid_report_sha256']:raise ValueError('Changed grid source')
    geometry_path=study/'geometry-hypothesis-97/index.json';geometry=read(geometry_path)
    if hashlib.sha256(geometry_path.read_bytes()).hexdigest()!=grid['source_geometry_report_sha256']:raise ValueError('Changed geometry source')
    buffer_path=study/'tile-buffer-hypothesis-97/index.json';source=read(buffer_path)
    if hashlib.sha256(buffer_path.read_bytes()).hexdigest()!=geometry['source_buffer_report_sha256']:raise ValueError('Changed buffer report')
    packages=[]
    for package in source['packages']:
        raw=(buffer_path.parent/package['buffer_file']).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=package['buffer_sha256']:raise ValueError('Changed source buffer')
        packages.append(raw)
    tiles=[]
    for index,tile in enumerate(grid['tiles']):
        origin=tile['sources'][0];pi=origin['package_index'];rec=source['packages'][pi]['records'][origin['tile_index']]
        raw=packages[pi][rec['buffer_offset']:rec['buffer_offset']+rec['actual_memory_size']]
        if hashlib.sha256(raw).hexdigest()!=tile['buffer_hashes'][0]:raise ValueError('Changed tile')
        bounds=list(struct.unpack_from('<6d',raw,40))
        if not all(math.isfinite(v) for v in bounds) or any(bounds[i]>bounds[i+3] for i in range(3)):raise ValueError('Invalid tile bounds')
        tiles.append(dict(id=index,raw=raw,bounds=bounds))
    rows=[]
    def query(tile,p,endpoint):
        raw=tile['raw'];emulator.load_tiles(raw,raw);point=p['original_nav'][endpoint]
        radius=p['horizontal_radius'];result=emulator.nearest(point,[radius,p['search_height'],radius])
        result.update(tile=tile['id'],source_tile_sha256=hashlib.sha256(raw).hexdigest(),attachment_verified=False)
        result['horizontal_radius_accepted']=result['polygon'] is not None and radial_accept(point,result['point_nav'],radius)
        result['baked_vertex_distance']=math.dist(result['point_nav'],p['baked_vertex_nav'][endpoint]) if result['polygon'] is not None else None
        return result
    for p in points['links']:
        start=query(tiles[p['tile']],p,0);radius=p['horizontal_radius'];extent=[radius,p['search_height'],radius]
        candidates=[query(tile,p,1) for tile in tiles if intersects(p['original_nav'][1],extent,tile['bounds'])]
        for candidate in candidates:
            candidate['same_as_start_polygon']=candidate['tile']==start['tile'] and candidate['polygon']==start['polygon'] and start['polygon'] is not None
        rows.append(dict(id=p['id'],start=start,end_candidates=candidates,attachment_verified=False))
    summary=dict(points=len(rows),start_radius_accepted=sum(r['start']['horizontal_radius_accepted'] for r in rows),
        start_matches_baked=sum(r['start']['baked_vertex_distance']==0 for r in rows),end_tile_queries=sum(len(r['end_candidates']) for r in rows),
        end_with_radius_candidate=sum(any(c['horizontal_radius_accepted'] and not c['same_as_start_polygon'] for c in r['end_candidates']) for r in rows),
        end_matches_baked=sum(any(c['horizontal_radius_accepted'] and not c['same_as_start_polygon'] and c['baked_vertex_distance']==0 for c in r['end_candidates']) for r in rows),
        saturated_queries=sum(r['start']['capacity_saturated']+sum(c['capacity_saturated'] for c in r['end_candidates']) for r in rows),
        native_calls=emulator.nearest_calls,synthetic_cases=len(synthetics),routes_verified=0,navigation_ready=False)
    native_source=read(root/'code-clues/native-enums.json')
    report=dict(source=native_source['source'],sha256=native_source['sha256'],
        source_special_report_sha256=hashlib.sha256(point_path.read_bytes()).hexdigest(),source_grid_report_sha256=hashlib.sha256(grid_path.read_bytes()).hexdigest(),
        emulator_sha256=hashlib.sha256((HERE/'recast-nearest-emulator.py').read_bytes()).hexdigest(),
        base_emulator_sha256=hashlib.sha256((HERE/'recast-portal-emulator.py').read_bytes()).hexdigest(),
        source_buffer_report_sha256=hashlib.sha256(buffer_path.read_bytes()).hexdigest(),
        anchors=anchors,fragments=emulator.nearest_fragments,native_pages=list(emulator.pages.values()),
        skipped_cookie_calls=[0x1452456f2,0x14523e8f6],synthetic_tile_references=True,bv_disabled=True,
        summary=summary,synthetics=synthetics,links=rows,
        limitations=['Explicit native no-BV fallback path; runtime BV selection/order and preferred area-priority search not reproduced.',
            'End tiles selected by 3D bounding-box overlap across the candidate union, not runtime side/load-order dispatch.',
            'No complete attachment, link allocation, active coverage, direction/filter evaluation or traversable route certified.'])
    path=study/'special-links/nearest-candidates.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(**summary,sha256=hashlib.sha256(path.read_bytes()).hexdigest())));return report

if __name__=='__main__':main()
