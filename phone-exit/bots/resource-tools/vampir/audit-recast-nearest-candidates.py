"""Check candidate provenance, selection completeness and bounded native replays."""
import hashlib,importlib.util,json,math,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    study=root/'maps/navigation-study';read=lambda path:json.loads(path.read_bytes())
    path=study/'special-links/nearest-candidates.json';report=read(path)
    source_bytes=(study/'special-links/index.json').read_bytes();source=json.loads(source_bytes)
    grid_bytes=(study/'geometry-hypothesis-97/grid-inventory.json').read_bytes();grid=json.loads(grid_bytes)
    assert report['source_special_report_sha256']==sha(source_bytes) and report['source_grid_report_sha256']==sha(grid_bytes)
    index_bytes=(study/'tile-buffer-hypothesis-97/index.json').read_bytes();index=json.loads(index_bytes)
    assert report['source_buffer_report_sha256']==sha(index_bytes)
    assert report['emulator_sha256']==sha((HERE/'recast-nearest-emulator.py').read_bytes())
    assert report['base_emulator_sha256']==sha((HERE/'recast-portal-emulator.py').read_bytes())
    native=Path(report['source']).read_bytes();assert sha(native)==report['sha256']
    for fragment in report['fragments']:
        offset=fragment['file_offset'];size=fragment['end_rva']-fragment['begin_rva'];assert sha(native[offset:offset+size])==fragment['sha256']
    for page in report['native_pages']:assert sha(native[page['file_offset']:page['file_offset']+4096])==page['sha256']
    packages=[]
    for package in index['packages']:
        raw=(study/'tile-buffer-hypothesis-97'/package['buffer_file']).read_bytes();assert sha(raw)==package['buffer_sha256'];packages.append(raw)
    tiles=[]
    for tile in grid['tiles']:
        origin=tile['sources'][0];pi=origin['package_index'];record=index['packages'][pi]['records'][origin['tile_index']]
        raw=packages[pi][record['buffer_offset']:record['buffer_offset']+record['actual_memory_size']]
        assert sha(raw)==tile['buffer_hashes'][0];tiles.append(raw)
    queries=[];assert len(report['links'])==len(source['links'])
    for row,point in zip(report['links'],source['links']):
        assert row['id']==point['id'] and row['attachment_verified'] is False
        assert row['start']['tile']==point['tile']
        endpoint=point['original_nav'][1];extent=[point['horizontal_radius'],point['search_height'],point['horizontal_radius']]
        selected=[]
        for i,raw in enumerate(tiles):
            bounds=struct.unpack_from('<6d',raw,40)
            if all(endpoint[a]+extent[a]>=bounds[a] and endpoint[a]-extent[a]<=bounds[a+3] for a in range(3)):selected.append(i)
        assert [c['tile'] for c in row['end_candidates']]==selected
        for end,candidate in [(0,row['start']),*((1,c) for c in row['end_candidates'])]:
            raw=tiles[candidate['tile']];assert sha(raw)==candidate['source_tile_sha256']
            assert candidate['attachment_verified'] is False and candidate['bv_disabled'] is True
            assert 0<=candidate['query_candidates']<=candidate['candidate_capacity']==128
            assert candidate['capacity_saturated']==(candidate['query_candidates']==128)
            point_nav=point['original_nav'][end];radius=point['horizontal_radius'];polygon=candidate['polygon']
            if polygon is not None:
                pc,vc=struct.unpack_from('<HH',raw,4);assert 0<=polygon<pc
                offset=88+24*vc+32*polygon;assert raw[offset+31]<64 and struct.unpack_from('<H',raw,offset+28)[0]!=0
                distance=math.dist(candidate['point_nav'],point['baked_vertex_nav'][end]);assert distance==candidate['baked_vertex_distance']
            else:assert candidate['baked_vertex_distance'] is None
            delta_x=candidate['point_nav'][0]-point_nav[0];delta_z=candidate['point_nav'][2]-point_nav[2]
            assert candidate['horizontal_radius_accepted']==(polygon is not None and delta_x*delta_x+delta_z*delta_z<=radius*radius)
            if end:assert candidate['same_as_start_polygon']==(candidate['tile']==row['start']['tile'] and polygon is not None and polygon==row['start']['polygon'])
            queries.append((candidate,point_nav,extent))
    spec=importlib.util.spec_from_file_location('nearest_audit_replay',HERE/'recast-nearest-emulator.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    emulator=module.NearestEmulator(root)
    selected=sorted({round(i*(len(queries)-1)/15) for i in range(16)})
    for i in selected:
        candidate,point,extent=queries[i];raw=tiles[candidate['tile']];emulator.load_tiles(raw,raw);actual=emulator.nearest(point,extent)
        for field,value in actual.items():assert value==candidate[field]
    summary=report['summary'];assert summary['points']==62 and summary['native_calls']==len(queries)+6
    assert summary['start_radius_accepted']==sum(r['start']['horizontal_radius_accepted'] for r in report['links'])==61
    assert summary['start_matches_baked']==sum(r['start']['baked_vertex_distance']==0 for r in report['links'])==60
    assert summary['end_matches_baked']==sum(any(c['horizontal_radius_accepted'] and not c['same_as_start_polygon'] and c['baked_vertex_distance']==0 for c in r['end_candidates']) for r in report['links'])==60
    result=dict(source_report_sha256=sha(path.read_bytes()),all_queries_checked=len(queries),native_replays=len(selected),routes_verified=0,navigation_ready=False)
    (path.parent/'nearest-candidates-audit.json').write_text(json.dumps(result,indent=2),'utf-8');print(json.dumps(result));return result

if __name__=='__main__':main()
