"""Source-pinned replay plus independent adjacency, reachability and corridor cost."""
import collections
import hashlib
import importlib.util
import json
import math
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()

def check_corridor(raw,case):
    pc,vc=struct.unpack_from('<HH',raw,4);off=88+vc*24
    vertices=[struct.unpack_from('<3d',raw,88+i*24) for i in range(vc)]
    polygons=[]
    for i in range(pc):
        pos=off+i*32;count=raw[pos+30];ids=struct.unpack_from('<6H',raw,pos+4)[:count]
        polygons.append(dict(vertices=ids,neighbors=struct.unpack_from('<6H',raw,pos+16)[:count],
            flags=struct.unpack_from('<H',raw,pos+28)[0],area=raw[pos+31]&63,
            center=[sum(vertices[v][axis] for v in ids)/count for axis in range(3)]))
    settings=case['settings'];include=settings.get('include',65535);exclude=settings.get('exclude',0)
    travel=settings.get('travel',[1.]*64);entering=settings.get('entering',[0.]*64)
    def allowed(index):return polygons[index]['flags']&include and not polygons[index]['flags']&exclude
    reached={case['start']};queue=collections.deque(reached)
    while queue:
        for word in polygons[queue.popleft()]['neighbors']:
            if not word or word&0x8000:continue
            target=word-1
            if target not in reached and allowed(target):reached.add(target);queue.append(target)
    result=case['result'];path=result['corridor'];status=result['status']
    assert status&0x40000000 and path and path[0]==case['start']
    assert bool(status&0x40)==(path[-1]!=case['end'])
    if settings.get('node_capacity',512)==512 and settings.get('cost_limit',1e300)==1e300:
        assert (path[-1]==case['end'])==(case['end'] in reached)
    position=polygons[path[0]]['center'];expected=[0.]
    for source,target in zip(path,path[1:]):
        current,following=polygons[source],polygons[target]
        edges=[i for i,word in enumerate(current['neighbors']) if word==target+1]
        assert len(edges)==1 and allowed(target)
        edge=edges[0];a=vertices[current['vertices'][edge]];b=vertices[current['vertices'][(edge+1)%len(current['vertices'])]]
        midpoint=[(x+y)*.5 for x,y in zip(a,b)]
        value=math.dist(position,midpoint)*travel[current['area']]
        if current['area']!=following['area']:value+=entering[following['area']]
        if target==case['end']:value+=math.dist(midpoint,following['center'])*travel[following['area']]
        expected.append(value);position=midpoint
    assert len(expected)==len(result['segment_costs'])
    for a,b in zip(expected,result['segment_costs']):assert math.isclose(a,b,rel_tol=2e-12,abs_tol=1e-8),(a,b,case['name'])
    assert math.isclose(sum(expected),result['total_cost'],rel_tol=2e-12,abs_tol=1e-8)
    return len(reached)

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    path=root/'code-clues/recast-path-query-evidence.json';report_raw=path.read_bytes();report=json.loads(report_raw)
    exe=Path(report['source']).read_bytes();assert sha(exe)==report['sha256']
    for file,key in [('recast-path-query-emulator.py','emulator_sha256'),('recast-portal-emulator.py','parent_emulator_sha256')]:assert sha((HERE/file).read_bytes())==report[key]
    assert sha((root/'code-clues/recast-geometry-code.json').read_bytes())==report['geometry_proof_sha256']
    folder=root/'maps/navigation-study/tile-buffer-hypothesis-97';manifest_raw=(folder/'index.json').read_bytes()
    assert sha(manifest_raw)==report['buffer_manifest_sha256'];manifest=json.loads(manifest_raw)
    for fragment in report['fragments']:
        off=fragment['file_offset'];length=fragment['end_rva']-fragment['begin_rva'];assert sha(exe[off:off+length])==fragment['sha256']
    for page in report['native_pages']:assert sha(exe[page['file_offset']:page['file_offset']+4096])==page['sha256']
    b=report['internal_link_block'];raw=bytes.fromhex(b['raw_hex']);assert sha(raw)==b['sha256'] and exe[b['file_offset']:b['file_offset']+len(raw)]==raw
    assert b['begin']==0x14523c6c1 and b['end_before_special_attachment']==0x14523c77a
    buffers={};tiles={}
    for tile in report['tiles']:
        package=manifest['packages'][tile['package_index']];record=package['records'][tile['record_index']]
        assert tile['buffer_file']==package['buffer_file'] and tile['offset']==record['buffer_offset'] and tile['length']==record['actual_memory_size']
        if tile['buffer_file'] not in buffers:
            buf=(folder/tile['buffer_file']).read_bytes();assert sha(buf)==package['buffer_sha256']==tile['buffer_sha256'];buffers[tile['buffer_file']]=buf
        raw=buffers[tile['buffer_file']][tile['offset']:tile['offset']+tile['length']]
        assert sha(raw)==tile['sha256']==record['tile_sha256'];tiles[tile['id']]=raw
    spec=importlib.util.spec_from_file_location('audit_path_emu',HERE/'recast-path-query-emulator.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);em=module.PathQueryEmulator(root)
    for case in report['cases']:
        raw=tiles[case['tile']];check_corridor(raw,case)
        assert em.search(raw,case['start'],case['end'],**case['settings'])==case['result']
    result=dict(source_report_sha256=sha(report_raw),native_cases_checked=len(report['cases']),native_replays=len(report['cases']),
        real_tiles=len(tiles),independent_connectivity_and_returned_cost_checked=True,global_optimality_asserted=False,
        path_search_executed=True,routes_verified=0,navigation_ready=False)
    (path.parent/'recast-path-query-audit.json').write_text(json.dumps(result,indent=2),'utf-8');print(json.dumps(result));return result

if __name__=='__main__':main()
