"""Independent native-link admission, interval and corridor-cost audit + replay."""
import collections
import hashlib
import importlib.util
import json
import math
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()

def polygons(raw):
    pc,vc=struct.unpack_from('<HH',raw,4);offset=88+24*vc
    return [dict(vertices=list(struct.unpack_from('<6H',raw,offset+32*i+4)[:raw[offset+32*i+30]]),
        neighbors=list(struct.unpack_from('<6H',raw,offset+32*i+16)[:raw[offset+32*i+30]]),
        flags=struct.unpack_from('<H',raw,offset+32*i+28)[0],area=raw[offset+32*i+31]&63,kind=raw[offset+32*i+31]>>6) for i in range(pc)]

def portal(link,polys,vertices,links):
    source,target=tuple(link['source']),tuple(link['target']);p=polys[source[0]][source[1]];q=polys[target[0]][target[1]]
    def special_pair(point,poly,edge):
        indices=[poly['vertices'][edge]]*2 if poly['kind']==1 else poly['vertices'][edge*2:edge*2+2]
        assert len(indices)==2
        return [vertices[point[0]][i] for i in indices]
    if p['kind'] in [1,2]:return special_pair(source,p,link['edge'])
    if q['kind'] in [1,2]:
        back=[r for r in links if r['source']==list(target) and r['target']==list(source)]
        assert len(back)==1
        return special_pair(target,q,back[0]['edge'])
    edge=link['edge'];assert edge<len(p['vertices'])
    a=vertices[source[0]][p['vertices'][edge]];b=vertices[source[0]][p['vertices'][(edge+1)%len(p['vertices'])]]
    if link['metadata']<128 and (link['low']!=0 or link['high']!=255):
        return [[a[i]+(b[i]-a[i])*(bound*(1./255.)) for i in range(3)] for bound in [link['low'],link['high']]]
    return [a,b]

def check_corridor(raws,case,endpoint_positions=None):
    polys=[polygons(raw) for raw in raws];links=case['state']['links'];vertices=case['state']['vertices'];options=case['options']
    adjacency=collections.defaultdict(list)
    def allowed(link):
        q=polys[link['target'][0]][link['target'][1]];metadata=link['metadata']
        return (q['flags']&options['include'] and not q['flags']&options['exclude'] and
            options['travel'][q['area']]<float.fromhex('0x1.fffffep127') and options['entering'][q['area']]<float.fromhex('0x1.fffffep127') and
            not (metadata&0x60==0x40 and metadata&0x10))
    for link in links:
        if allowed(link):adjacency[tuple(link['source'])].append(link)
    start,end=tuple(case['start']),tuple(case['end']);seen={start};queue=collections.deque([start])
    while queue:
        for link in adjacency[queue.popleft()]:
            target=tuple(link['target'])
            if target not in seen:seen.add(target);queue.append(target)
    result=case['result'];path=[tuple(p) for p in result['corridor']]
    assert result['status']&0x40000000 and path and path[0]==start
    assert bool(result['status']&0x40)==(path[-1]!=end)
    assert (path[-1]==end)==(end in seen)
    def center(point):
        if endpoint_positions is not None:
            assert start!=end
            return endpoint_positions[0] if point==start else endpoint_positions[1]
        # Endpoints passed to native query are original arithmetic centers.
        raw=raws[point[0]];p=polys[point[0]][point[1]]
        v=[struct.unpack_from('<3d',raw,88+24*i) for i in p['vertices']]
        return [sum(x[j] for x in v)/len(v) for j in range(3)]
    position=center(start);expected=[0.]
    for source,target in zip(path,path[1:]):
        matches=[l for l in adjacency[source] if tuple(l['target'])==target];assert len(matches)==1
        a,b=portal(matches[0],polys,vertices,links);midpoint=[(x+y)*.5 for x,y in zip(a,b)]
        p,q=polys[source[0]][source[1]],polys[target[0]][target[1]]
        value=math.dist(position,midpoint)*options['travel'][p['area']]
        if p['area']!=q['area']:value+=options['entering'][q['area']]
        if target==end:value+=math.dist(midpoint,center(end))*options['travel'][q['area']]
        expected.append(value);position=midpoint
    assert len(expected)==len(result['segment_costs'])
    for a,b in zip(expected,result['segment_costs']):assert math.isclose(a,b,rel_tol=2e-12,abs_tol=1e-7),(case['kind'],case['name'],a,b)
    assert math.isclose(sum(expected),result['total_cost'],rel_tol=2e-12,abs_tol=1e-7)

def check_internal(raws,state):
    expected=[]
    for ti,raw in enumerate(raws):
        for pi,p in enumerate(polygons(raw)):
            if p['kind']:continue
            for edge,word in enumerate(p['neighbors']):
                if word and not word&0x8000:expected.append(dict(source=[ti,pi],target=[ti,word-1],edge=edge,metadata=128,low=0,high=0))
    actual=[l for l in state['links'] if l['metadata']==128]
    key=lambda l:json.dumps(l,sort_keys=True)
    assert sorted(map(key,actual))==sorted(map(key,expected))

def expected_external(raws,ids,side,graph):
    expected=[]
    for ti in [0,1]:
        raw=raws[ti];pc,vc=struct.unpack_from('<HH',raw,4);offset=88+24*vc;direction=side if ti==0 else (side-4)&7
        for p,edge,target,q,low,high in graph[ids[ti]]['connections']:
            if target!=ids[1-ti]:continue
            word=struct.unpack_from('<H',raw,offset+32*p+16+2*edge)[0]
            if word!=0x8000|direction:continue
            poly=polygons(raw)[p];axis=2 if direction in [0,4] else 0
            a=struct.unpack_from('<3d',raw,88+24*poly['vertices'][edge])[axis]
            b=struct.unpack_from('<3d',raw,88+24*poly['vertices'][(edge+1)%len(poly['vertices'])])[axis]
            ratio=1./(b-a);normalized=[(bound-a)*ratio for bound in [low,high]]
            bounds=[int(min(1.,max(0.,v))*255.) for v in [min(normalized),max(normalized)]]
            expected.append(dict(source=[ti,p],target=[1-ti,q],edge=edge,metadata=direction,low=bounds[0],high=bounds[1]))
    return expected

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    path=root/'code-clues/recast-linked-path-evidence.json';report_raw=path.read_bytes();report=json.loads(report_raw)
    exe=Path(report['source']).read_bytes();assert sha(exe)==report['sha256']
    for file,digest in report['dependencies'].items():assert sha((HERE/file).read_bytes())==digest
    study=root/'maps/navigation-study';inputs={}
    for file,digest in report['input_reports'].items():
        raw=(study/file).read_bytes();assert sha(raw)==digest;inputs[file]=json.loads(raw)
    index=inputs['tile-buffer-hypothesis-97/index.json'];grid=inputs['geometry-hypothesis-97/grid-inventory.json'];graph=inputs['external-graph-height-35.0/graph.json']
    for fragment in report['fragments']:
        off=fragment['file_offset'];length=fragment['end_rva']-fragment['begin_rva'];assert sha(exe[off:off+length])==fragment['sha256']
    for page in report['native_pages']:assert sha(exe[page['file_offset']:page['file_offset']+4096])==page['sha256']
    spec=importlib.util.spec_from_file_location('linked_audit_emu',HERE/'recast-linked-path-emulator.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);em=module.LinkedPathEmulator(root)
    off=em.image.offset(0x523c6c1);assert sha(exe[off:off+0xb9])==report['internal_block_sha256']
    buffers={};tiles={}
    for tile in report['tiles']:
        pi=tile['package_index'];package=index['packages'][pi];record=package['records'][tile['record_index']]
        assert tile['buffer_file']==package['buffer_file'] and tile['offset']==record['buffer_offset'] and tile['length']==record['actual_memory_size']
        assert any(s['package_index']==pi and s['tile_index']==tile['record_index'] for s in grid['tiles'][tile['id']]['sources'])
        if pi not in buffers:
            buf=(study/'tile-buffer-hypothesis-97'/package['buffer_file']).read_bytes();assert sha(buf)==package['buffer_sha256']==tile['buffer_sha256'];buffers[pi]=buf
        raw=buffers[pi][tile['offset']:tile['offset']+tile['length']]
        assert sha(raw)==tile['sha256']==record['tile_sha256']==grid['tiles'][tile['id']]['buffer_hashes'][0];tiles[tile['id']]=raw
    attachment=inputs['special-links/attachment-study.json'];mode=next(m for m in attachment['modes'] if m['name']=='priority_11_63_10')
    assert attachment['sha256']==report['sha256']
    key=lambda link:json.dumps(link,sort_keys=True)
    for case in report['cases']:
        selection=case['selection'];ids=selection['tiles'];raws=[tiles[i] for i in ids];state=case['state']
        options=case['options']
        assert options['height']==35. and options['quantization']==attachment['quantization_candidate']
        assert options['travel']==[1.]*64 and options['entering']==[0.]*64 and options['include']==65535 and options['node_capacity']==512
        assert options['exclude']==(65535 if case['name']=='excluded' else 0)
        assert options['priorities']==([0]*64 if case['kind']=='external' else mode['priorities'])
        check_internal(raws,state)
        if case['kind']=='external':
            expected=expected_external(raws,ids,selection['side'],graph) if case['connected'] else []
            actual=[l for l in state['links'] if l['metadata']!=128]
            assert sorted(map(key,actual))==sorted(map(key,expected))
            # Ordinary attachment must not alter vertices.
            for ti,raw in enumerate(raws):assert state['vertices'][ti]==[list(struct.unpack_from('<3d',raw,88+24*v)) for v in range(struct.unpack_from('<H',raw,6)[0])]
        else:
            original=next(c for c in attachment['cases'] if c['id']==selection['id'])
            assert ids[0]==original['source_tile'] and ids[1] in original['target_tiles']
            assert selection['side']==original['side_raw'] and selection['special_polygon']==original['special_polygon']
            assert selection['same_tile']==(ids[0]==ids[1])
            previous=next(row for row in mode['links'] if row['id']==selection['id'])
            pair=next(p for p in previous['pairs'] if p['target_tile']==ids[1]);before=pair['result']['end_state']
            expected=[dict(source=[l['source_tile_index'],l['source_polygon']],target=[l['target_tile_index'],l['target_polygon']],
                edge=l['edge_raw'],metadata=l['metadata_raw']) for l in before['links']]
            actual=[{k:v for k,v in l.items() if k not in ['low','high']} for l in state['links'] if l['metadata']!=128]
            assert sorted(map(key,actual))==sorted(map(key,expected))
            p=polygons(raws[0])[selection['special_polygon']]
            assert [state['vertices'][0][v] for v in p['vertices'][:2]]==before['vertices_nav']
            assert [0,selection['special_polygon']] in case['result']['corridor']
        check_corridor(raws,case)
        em.prepare_pair(raws,**case['options'])
        if case['connected']:
            if case['kind']=='external':em.connect_external(selection['side'])
            else:em.connect_special(selection['side'],same_tile=selection['same_tile'])
        assert em.snapshot()==state
        assert em.search_prepared(case['start'],case['end'])==case['result']
    result=dict(source_report_sha256=sha(report_raw),native_replays=len(report['cases']),
        independent_internal_links_external_intervals_special_attachment_and_corridor_cost_checked=True,
        external_pairs=report['summary']['external_pairs'],special_points=report['summary']['attached_special_points'],
        routes_verified=0,navigation_ready=False)
    (path.parent/'recast-linked-path-audit.json').write_text(json.dumps(result,indent=2),'utf-8');print(json.dumps(result));return result

if __name__=='__main__':main()
