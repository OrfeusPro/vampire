"""Audit candidate portals against buffer geometry and replay a native sample."""
import collections,hashlib,importlib.util,json,math,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent


def main(root=Path('F:/PhoneExit Resources/Vampir')):
    study=root/'maps/navigation-study';folder=study/'external-graph-height-35.0'
    report_bytes=(folder/'index.json').read_bytes();report=json.loads(report_bytes)
    graph_bytes=(folder/report['graph']['file']).read_bytes()
    if hashlib.sha256(graph_bytes).hexdigest()!=report['graph']['sha256']:raise ValueError('Changed graph')
    graph=json.loads(graph_bytes);grid_bytes=(study/'geometry-hypothesis-97/grid-inventory.json').read_bytes()
    if hashlib.sha256(grid_bytes).hexdigest()!=report['source_grid_report_sha256']:raise ValueError('Changed grid')
    grid=json.loads(grid_bytes);buffer_path=study/'tile-buffer-hypothesis-97/index.json';source_bytes=buffer_path.read_bytes();source=json.loads(source_bytes)
    if hashlib.sha256(source_bytes).hexdigest()!=report['source_buffer_report_sha256']:raise ValueError('Changed buffer manifest')
    spec=importlib.util.spec_from_file_location('audit_portal_emulator',HERE/'recast-portal-emulator.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    em=module.PortalEmulator(root)
    if report['emulator_sha256']!=hashlib.sha256((HERE/'recast-portal-emulator.py').read_bytes()).hexdigest():raise ValueError('Changed emulator')
    packages=[]
    for package in source['packages']:
        raw=(buffer_path.parent/package['buffer_file']).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=package['buffer_sha256']:raise ValueError('Changed buffer bytes')
        packages.append(raw)
    tiles=[]
    for identity in grid['tiles']:
        origin=identity['sources'][0];pi=origin['package_index'];rec=source['packages'][pi]['records'][origin['tile_index']]
        raw=packages[pi][rec['buffer_offset']:rec['buffer_offset']+rec['actual_memory_size']]
        if hashlib.sha256(raw).hexdigest()!=identity['buffer_hashes'][0]:raise ValueError('Changed tile identity')
        tiles.append(raw)
    if len(graph)!=len(tiles):raise ValueError('Graph tile count mismatch')
    pairs=set();queries=collections.defaultdict(list);portals=0;epsilon=.009999999776482582
    def edge_data(tile,poly,edge):
        raw=tiles[tile];pc,nv=struct.unpack_from('<HH',raw,4)
        if not 0<=poly<pc:raise ValueError('Polygon index')
        off=88+24*nv+32*poly;count=raw[off+30]
        if not 0<=edge<count:raise ValueError('Edge index')
        indices=struct.unpack_from('<6H',raw,off+4)
        if any(v>=nv for v in indices[:count]):raise ValueError('Vertex index')
        a=struct.unpack_from('<3d',raw,88+24*indices[edge]);b=struct.unpack_from('<3d',raw,88+24*indices[(edge+1)%count])
        word=struct.unpack_from('<H',raw,off+16+2*edge)[0]
        return a,b,word
    for ident,row in enumerate(graph):
        if row['tile_id']!=ident or row['source_tile_sha256']!=grid['tiles'][ident]['buffer_hashes'][0]:raise ValueError('Graph identity')
        for poly,edge,target,target_poly,low,high in row['connections']:
            if not 0<=target<len(tiles) or ident==target or not all(math.isfinite(x) for x in [low,high]) or high<low:raise ValueError('Portal bounds')
            a,b,word=edge_data(ident,poly,edge);side=word&255
            if word!=0x8000|side or side not in [0,2,4,6]:raise ValueError('Source side')
            dx,dy=module.SIDE_STEPS[side];x,y=row['grid']
            if graph[target]['grid'] not in [[x,y],[x+dx,y+dy]]:raise ValueError('Neighbor cell mismatch')
            pc,nv=struct.unpack_from('<HH',tiles[target],4)
            if not 0<=target_poly<pc:raise ValueError('Target polygon')
            off=88+24*nv+32*target_poly;matches=0;axis=0 if side in [0,4] else 2;along=2-axis
            for e in range(tiles[target][off+30]):
                c,d,n=edge_data(target,target_poly,e)
                if n!=0x8000|((side-4)&7):continue
                overlap=[max(min(a[along],b[along]),min(c[along],d[along])),min(max(a[along],b[along]),max(c[along],d[along]))]
                if abs(a[axis]-c[axis])<=epsilon and all(abs(x-y)<=1e-8 for x,y in zip(overlap,[low,high])):matches+=1
            if not matches:raise ValueError('Portal not on a matching boundary')
            pairs.add((ident,poly,target,target_poly));queries[(ident,poly,edge,target,side)].append(dict(polygon=target_poly,interval=[low,high]));portals+=1
    ordered=sorted(queries);sample=[]
    for i in range(min(32,len(ordered))):
        key=ordered[i*(len(ordered)-1)//31] if len(ordered)>=32 else ordered[i]
        tile,poly,edge,target,side=key;em.load_tiles(tiles[tile],tiles[target]);actual=em.match(poly,edge,side,report['height_parameter_hypothesis'])
        if actual!=queries[key]:raise ValueError('Native replay differs')
        sample.append(dict(query=list(key),result=actual))
    if portals!=report['summary']['matched_portals']:raise ValueError('Portal total mismatch')
    audit=dict(source_graph_report_sha256=hashlib.sha256(report_bytes).hexdigest(),
               summary=dict(tiles=len(tiles),portals=portals,unique_directed_polygon_pairs=len(pairs),
                            pairs_without_reverse=sum((b,q,a,p) not in pairs for a,p,b,q in pairs),native_replay_queries=len(sample)),
               native_replay=sample,native=em.provenance(),runtime_graph_verified=False)
    path=folder/'audit.json';path.write_text(json.dumps(audit,ensure_ascii=False,indent=2),'utf-8');print(json.dumps(dict(**audit['summary'],sha256=hashlib.sha256(path.read_bytes()).hexdigest())))
    return audit


if __name__=='__main__':main()
