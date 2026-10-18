"""Execute native external-edge matching for the full deduplicated candidate union."""
import argparse,collections,hashlib,importlib.util,json,math,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent


def main(height,root=Path('F:/PhoneExit Resources/Vampir')):
    spec=importlib.util.spec_from_file_location('external_graph_emu',HERE/'recast-portal-emulator.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    if not math.isfinite(height) or height<0:raise ValueError('Height parameter must be explicit and nonnegative')
    em=module.PortalEmulator(root)
    study=root/'maps/navigation-study';grid_path=study/'geometry-hypothesis-97/grid-inventory.json';grid_bytes=grid_path.read_bytes();grid=json.loads(grid_bytes)
    if grid['conflicts'] or grid['within_package_duplicates']:raise ValueError('Resolve grid conflicts before union graph')
    geometry_path=study/'geometry-hypothesis-97/index.json';geometry_bytes=geometry_path.read_bytes();geometry=json.loads(geometry_bytes)
    if hashlib.sha256(geometry_bytes).hexdigest()!=grid['source_geometry_report_sha256']:raise ValueError('Changed geometry manifest')
    buffer_path=study/'tile-buffer-hypothesis-97/index.json';buffer_bytes=buffer_path.read_bytes();buffer_index=json.loads(buffer_bytes)
    if hashlib.sha256(buffer_bytes).hexdigest()!=geometry['source_buffer_report_sha256']:raise ValueError('Changed buffer manifest')
    buffers=[]
    for package in buffer_index['packages']:
        raw=(buffer_path.parent/package['buffer_file']).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=package['buffer_sha256']:raise ValueError('Changed source buffers')
        buffers.append(raw)
    tiles=[];cells=collections.defaultdict(list)
    for row in grid['tiles']:
        source=row['sources'][0];pi=source['package_index'];record=buffer_index['packages'][pi]['records'][source['tile_index']]
        raw=buffers[pi][record['buffer_offset']:record['buffer_offset']+record['actual_memory_size']]
        if hashlib.sha256(raw).hexdigest()!=row['buffer_hashes'][0]:raise ValueError('Changed grid tile')
        sections=module.tile_sections(raw);pc,nv=struct.unpack_from('<HH',raw,4);edges=[]
        for poly in range(pc):
            off=sections[16]+poly*32;count=raw[off+30]
            if not 1<=count<=6:raise ValueError('Invalid polygon count')
            vertices=struct.unpack_from('<6H',raw,off+4)
            for edge in range(count):
                neighbor=struct.unpack_from('<H',raw,off+16+edge*2)[0]
                if not neighbor&0x8000:continue
                side=neighbor&255
                if neighbor!=0x8000|side or side not in [0,2,4,6]:raise ValueError('Unsupported boundary word')
                if vertices[edge]>=nv or vertices[(edge+1)%count]>=nv:raise ValueError('Invalid boundary vertex')
                a=struct.unpack_from('<3d',raw,88+vertices[edge]*24);b=struct.unpack_from('<3d',raw,88+vertices[(edge+1)%count]*24)
                axis=0 if side in [0,4] else 2;along=2-axis
                edges.append(dict(polygon=poly,edge=edge,side=side,plane=a[axis],low=min(a[along],b[along]),high=max(a[along],b[along])))
        ident=len(tiles);cells[tuple(row['grid'])].append(ident)
        tiles.append(dict(raw=raw,edges=edges,grid=row['grid'],layer=row['layer'],sha256=row['buffer_hashes'][0],source=source))
    out=study/('external-graph-height-'+str(height));out.mkdir(exist_ok=True)
    shards=[];total_edges=total_portals=zero_pairs=0;epsilon=.009999999776482582;stats=collections.Counter()
    for tile_id,tile in enumerate(tiles):
        connections=[]
        for edge in tile['edges']:
            total_edges+=1;side=edge['side'];dx,dy=module.SIDE_STEPS[side];x,y=tile['grid']
            targets=set(cells.get((x+dx,y+dy),[])+cells.get((x,y),[]));targets.discard(tile_id)
            for target_id in sorted(targets):
                target=tiles[target_id]
                # Exact native admission gates only; never substitute for height matching.
                if not any(e['side']==(side-4)&7 and abs(edge['plane']-e['plane'])<=epsilon and
                           min(edge['high'],e['high'])-max(edge['low'],e['low'])>=epsilon for e in target['edges']):continue
                em.load_tiles(tile['raw'],target['raw'])
                result=em.match(edge['polygon'],edge['edge'],side,height)
                if not result:zero_pairs+=1
                for portal in result:
                    connections.append([edge['polygon'],edge['edge'],target_id,portal['polygon'],*portal['interval']]);total_portals+=1
        payload=dict(tile_id=tile_id,grid=tile['grid'],layer=tile['layer'],source_tile_sha256=tile['sha256'],connections=connections)
        shards.append(payload)
        if (tile_id+1)%1000==0:print(json.dumps(dict(tiles=tile_id+1,total=len(tiles),calls=em.calls,portals=total_portals,height_calls=em.height_samples)),flush=True)
    path=out/'graph.json';raw=json.dumps(shards,separators=(',',':')).encode('utf-8');path.write_bytes(raw)
    report=dict(source_grid_report_sha256=hashlib.sha256(grid_bytes).hexdigest(),source_buffer_report_sha256=hashlib.sha256(buffer_bytes).hexdigest(),
                emulator_sha256=hashlib.sha256((HERE/'recast-portal-emulator.py').read_bytes()).hexdigest(),native=em.provenance(),
                graph=dict(file=path.name,sha256=hashlib.sha256(raw).hexdigest()),height_parameter_hypothesis=height,
                summary=dict(candidate_tiles=len(tiles),boundary_edges=total_edges,native_calls=em.calls,matched_portals=total_portals,
                             native_rejected_pairs=zero_pairs,routes_verified=0,navigation_ready=False),
                limitations=['Full stored candidate union with explicit height/archive/property assumptions, not active runtime coverage.',
                             'Native portal matching only: runtime link allocation limits, load order, quantized link intervals and special links are not simulated.',
                             'No character traversal or coordinate conversion verified.'])
    path=out/'index.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(**report['summary'],sha256=hashlib.sha256(path.read_bytes()).hexdigest())))
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--height',type=float,required=True);args=parser.parse_args();main(args.height)
