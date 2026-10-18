"""Decode native vertices/polygons and audit internal links in candidate buffers."""
import collections,hashlib,importlib.util,json,math,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent


def decode_tile(raw):
    if len(raw)<88 or struct.unpack_from('<H',raw)[0]!=7:raise ValueError('Unsupported tile header')
    pc,vc=struct.unpack_from('<HH',raw,4);polys_offset=88+vc*24;end=polys_offset+pc*32
    if end>len(raw):raise ValueError('Geometry arrays exceed tile buffer')
    vertices=[list(struct.unpack_from('<3d',raw,88+i*24)) for i in range(vc)]
    if not all(math.isfinite(x) for v in vertices for x in v):raise ValueError('Nonfinite vertex')
    polygons=[];links=[];high_bit_edges=[]
    for i in range(pc):
        values=struct.unpack_from('<I6H6HHBB',raw,polys_offset+32*i)
        first,indices,neighbors,flags,count,area_type=values[0],values[1:7],values[7:13],values[13],values[14],values[15]
        if not 1<=count<=6 or any(v>=vc for v in indices[:count]):raise ValueError('Polygon vertex index/count outside tile')
        active=neighbors[:count]
        if any(0<n<32768 and n>pc for n in active):raise ValueError('Internal neighbor index outside tile')
        polygons.append(dict(vertices=list(indices[:count]),neighbors_raw=list(active),flags_raw=flags,
                             area_type_raw=area_type,first_link_serialized_raw=first))
        if area_type>=64:continue
        for edge,n in enumerate(active):
            if 0<n<32768:links.append([i,edge,n-1])
            elif n>=32768:high_bit_edges.append([i,edge,n])
    mismatches=[]
    for i,edge,other in links:
        poly=polygons[i];target=polygons[other];v=poly['vertices'];w=target['vertices']
        reverse=[e for e,n in enumerate(target['neighbors_raw']) if n==i+1 and
                 w[e]==v[(edge+1)%len(v)] and w[(e+1)%len(w)]==v[edge]]
        if len(reverse)!=1:mismatches.append([i,edge,other])
    return dict(grid_raw=list(struct.unpack_from('<ii',raw,8)),layer_raw=struct.unpack_from('<H',raw,2)[0],
                vertices=vertices,polygons=polygons,internal_links=links,high_bit_edges_unresolved=high_bit_edges,
                decoded_geometry_prefix_bytes=end,remaining_bytes_uninterpreted=len(raw)-end,
                reciprocal_shared_edge_mismatches=mismatches)


def main(root=Path('F:/PhoneExit Resources/Vampir')):
    spec=importlib.util.spec_from_file_location('recast_geometry_validate',HERE/'validate-recast-tile-buffers.py')
    verifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(verifier)
    source_path=root/'maps/navigation-study/tile-buffer-hypothesis-97/index.json'
    verifier.main(source_path)
    source_bytes=source_path.read_bytes();source=json.loads(source_bytes)
    proof_path=root/'code-clues/recast-geometry-code.json';proof_bytes=proof_path.read_bytes();proof=json.loads(proof_bytes)
    exe=Path(proof['source']).read_bytes()
    if hashlib.sha256(exe).hexdigest()!=proof['sha256'] or proof['sha256']!=source['source']['sha256']:raise ValueError('Changed geometry EXE proof')
    for fragment in proof['fragments']+[proof['opaque_tail']]:
        offset=fragment['file_offset'];size=fragment['end_rva']-fragment['begin_rva']
        if hashlib.sha256(exe[offset:offset+size]).hexdigest()!=fragment['sha256']:raise ValueError('Changed geometry code fragment')
    out=root/'maps/navigation-study/geometry-hypothesis-97';out.mkdir(exist_ok=True)
    packages=[];totals=collections.Counter();area_types=collections.Counter();vertex_counts=collections.Counter()
    for package in source['packages']:
        buffers=(source_path.parent/package['buffer_file']).read_bytes();tiles=[];summary=collections.Counter()
        for record in package['records']:
            start=record['buffer_offset'];data=buffers[start:start+record['actual_memory_size']]
            tile=decode_tile(data)
            tile.update(index=record['index'],source_buffer_offset=start,source_tile_sha256=record['tile_sha256'])
            tiles.append(tile)
            summary.update(tiles=1,vertices=len(tile['vertices']),polygons=len(tile['polygons']),
                           internal_links=len(tile['internal_links']),unresolved_high_bit_edges=len(tile['high_bit_edges_unresolved']),
                           reciprocal_mismatches=len(tile['reciprocal_shared_edge_mismatches']))
            area_types.update(p['area_type_raw'] for p in tile['polygons']);vertex_counts.update(len(p['vertices']) for p in tile['polygons'])
        name=package['buffer_file'].removesuffix('-buffers.bin')+'-geometry.json'
        payload=dict(source_buffer_file=package['buffer_file'],source_buffer_sha256=package['buffer_sha256'],
                     tiles=tiles,summary=dict(summary),runtime_selection_verified=False,coordinates_projected=False)
        raw=json.dumps(payload,ensure_ascii=False,separators=(',',':')).encode('utf-8');(out/name).write_bytes(raw)
        packages.append(dict(file=name,sha256=hashlib.sha256(raw).hexdigest(),archive=package['archive'],package=package['package'],summary=dict(summary)))
        totals.update(summary)
    report=dict(source_buffer_report_sha256=hashlib.sha256(source_bytes).hexdigest(),geometry_proof_sha256=hashlib.sha256(proof_bytes).hexdigest(),
                decoder_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),packages=packages,
                summary=dict(packages=len(packages),**totals,routes_verified=0,navigation_ready=False),
                area_type_raw_histogram=dict(sorted(area_types.items())),polygon_vertex_count_histogram=dict(sorted(vertex_counts.items())),
                limitations=['Geometry decoded from buffers with explicit property/custom-version hypotheses.',
                             'All package versions retained; not a unique active navigation mesh.',
                             'Only within-tile links decoded; high-bit matching, special links and other buffer sections remain unresolved.',
                             'No world-to-map coordinate conversion or traversable route verification.'])
    path=out/'index.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(**report['summary'],sha256=hashlib.sha256(path.read_bytes()).hexdigest())))
    return report


if __name__=='__main__':main()
