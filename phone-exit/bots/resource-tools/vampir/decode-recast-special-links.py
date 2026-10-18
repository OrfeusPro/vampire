"""Decode special endpoints and keep spatial lift coincidences unverified."""
import collections,hashlib,importlib.util,json,math,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
sections_module=load('special_sections','recast-portal-emulator.py')
coordinates=load('special_coordinates','recast-coordinate-math.py')


def decode_points(raw):
    sections=sections_module.tile_sections(raw);pc,vc=struct.unpack_from('<HH',raw,4);count=struct.unpack_from('<H',raw,26)[0];rows=[];seen=set()
    for index in range(count):
        offset=sections[72]+index*80;data=raw[offset:offset+80]
        points=struct.unpack_from('<6d',data);radius,height=struct.unpack_from('<2d',data,48)
        identifier,poly,side,flags=struct.unpack_from('<QHBB',data,64)
        if not all(math.isfinite(v) for v in (*points,radius,height)) or radius<0 or height<0:raise ValueError('Invalid special endpoint/extent')
        if poly>=pc or poly in seen:raise ValueError('Invalid/duplicate special polygon')
        pos=sections[16]+poly*32
        if raw[pos+30]!=2 or raw[pos+31]<64:raise ValueError('Special point does not reference a two-vertex special polygon')
        ids=struct.unpack_from('<2H',raw,pos+4)
        if any(v>=vc for v in ids):raise ValueError('Special vertex outside tile')
        baked=[struct.unpack_from('<3d',raw,88+24*v) for v in ids]
        if not all(math.isfinite(v) for p in baked for v in p):raise ValueError('Invalid baked special vertex')
        original=[list(points[:3]),list(points[3:])];seen.add(poly)
        rows.append(dict(index=index,buffer_offset=offset,record_sha256=hashlib.sha256(data).hexdigest(),raw_hex=data.hex(),polygon=poly,
                         original_nav=original,original_world=[coordinates.nav_to_world(p) for p in original],
                         baked_vertex_nav=[list(p) for p in baked],baked_vertex_world=[coordinates.nav_to_world(p) for p in baked],
                         baked_endpoint_shift=[math.dist(a,b) for a,b in zip(original,baked)],
                         horizontal_radius=radius,search_height=height,identifier_raw=str(identifier),side_raw=side,flags_raw=flags,
                         tail_uninterpreted_hex=data[76:].hex(),attachment_verified=False))
    unresolved=[i for i in range(pc) if raw[sections[16]+i*32+31]>=64 and i not in seen]
    return rows,unresolved


def spatial_candidates(world,lifts,tolerance=1e-6):
    matches=[]
    for lift in lifts:
        for link in lift['calculated_links']:
            error=max(math.dist(world[0],link['left']),math.dist(world[1],link['right']))
            if error<=tolerance:matches.append(dict(lift_id=lift['id'],link_index=link['index'],max_endpoint_distance=error,
                tolerance=tolerance,component_binding_verified=False,world_coordinates_verified=False))
    return matches


def main(root=Path('F:/PhoneExit Resources/Vampir')):
    study=root/'maps/navigation-study';proofs={};exe=None
    for name in ['recast-special-code.json','recast-coordinate-evidence.json']:
        raw=(root/'code-clues'/name).read_bytes();proof=json.loads(raw)
        if exe is None:exe=Path(proof['source']).read_bytes()
        if hashlib.sha256(exe).hexdigest()!=proof['sha256']:raise ValueError('Changed native source')
        for f in proof['fragments']:
            offset=f['file_offset'];size=f['end_rva']-f['begin_rva']
            if hashlib.sha256(exe[offset:offset+size]).hexdigest()!=f['sha256']:raise ValueError('Changed native fragment')
        proofs[name]=hashlib.sha256(raw).hexdigest()
        if name=='recast-coordinate-evidence.json' and proof['model_sha256']!=hashlib.sha256((HERE/'recast-coordinate-math.py').read_bytes()).hexdigest():raise ValueError('Changed coordinate model')
    grid_bytes=(study/'geometry-hypothesis-97/grid-inventory.json').read_bytes();grid=json.loads(grid_bytes)
    geometry_bytes=(study/'geometry-hypothesis-97/index.json').read_bytes();geometry=json.loads(geometry_bytes)
    if hashlib.sha256(geometry_bytes).hexdigest()!=grid['source_geometry_report_sha256'] or grid['conflicts']:raise ValueError('Changed/conflicting geometry')
    buffer_bytes=(study/'tile-buffer-hypothesis-97/index.json').read_bytes();source=json.loads(buffer_bytes)
    if hashlib.sha256(buffer_bytes).hexdigest()!=geometry['source_buffer_report_sha256']:raise ValueError('Changed buffer source')
    lift_bytes=(root/'maps/atlas/lift-preview.json').read_bytes();lifts=json.loads(lift_bytes)
    component_bytes=(study/'level/link-properties.json').read_bytes();components=json.loads(component_bytes)
    component_ids=collections.defaultdict(list)
    for component in components['links']:
        for field in ['CustomLinkId','AuxiliaryCustomLinkId']:
            value=component['decoded']['properties'].get(field)
            if value and value!='0':component_ids[value].append(dict(export_index=component['source']['export']['index'],field=field,binding_verified=False))
    packages=[]
    for package in source['packages']:
        raw=(study/'tile-buffer-hypothesis-97'/package['buffer_file']).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=package['buffer_sha256']:raise ValueError('Changed source buffers')
        packages.append(raw)
    links=[];unresolved=[]
    for tile_id,tile in enumerate(grid['tiles']):
        origin=tile['sources'][0];pi=origin['package_index'];rec=source['packages'][pi]['records'][origin['tile_index']];start=rec['buffer_offset']
        raw=packages[pi][start:start+rec['actual_memory_size']]
        if hashlib.sha256(raw).hexdigest()!=tile['buffer_hashes'][0]:raise ValueError('Changed tile')
        points,unknown=decode_points(raw)
        unresolved.extend(dict(tile=tile_id,polygon=p) for p in unknown)
        for point in points:
            point.update(id='special-'+str(tile_id)+'-'+str(point['index']),tile=tile_id,grid=tile['grid'],layer=tile['layer'],
                         source_tile_sha256=tile['buffer_hashes'][0],source=origin,
                         spatial_lift_candidates=spatial_candidates(point['original_world'],lifts['lifts']),
                         component_numeric_id_candidates=component_ids.get(point['identifier_raw'],[]) if point['identifier_raw']!='0' else [])
            links.append(point)
    summary=dict(points=len(links),zero_identifiers=sum(p['identifier_raw']=='0' for p in links),
                 spatial_lift_matches=sum(bool(p['spatial_lift_candidates']) for p in links),
                 component_numeric_id_matches=sum(bool(p['component_numeric_id_candidates']) for p in links),
                 changed_baked_endpoints=sum(any(d!=0 for d in p['baked_endpoint_shift']) for p in links),
                 unresolved_special_polygons=len(unresolved),routes_verified=0,navigation_ready=False)
    report=dict(native_proof_sha256=proofs,source_grid_report_sha256=hashlib.sha256(grid_bytes).hexdigest(),
                source_lift_preview_sha256=hashlib.sha256(lift_bytes).hexdigest(),source_components_sha256=hashlib.sha256(component_bytes).hexdigest(),
                links=links,unresolved_special_polygons=unresolved,summary=summary,
                limitations=['Archive/property/custom-version assumptions from candidate buffers remain in effect.',
                             'Spatial coincidences are not component bindings; lift preview world transforms remain unverified.',
                             'Raw and baked endpoints differ; native attachment, flags, runtime conditions and direction remain unverified.'])
    out=study/'special-links';out.mkdir(exist_ok=True);path=out/'index.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(**summary,sha256=hashlib.sha256(path.read_bytes()).hexdigest())))
    return report


if __name__=='__main__':main()
