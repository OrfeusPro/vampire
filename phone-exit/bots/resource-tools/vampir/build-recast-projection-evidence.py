"""Exercise native endpoint projection on source-pinned ordinary tile pairs."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    spec=importlib.util.spec_from_file_location('project_evidence_native',HERE/'recast-projection-emulator.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);em=module.ProjectionEmulator(root)
    linked_raw=(root/'code-clues/recast-linked-path-evidence.json').read_bytes();linked=json.loads(linked_raw)
    tile_index={t['id']:t for t in linked['tiles']};tiles={};buffers={};cases=[];routes=[]
    def raw(tid):
        if tid in tiles:return tiles[tid]
        t=tile_index[tid];file=t['buffer_file']
        if file not in buffers:
            buffers[file]=(root/'maps/navigation-study/tile-buffer-hypothesis-97'/file).read_bytes();assert sha(buffers[file])==t['buffer_sha256']
        result=buffers[file][t['offset']:t['offset']+t['length']];assert sha(result)==t['sha256'];tiles[tid]=result;return result
    for selection in linked['external_selections']:
        previous=next(c for c in linked['cases'] if c['kind']=='external' and c['name']=='forward' and c['selection']==selection)
        raws=[raw(tid) for tid in selection['tiles']];options=previous['options']
        em.prepare_pair(raws,**options);em.connect_external(selection['side']);em.configure_grid([0.,0.,0.],[1000.,1000.])
        a=em.centers_pair[selection['start'][0]][selection['start'][1]];b=em.centers_pair[selection['end'][0]][selection['end'][1]]
        points=[('start',a,[25.,50.,25.]),('end',b,[25.,50.,25.]),
            ('above',[a[0],a[1]+20.,a[2]],[25.,50.,25.]),
            ('below',[a[0],a[1]-20.,a[2]],[25.,50.,25.]),
            ('outside_vertical_extent',[a[0],a[1]+100.,a[2]],[1.,1.,1.]),
            ('outside_grid',[a[0]+10000.,a[1],a[2]+10000.],[25.,50.,25.])]
        # A point just outside one edge tests horizontal clamp and detail height.
        source=raws[0];p=selection['start'][1];vc=struct.unpack_from('<H',source,6)[0];off=88+24*vc+32*p
        v=struct.unpack_from('<H',source,off+4)[0];vertex=struct.unpack_from('<3d',source,88+24*v)
        points.append(('near_vertex',[vertex[0]+5.,vertex[1]+5.,vertex[2]-5.],[25.,50.,25.]))
        for name,point,extents in points:
            result=em.project(point,extents)
            cases.append(dict(selection=selection,options=options,grid=em.grid,name=name,point=point,extents=extents,result=result))
        # Same geometry, all candidate flags excluded.
        blocked=dict(options,exclude=65535);em.prepare_pair(raws,**blocked);em.configure_grid([0.,0.,0.],[1000.,1000.])
        result=em.project(a,[25.,50.,25.]);assert result['polygon'] is None
        cases.append(dict(selection=selection,options=blocked,grid=em.grid,name='all_flags_excluded',point=a,extents=[25.,50.,25.],result=result))
        em.prepare_pair(raws,**options);em.connect_external(selection['side']);em.configure_grid([0.,0.,0.],[1000.,1000.])
        start=[a[0],a[1]+20.,a[2]];end=[b[0],b[1]-20.,b[2]];extents=[25.,50.,25.]
        result=em.route_between_points(start,end,extents)
        assert result['corridor_query'] is not None and not result['corridor_query']['status']&0x40
        routes.append(dict(selection=selection,options=options,grid=em.grid,start=start,end=end,extents=extents,result=result,state=em.snapshot()))
    offset=em.image.offset(0x52451e4)
    instruction=next(r for f in em.projection_fragments for r in f['instructions'] if r['address']==0x1452451e4)
    literal=instruction['rip_references'][0];lo=em.image.offset(literal-em.image.pe.base);data=em.data[lo:lo+8]
    report=dict(source=linked['source'],sha256=sha(em.data),source_linked_report_sha256=sha(linked_raw),
        dependencies={file:sha((HERE/file).read_bytes()) for file in ['recast-projection-emulator.py','recast-linked-path-emulator.py','recast-path-query-emulator.py','recast-portal-emulator.py']},
        fragments=em.projection_fragments+em.linked_fragments+em.query_fragments+em.fragments,native_pages=list(em.pages.values()),
        minimum_extent=dict(address=literal,file_offset=lo,raw_hex=data.hex(),value=struct.unpack('<d',data)[0]),
        cases=cases,projected_routes=routes,tiles=[tile_index[i] for i in tiles],
        summary=dict(native_cases=len(cases),tile_pairs=len(linked['external_selections']),
            projections_found=sum(c['result']['polygon'] is not None for c in cases),
            candidate_capacity_saturated=sum(c['result']['capacity_saturated'] for c in cases),
            projected_corridors=len(routes),straight_path_executed=False,routes_verified=0,navigation_ready=False),
        limitations=['Full native coordinate→tile hash→BV/flag/area admission→closest/detail-height→nearest selection runs, on two explicit candidate tiles only.',
            'Grid origin[0,0,0], width[1000,1000], mask0/hash chain, height35, quantization/priorities/filter arrays are explicit synthetic scenario inputs, not active mesh settings.',
            'Inputs already use nav coordinates; the established world→nav convention is not a live position detector.',
            '128candidate capacity, tile list<32, extents<=1000; allocation paths forbidden. Only stack cookie checks skipped.',
            'No alternate reference point in these cases; no funnel or controller movement; runtime callbacks/cluster links disabled.'])
    path=root/'code-clues/recast-projection-evidence.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(**report['summary'],sha256=sha(path.read_bytes()))));return report

if __name__=='__main__':main()
