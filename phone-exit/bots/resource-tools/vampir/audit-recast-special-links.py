"""Independently compare every special point with source bytes and deployed data."""
import hashlib,json,math,struct
from pathlib import Path

HERE=Path(__file__).resolve().parent

def sha(raw):return hashlib.sha256(raw).hexdigest()

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    study=root/'maps/navigation-study';atlas=root/'maps/atlas'
    read=lambda path:json.loads(path.read_bytes())
    report_path=study/'special-links/index.json';report=read(report_path)
    grid_path=study/'geometry-hypothesis-97/grid-inventory.json';grid=read(grid_path)
    assert sha(grid_path.read_bytes())==report['source_grid_report_sha256']
    source=read(study/'tile-buffer-hypothesis-97/index.json')
    buffers=[]
    for package in source['packages']:
        raw=(study/'tile-buffer-hypothesis-97'/package['buffer_file']).read_bytes()
        assert sha(raw)==package['buffer_sha256'];buffers.append(raw)
    for name,digest in report['native_proof_sha256'].items():
        path=root/'code-clues'/name;assert sha(path.read_bytes())==digest
        proof=read(path);native=Path(proof['source']).read_bytes();assert sha(native)==proof['sha256']
        for fragment in proof['fragments']:
            start=fragment['file_offset'];size=fragment['end_rva']-fragment['begin_rva']
            assert sha(native[start:start+size])==fragment['sha256']
    lifts_path=atlas/'lift-preview.json';assert sha(lifts_path.read_bytes())==report['source_lift_preview_sha256']
    assert sha((study/'level/link-properties.json').read_bytes())==report['source_components_sha256']
    lifts=read(lifts_path)['lifts'];expected=[];changed=0;spatial=0
    convert=lambda p:[-p[0],-p[2],p[1]]
    align=lambda n:(n+7)//8*8
    for tile_id,tile in enumerate(grid['tiles']):
        origin=tile['sources'][0];pi=origin['package_index'];record=source['packages'][pi]['records'][origin['tile_index']]
        start=record['buffer_offset'];raw=buffers[pi][start:start+record['actual_memory_size']]
        assert sha(raw)==tile['buffer_hashes'][0]
        u=lambda offset:struct.unpack_from('<H',raw,offset)[0]
        poly_start=88+24*u(6)
        special_start=poly_start+32*u(4)+16*u(16)+align(6*u(18))+24*u(20)+align(4*u(22))+16*u(24)
        special_polygons=set()
        for index in range(u(26)):
            p=report['links'][len(expected)];expected.append(p['id'])
            offset=special_start+80*index;data=raw[offset:offset+80]
            values=struct.unpack('<8dQHBB4s',data);poly=values[9]
            assert p['id']==f'special-{tile_id}-{index}' and p['source']==origin
            assert p['buffer_offset']==offset and p['raw_hex']==data.hex() and p['record_sha256']==sha(data)
            assert p['polygon']==poly and p['identifier_raw']==str(values[8])=='0'
            assert [p['horizontal_radius'],p['search_height'],p['side_raw'],p['flags_raw']]==[values[6],values[7],values[10],values[11]]
            assert p['tail_uninterpreted_hex']==values[12].hex() and p['attachment_verified'] is False
            original=[list(values[:3]),list(values[3:6])]
            assert p['original_nav']==original and p['original_world']==list(map(convert,original))
            position=poly_start+32*poly;assert raw[position+30]==2 and raw[position+31]>=64
            ids=struct.unpack_from('<2H',raw,position+4)
            baked=[list(struct.unpack_from('<3d',raw,88+24*v)) for v in ids]
            assert p['baked_vertex_nav']==baked and p['baked_vertex_world']==list(map(convert,baked))
            shifts=[math.dist(a,b) for a,b in zip(original,baked)]
            assert p['baked_endpoint_shift']==shifts;changed+=any(shifts);special_polygons.add(poly)
            candidates=[]
            for lift in lifts:
                for link in lift['calculated_links']:
                    error=max(math.dist(p['original_world'][0],link['left']),math.dist(p['original_world'][1],link['right']))
                    if error<=1e-6:candidates.append(dict(lift_id=lift['id'],link_index=link['index'],max_endpoint_distance=error,tolerance=1e-6,component_binding_verified=False,world_coordinates_verified=False))
            assert p['spatial_lift_candidates']==candidates and p['component_numeric_id_candidates']==[]
            spatial+=bool(candidates)
        assert special_polygons=={i for i in range(u(4)) if raw[poly_start+32*i+31]>=64}
    assert len(expected)==len(report['links'])==62 and changed==61 and spatial==39
    overlay_path=atlas/'navigation-overlay.json';overlay=read(overlay_path);manifest=read(atlas/'navigation-overlay-manifest.json')
    assert sha(overlay_path.read_bytes())==manifest['sha256']
    assert overlay['special_source']['sha256']==sha(report_path.read_bytes())
    if 'special_direction_evidence' in overlay:
        evidence_path=(atlas/overlay['special_direction_evidence']['file']).resolve();evidence=read(evidence_path)
        assert sha(evidence_path.read_bytes())==overlay['special_direction_evidence']['sha256']
        assert evidence['source_special_report_sha256']==sha(report_path.read_bytes())
        assert evidence['model_sha256']==sha((HERE/'recast-special-flags.py').read_bytes())
        assert evidence['point_flags_histogram']=={'192':62}
    nearest=None
    if 'special_nearest_evidence' in overlay:
        nearest_path=(atlas/overlay['special_nearest_evidence']['file']).resolve();nearest=read(nearest_path)
        assert sha(nearest_path.read_bytes())==overlay['special_nearest_evidence']['sha256']
        assert nearest['source_special_report_sha256']==sha(report_path.read_bytes())
        assert read(nearest_path.parent/'nearest-candidates-audit.json')['source_report_sha256']==sha(nearest_path.read_bytes())
    attachment_scenario=None
    if 'navigation_filter_evidence' in overlay:
        filter_path=(atlas/overlay['navigation_filter_evidence']['file']).resolve();filters=read(filter_path)
        assert sha(filter_path.read_bytes())==overlay['navigation_filter_evidence']['sha256']
        assert read(filter_path.parent/'audit.json')['source_decoded_report_sha256']==sha(filter_path.read_bytes())
        assert overlay['navigation_filter_evidence']['runtime_selection_verified'] is False
        for preset in overlay['navigation_filter_presets']:
            variants=[v for v in filters['variants'] if v['path']==preset['path']]
            assert preset['areas']==[r['properties'] for r in variants[0]['decoded']['areas']]
            assert preset['source_variants']==len(variants) and preset['runtime_verified'] is False
    if 'navigation_filter_application_evidence' in overlay:
        apply_path=(atlas/overlay['navigation_filter_application_evidence']['file']).resolve();application=read(apply_path)
        assert sha(apply_path.read_bytes())==overlay['navigation_filter_application_evidence']['sha256']
        assert read(apply_path.parent/'recast-filter-apply-audit.json')['source_report_sha256']==sha(apply_path.read_bytes())
        assert overlay['navigation_filter_application_evidence']['runtime_selection_verified'] is False
        assert application['summary']['runtime_filter_selection_verified'] is False
        for preset in overlay['navigation_filter_presets']:
            cases=[c for c in application['cases'] if c['name']==preset['path'] and c['variant_index'] is not None]
            assert cases and all(c['areas']==preset['areas'] and c['record_effects']==preset['application_check'] for c in cases)
    if 'area_priority_evidence' in overlay:
        priority_path=(atlas/overlay['area_priority_evidence']['file']).resolve();priority=read(priority_path)
        assert sha(priority_path.read_bytes())==overlay['area_priority_evidence']['sha256']
        assert read(priority_path.parent/'recast-area-priority-audit.json')['source_report_sha256']==sha(priority_path.read_bytes())
        assert overlay['area_priority_evidence']['active_values_verified'] is False and priority['summary']['active_cost_arrays_verified'] is False
    if 'special_attachment_evidence' in overlay:
        attachment_path=(atlas/overlay['special_attachment_evidence']['file']).resolve();attachment=read(attachment_path)
        assert sha(attachment_path.read_bytes())==overlay['special_attachment_evidence']['sha256']
        assert attachment['source_special_report_sha256']==sha(report_path.read_bytes())
        assert read(attachment_path.parent/'attachment-study-audit.json')['source_report_sha256']==sha(attachment_path.read_bytes())
        assert overlay['special_attachment_evidence']['runtime_verified'] is False
        attachment_scenario=next(m for m in attachment['modes'] if m['name']==overlay['special_attachment_evidence']['scenario'])
    assert len(overlay['special_links'])==len(expected)
    for p,display in zip(report['links'],overlay['special_links']):
        assert display['id']==p['id'] and display['attachment_verified'] is False
        assert [display['start'],display['end']]==p['original_world']
        assert [display['baked_start'],display['baked_end']]==p['baked_vertex_world']
        assert display['spatial_lift_candidates']==p['spatial_lift_candidates']
        if 'special_direction_evidence' in overlay:assert display['direction_gate_bypassed_by_flag'] is True and p['flags_raw']==192
        if nearest:
            row=nearest['links'][display['source_index']];assert row['id']==p['id']
            assert display['surface_candidate_check']==dict(start_found=row['start']['horizontal_radius_accepted'],
                start_matches_baked=row['start']['horizontal_radius_accepted'] and row['start']['baked_vertex_distance']==0,
                end_candidate_count=sum(c['horizontal_radius_accepted'] and not c['same_as_start_polygon'] for c in row['end_candidates']),
                end_matches_baked=any(c['horizontal_radius_accepted'] and not c['same_as_start_polygon'] and c['baked_vertex_distance']==0 for c in row['end_candidates']),
                attachment_verified=False,bv_disabled=True)
        if attachment_scenario:
            row=attachment_scenario['links'][display['source_index']];assert row['id']==p['id']
            assert display['native_attachment_scenario']==dict(connected=any(c['start_connected'] and c['end_connected'] for c in row['pairs']),
                matches_baked=any(c['matches_baked_vertices'] for c in row['pairs']),runtime_verified=False)
    scene_path=atlas/'nocturne.json';assert read(scene_path)['navigation_overlay']==manifest
    assert sha(scene_path.read_bytes())==read(atlas/'nocturne-manifest.json')['sha256']
    for source_name,target in [('world-map.html','index.html'),('world-map.js','world-map.js'),('world-map-model.js','world-map-model.js'),('nav-overlay-model.js','nav-overlay-model.js')]:
        assert (HERE/source_name).read_text('utf-8')==(atlas/target).read_text('utf-8')
    result=dict(source_report_sha256=sha(report_path.read_bytes()),overlay_sha256=manifest['sha256'],points=62,spatial_coincidences=39,changed_baked_endpoint_pairs=61,deployed_files_checked=4,routes_verified=0,navigation_ready=False)
    (report_path.parent/'audit.json').write_text(json.dumps(result,indent=2),'utf-8')
    print(json.dumps(result));return result

if __name__=='__main__':main()
