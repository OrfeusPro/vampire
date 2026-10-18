"""Project candidate surface polygons using the native-proven coordinate basis."""
import hashlib,importlib.util,json,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent


def main(root=Path('F:/PhoneExit Resources/Vampir')):
    spec=importlib.util.spec_from_file_location('overlay_coordinate_math',HERE/'recast-coordinate-math.py')
    model=importlib.util.module_from_spec(spec);spec.loader.exec_module(model)
    proof_path=root/'code-clues/recast-coordinate-evidence.json';proof_bytes=proof_path.read_bytes();proof=json.loads(proof_bytes)
    if hashlib.sha256((HERE/'recast-coordinate-math.py').read_bytes()).hexdigest()!=proof['model_sha256']:raise ValueError('Changed coordinate model')
    exe=Path(proof['source']).read_bytes()
    if hashlib.sha256(exe).hexdigest()!=proof['sha256']:raise ValueError('Changed coordinate EXE')
    for fragment in proof['fragments']:
        offset=fragment['file_offset'];size=fragment['end_rva']-fragment['begin_rva']
        if hashlib.sha256(exe[offset:offset+size]).hexdigest()!=fragment['sha256']:raise ValueError('Changed coordinate proof fragment')
    study=root/'maps/navigation-study';grid_path=study/'geometry-hypothesis-97/grid-inventory.json';grid_bytes=grid_path.read_bytes();grid=json.loads(grid_bytes)
    if grid['conflicts']:raise ValueError('Resolve grid conflicts before overlay')
    geometry_bytes=(study/'geometry-hypothesis-97/index.json').read_bytes();geometry=json.loads(geometry_bytes)
    if hashlib.sha256(geometry_bytes).hexdigest()!=grid['source_geometry_report_sha256']:raise ValueError('Changed geometry source')
    buffer_path=study/'tile-buffer-hypothesis-97/index.json';buffer_bytes=buffer_path.read_bytes();source=json.loads(buffer_bytes)
    if hashlib.sha256(buffer_bytes).hexdigest()!=geometry['source_buffer_report_sha256']:raise ValueError('Changed buffer source')
    packages=[]
    for entry in source['packages']:
        raw=(buffer_path.parent/entry['buffer_file']).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=entry['buffer_sha256']:raise ValueError('Changed buffers')
        packages.append(raw)
    tiles=[];polygons=0;special=0
    for tile_id,row in enumerate(grid['tiles']):
        origin=row['sources'][0];pi=origin['package_index'];record=source['packages'][pi]['records'][origin['tile_index']]
        start=record['buffer_offset'];raw=packages[pi][start:start+record['actual_memory_size']]
        if hashlib.sha256(raw).hexdigest()!=row['buffer_hashes'][0]:raise ValueError('Changed tile')
        pc,vc=struct.unpack_from('<HH',raw,4)
        vertices=[model.nav_to_world(struct.unpack_from('<3d',raw,88+24*i)) for i in range(vc)]
        faces=[]
        for poly in range(pc):
            offset=88+24*vc+32*poly;count=raw[offset+30]
            if raw[offset+31]>=64:special+=1;continue
            if not 1<=count<=6:raise ValueError('Invalid polygon count')
            ids=list(struct.unpack_from('<6H',raw,offset+4)[:count])
            if any(i>=vc for i in ids):raise ValueError('Invalid vertex index')
            faces.append(ids)
        if not faces:continue
        used={i for face in faces for i in face};points=[vertices[i] for i in used]
        bounds=[min(p[0] for p in points),min(p[1] for p in points),max(p[0] for p in points),max(p[1] for p in points)]
        tiles.append(dict(id=tile_id,bounds=bounds,vertices=[v[:2] for v in vertices],polygons=faces,
                          height_range=[min(p[2] for p in points),max(p[2] for p in points)]));polygons+=len(faces)
    result=dict(schema_version=1,coordinate_space='world_xy',navigation_ready=False,tiles=tiles,
                stats=dict(tiles=len(tiles),surface_polygons=polygons,special_polygons_omitted=special),
                source_grid_sha256=hashlib.sha256(grid_bytes).hexdigest(),coordinate_proof_sha256=hashlib.sha256(proof_bytes).hexdigest(),
                limitations=['Candidate union of all stored packages; active coverage and archive/property assumptions remain unverified.',
                             'All heights displayed together. Special transitions are omitted. Not a traversable-route layer.'])
    special_path=study/'special-links/index.json'
    if special_path.is_file():
        special_bytes=special_path.read_bytes();special=json.loads(special_bytes)
        if special['source_grid_report_sha256']!=result['source_grid_sha256'] or special['native_proof_sha256']['recast-coordinate-evidence.json']!=result['coordinate_proof_sha256']:raise ValueError('Changed special geometry source')
        if hashlib.sha256((root/'maps/atlas/lift-preview.json').read_bytes()).hexdigest()!=special['source_lift_preview_sha256']:raise ValueError('Changed spatial lift candidates')
        result['special_links']=[dict(id=p['id'],label='Особый переход '+str(i+1),start=p['original_world'][0],end=p['original_world'][1],
            baked_start=p['baked_vertex_world'][0],baked_end=p['baked_vertex_world'][1],
            spatial_lift_candidates=p['spatial_lift_candidates'],source_index=i,attachment_verified=False) for i,p in enumerate(special['links'])]
        result['special_source']=dict(file='../navigation-study/special-links/index.json',sha256=hashlib.sha256(special_bytes).hexdigest())
        result['stats']['special_links']=len(result['special_links'])
        result['limitations'][1]='All heights displayed together. Special transitions have a separate preliminary layer; their attachment/direction/accessibility are unverified.'
        direction_path=root/'code-clues/recast-special-direction-evidence.json'
        if direction_path.is_file():
            direction_bytes=direction_path.read_bytes();direction=json.loads(direction_bytes)
            if direction['sha256']!=proof['sha256'] or direction['source_special_report_sha256']!=hashlib.sha256(special_bytes).hexdigest():raise ValueError('Changed direction evidence source')
            if direction['model_sha256']!=hashlib.sha256((HERE/'recast-special-flags.py').read_bytes()).hexdigest():raise ValueError('Changed direction model')
            for fragment in direction['fragments']:
                offset=fragment['file_offset'];size=fragment['end_rva']-fragment['begin_rva']
                if hashlib.sha256(exe[offset:offset+size]).hexdigest()!=fragment['sha256']:raise ValueError('Changed direction proof fragment')
            if direction['point_flags_histogram']!={'192':62}:raise ValueError('Review direction flag conclusions')
            result['special_direction_evidence']=dict(file='../../code-clues/recast-special-direction-evidence.json',sha256=hashlib.sha256(direction_bytes).hexdigest())
            for point,display in zip(special['links'],result['special_links']):
                if point['flags_raw']!=192:raise ValueError('Unexpected direction flags')
                display['direction_gate_bypassed_by_flag']=True
            result['limitations'][1]='All heights displayed together. Stored special flags bypass three direction gates; attachment, other filters and accessibility remain unverified.'
        nearest_path=study/'special-links/nearest-candidates.json'
        if nearest_path.is_file():
            nearest_bytes=nearest_path.read_bytes();nearest=json.loads(nearest_bytes)
            audit=json.loads((nearest_path.parent/'nearest-candidates-audit.json').read_bytes())
            if audit['source_report_sha256']!=hashlib.sha256(nearest_bytes).hexdigest():raise ValueError('Changed nearest audit source')
            if nearest['sha256']!=proof['sha256'] or nearest['source_special_report_sha256']!=hashlib.sha256(special_bytes).hexdigest() or nearest['source_grid_report_sha256']!=result['source_grid_sha256']:raise ValueError('Changed nearest evidence source')
            for file,key in [('recast-nearest-emulator.py','emulator_sha256'),('recast-portal-emulator.py','base_emulator_sha256')]:
                if hashlib.sha256((HERE/file).read_bytes()).hexdigest()!=nearest[key]:raise ValueError('Changed nearest emulator')
            for fragment in nearest['fragments']:
                offset=fragment['file_offset'];size=fragment['end_rva']-fragment['begin_rva']
                if hashlib.sha256(exe[offset:offset+size]).hexdigest()!=fragment['sha256']:raise ValueError('Changed nearest native fragment')
            if [p['id'] for p in nearest['links']]!=[p['id'] for p in result['special_links']]:raise ValueError('Changed nearest point identity')
            result['special_nearest_evidence']=dict(file='../navigation-study/special-links/nearest-candidates.json',sha256=hashlib.sha256(nearest_bytes).hexdigest())
            for point,display in zip(nearest['links'],result['special_links']):
                display['surface_candidate_check']=dict(start_found=point['start']['horizontal_radius_accepted'],
                    start_matches_baked=point['start']['horizontal_radius_accepted'] and point['start']['baked_vertex_distance']==0,
                    end_candidate_count=sum(c['horizontal_radius_accepted'] and not c['same_as_start_polygon'] for c in point['end_candidates']),
                    end_matches_baked=any(c['horizontal_radius_accepted'] and not c['same_as_start_polygon'] and c['baked_vertex_distance']==0 for c in point['end_candidates']),
                    attachment_verified=False,bv_disabled=True)
        attachment_path=study/'special-links/attachment-study.json'
        if attachment_path.is_file():
            attachment_bytes=attachment_path.read_bytes();attachment=json.loads(attachment_bytes)
            audit=json.loads((attachment_path.parent/'attachment-study-audit.json').read_bytes())
            bv_bytes=(attachment_path.parent/'bv-priority-study.json').read_bytes();bv=json.loads(bv_bytes)
            if audit['source_report_sha256']!=hashlib.sha256(attachment_bytes).hexdigest() or attachment['source_bv_study_sha256']!=hashlib.sha256(bv_bytes).hexdigest():raise ValueError('Changed attachment audit/BV source')
            if attachment['source_special_report_sha256']!=hashlib.sha256(special_bytes).hexdigest() or attachment['source_grid_report_sha256']!=result['source_grid_sha256'] or attachment['sha256']!=proof['sha256']:raise ValueError('Changed attachment source')
            for file,digest in dict(bv['model_sha256'],**{'recast-attachment-emulator.py':attachment['emulator_sha256']}).items():
                if hashlib.sha256((HERE/file).read_bytes()).hexdigest()!=digest:raise ValueError('Changed attachment emulator')
            for fragment in attachment['fragments']+bv['fragments']:
                offset=fragment['file_offset'];size=fragment['end_rva']-fragment['begin_rva']
                if hashlib.sha256(exe[offset:offset+size]).hexdigest()!=fragment['sha256']:raise ValueError('Changed attachment native code')
            best=max(m['summary']['both_connected_matching_baked'] for m in attachment['modes'])
            candidates=[m for m in attachment['modes'] if m['summary']['both_connected_matching_baked']==best]
            if len(candidates)!=1:raise ValueError('Review ambiguous best attachment scenario')
            scenario=candidates[0]
            if [r['id'] for r in scenario['links']]!=[r['id'] for r in result['special_links']]:raise ValueError('Changed attachment point order')
            result['special_attachment_evidence']=dict(file='../navigation-study/special-links/attachment-study.json',sha256=hashlib.sha256(attachment_bytes).hexdigest(),scenario=scenario['name'],runtime_verified=False)
            for row,display in zip(scenario['links'],result['special_links']):
                display['native_attachment_scenario']=dict(connected=any(p['start_connected'] and p['end_connected'] for p in row['pairs']),
                    matches_baked=any(p['matches_baked_vertices'] for p in row['pairs']),runtime_verified=False)
        priority_path=root/'code-clues/recast-area-priority-evidence.json'
        if priority_path.is_file():
            priority_bytes=priority_path.read_bytes();priority=json.loads(priority_bytes)
            audit=json.loads((priority_path.parent/'recast-area-priority-audit.json').read_bytes())
            if audit['source_report_sha256']!=hashlib.sha256(priority_bytes).hexdigest() or priority['sha256']!=proof['sha256']:raise ValueError('Changed area priority evidence')
            for file,key in [('recast-area-priority-emulator.py','emulator_sha256'),('recast-portal-emulator.py','base_emulator_sha256')]:
                if hashlib.sha256((HERE/file).read_bytes()).hexdigest()!=priority[key]:raise ValueError('Changed area priority emulator')
            for fragment in priority['fragments']:
                offset=fragment['file_offset'];size=fragment['end_rva']-fragment['begin_rva']
                if hashlib.sha256(exe[offset:offset+size]).hexdigest()!=fragment['sha256']:raise ValueError('Changed area priority code')
            result['area_priority_evidence']=dict(file='../../code-clues/recast-area-priority-evidence.json',sha256=hashlib.sha256(priority_bytes).hexdigest(),active_values_verified=False)
        filter_path=study/'filter-resources/decoded.json'
        if filter_path.is_file():
            filter_bytes=filter_path.read_bytes();filters=json.loads(filter_bytes)
            audit=json.loads((filter_path.parent/'audit.json').read_bytes())
            filter_proof_bytes=(root/'code-clues/navigation-filter-code.json').read_bytes();filter_proof=json.loads(filter_proof_bytes)
            if audit['source_decoded_report_sha256']!=hashlib.sha256(filter_bytes).hexdigest() or filters['native_proof_sha256']!=hashlib.sha256(filter_proof_bytes).hexdigest() or audit['native_proof_sha256']!=filters['native_proof_sha256']:raise ValueError('Changed filter audit/proof')
            if filter_proof['sha256']!=proof['sha256'] or filters['source_resource_report_sha256']!=hashlib.sha256((filter_path.parent/'index.json').read_bytes()).hexdigest():raise ValueError('Changed filter source')
            for fragment in filter_proof['fragments']:
                offset=fragment['file_offset'];size=fragment['end_rva']-fragment['begin_rva']
                if hashlib.sha256(exe[offset:offset+size]).hexdigest()!=fragment['sha256']:raise ValueError('Changed filter native code')
            presets=[]
            for path in sorted({v['path'] for v in filters['variants']}):
                variants=[v for v in filters['variants'] if v['path']==path]
                if len({v['source_export']['export']['sha256'] for v in variants})!=1:raise ValueError('Review differing filter variants')
                presets.append(dict(path=path,name=path.rsplit('/',1)[-1],source_variants=len(variants),
                    areas=[r['properties'] for r in variants[0]['decoded']['areas']],runtime_verified=False))
            result['navigation_filter_presets']=presets
            result['navigation_filter_evidence']=dict(file='../navigation-study/filter-resources/decoded.json',sha256=hashlib.sha256(filter_bytes).hexdigest(),runtime_selection_verified=False)
            apply_path=root/'code-clues/recast-filter-apply-evidence.json'
            if apply_path.is_file():
                apply_bytes=apply_path.read_bytes();application=json.loads(apply_bytes)
                audit=json.loads((apply_path.parent/'recast-filter-apply-audit.json').read_bytes())
                if audit['source_report_sha256']!=hashlib.sha256(apply_bytes).hexdigest() or application['source_decoded_report_sha256']!=hashlib.sha256(filter_bytes).hexdigest() or application['native_filter_proof_sha256']!=hashlib.sha256(filter_proof_bytes).hexdigest():raise ValueError('Changed filter application source/audit')
                if application['sha256']!=proof['sha256']:raise ValueError('Changed application EXE')
                for file,key in [('recast-filter-apply-emulator.py','emulator_sha256'),('recast-portal-emulator.py','base_emulator_sha256')]:
                    if hashlib.sha256((HERE/file).read_bytes()).hexdigest()!=application[key]:raise ValueError('Changed filter application emulator')
                for fragment in application['fragments']+application['leaves']:
                    offset=fragment['file_offset'];size=fragment['end_rva']-fragment['begin_rva']
                    if hashlib.sha256(exe[offset:offset+size]).hexdigest()!=fragment['sha256']:raise ValueError('Changed application native code')
                for preset in presets:
                    cases=[c for c in application['cases'] if c['name']==preset['path'] and c['variant_index'] is not None]
                    if not cases or any(c['record_effects']!=cases[0]['record_effects'] for c in cases):raise ValueError('Review different filter application variants')
                    preset['application_check']=cases[0]['record_effects']
                result['navigation_filter_application_evidence']=dict(file='../../code-clues/recast-filter-apply-evidence.json',sha256=hashlib.sha256(apply_bytes).hexdigest(),runtime_selection_verified=False)
    out=root/'maps/atlas';path=out/'navigation-overlay.json';path.write_text(json.dumps(result,separators=(',',':')),'utf-8')
    manifest=dict(file=path.name,sha256=hashlib.sha256(path.read_bytes()).hexdigest(),stats=result['stats'],
                  coordinate_proof='../../code-clues/recast-coordinate-evidence.json',runtime_selection_verified=False)
    (out/'navigation-overlay-manifest.json').write_text(json.dumps(manifest,indent=2),'utf-8')
    print(json.dumps(dict(**result['stats'],bytes=path.stat().st_size,sha256=manifest['sha256'])))
    return manifest


if __name__=='__main__':main()
