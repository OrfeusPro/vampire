"""Audit map source geometry and route inputs; never certify walkability from endpoints."""
import hashlib,importlib.util,json,math,re
from collections import Counter
from pathlib import Path

_spec=importlib.util.spec_from_file_location('readiness_area_math',Path(__file__).with_name('area-transform-math.py'))
area_math=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(area_math)

def assess(boxes,cases,world_ids,rotation_verified=False):
    rotations=[];checked_rotations=[];invalid=[];valid=0
    def vector(text):
        number=r'[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?'
        match=re.fullmatch(r'\s*x\s*=\s*('+number+r')\s*,\s*y\s*=\s*('+number+r')\s*',text)
        if not match:return None
        values=dict(zip(['x','y'],match.groups()))
        try:
            result=[float(values[k]) for k in ['x','y']]
            return result if all(math.isfinite(v) for v in result) else None
        except (ValueError,KeyError):return None
    for row in boxes:
        low,high=vector(row['AreaBoxMinPos']),vector(row['AreaBoxMaxPos'])
        try:yaw=float(row['Yaw'] or '0')
        except ValueError:yaw=float('nan')
        if low is None or high is None or not math.isfinite(yaw) or any(a>b for a,b in zip(low,high)):
            invalid.append(dict(record=row,reason='Malformed/nonfinite or inverted extents'))
        elif yaw!=0:
            if rotation_verified:
                checked_rotations.append(dict(record=row,rotation_pivot_verified=True,rotation_direction_verified=True,
                    polygon=area_math.vertices(low,high,yaw)))
            else:rotations.append(dict(record=row,rotation_pivot_verified=False,rotation_direction_verified=False,polygon=None))
        else:valid+=1
    route_inputs=[]
    for row in cases:
        try:finite=all(math.isfinite(float(row[k])) for k in ['sx','sy','sz','ex','ey','ez'])
        except (ValueError,KeyError):finite=False
        route_inputs.append(dict(record=row,input_coordinates_finite=finite,world_present=row['worldInfoId'] in world_ids,path_verified=False,walkable=None))
    summary=dict(area_boxes=len(boxes),zero_yaw_valid=valid,rotated_unverified=len(rotations),rotated_verified=len(checked_rotations),invalid_extents=len(invalid),route_inputs=len(cases),route_world_missing=sum(not r['world_present'] for r in route_inputs),route_invalid_coordinates=sum(not r['input_coordinates_finite'] for r in route_inputs),routes_verified=0,rotation_pivot_verified=rotation_verified,navigation_ready=False,nav_files=dict(sorted(Counter(r['navFileName'] for r in cases).items())))
    return dict(summary=summary,rotated_boxes=rotations,verified_rotated_boxes=checked_rotations,invalid_boxes=invalid,route_inputs=route_inputs)

def main(root):
    out=root/'maps/atlas';index=json.loads((out/'index.json').read_text('utf-8'));raw=(out/'tables.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=index['tables_sha256']:raise ValueError('Changed atlas tables')
    transform=area_math.validated_evidence(root,index['tables_sha256'])
    tables=json.loads(raw);report=assess(tables['AreaBox'],tables['NavigationTestCase'],{r['Id'] for r in tables['World']},rotation_verified=transform is not None)
    if transform:report['area_transform_source']=transform
    report.update(sources=dict(tables_file='maps/atlas/tables.json',tables_sha256=index['tables_sha256'],table_sources=index['sources']),limitations=['NavigationTestCase stores endpoints only, no expected path or pass/fail result.','AreaBox Type/PlayerBlockType and rotated coordinate pivot/direction are not proven collision or navigation rules.','Portal table links and map texture lines are not walkable paths.','No path solver or Android traversal was executed.'])
    evidence_path=root/'code-clues/area-box-code.json'
    if evidence_path.is_file():
        evidence=json.loads(evidence_path.read_text('utf-8'));exe=Path(evidence['source']).read_bytes()
        if hashlib.sha256(exe).hexdigest()!=evidence['sha256']:raise ValueError('Changed AreaBox native source')
        for anchor in evidence['anchors']+[evidence['vtable'],evidence['callback']]:
            value=bytes.fromhex(anchor['bytes']);offset=anchor['file_offset']
            if exe[offset:offset+len(value)]!=value:raise ValueError('Changed AreaBox native anchor')
        report['native_area_box_source']=dict(file='code-clues/area-box-code.json',sha256=hashlib.sha256(evidence_path.read_bytes()).hexdigest(),exe_sha256=evidence['sha256'])
    files=sorted(root.rglob('*_Nav.bin'));report['exported_nav_files']=[dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in files if p.is_file()]
    report['summary']['exported_nav_files']=len(report['exported_nav_files']);report['summary']['nav_search_scope']=str(root)
    navigation_path=root/'maps/navigation-study/index.json'
    if navigation_path.is_file():
        navigation=json.loads(navigation_path.read_text('utf-8'));exe=Path(navigation['source']).read_bytes()
        if hashlib.sha256(exe).hexdigest()!=navigation['exe_sha256']:raise ValueError('Changed navigation native source')
        for anchor in navigation['anchors']+navigation['literals']+navigation.get('native_descriptors',[]):
            value=bytes.fromhex(anchor['bytes']);offset=anchor['file_offset']
            if exe[offset:offset+len(value)]!=value:raise ValueError('Changed navigation anchor')
        for artifact in navigation['extracted']:
            if hashlib.sha256((navigation_path.parent/artifact['file']).read_bytes()).hexdigest()!=artifact['sha256']:raise ValueError('Changed navigation resource')
        report['navigation_source_study']=dict(file='../navigation-study/index.json',sha256=hashlib.sha256(navigation_path.read_bytes()).hexdigest(),summary=navigation['summary'])
        report['summary']['reference_asset_records']=navigation['summary']['reference_asset_records']
        report['summary']['external_actor_candidates']=navigation['summary']['external_actor_candidates']
        report['summary']['decoded_navigation_chunks']=navigation['summary'].get('decoded_chunks',0)
    generated_path=root/'maps/navigation-study/generated-chunks/index.json'
    if generated_path.is_file():
        generated=json.loads(generated_path.read_text('utf-8'))
        search_path=root/'maps/navigation-study/chunk-header-search/index.json'
        if hashlib.sha256(search_path.read_bytes()).hexdigest()!=generated['source_header_search_sha256']:raise ValueError('Changed generated navigation header search')
        for package in generated['packages']:
            if not package['package_pair_verified'] or not package['owner_chain_verified']:raise ValueError('Unverified generated navigation package')
            for artifact in package['parts']+package['navigation_exports']:
                expected=artifact.get('sha256',artifact.get('export',{}).get('sha256'))
                if hashlib.sha256((generated_path.parent/artifact['file']).read_bytes()).hexdigest()!=expected:raise ValueError('Changed generated navigation bytes')
        report['generated_navigation_source']=dict(file='../navigation-study/generated-chunks/index.json',sha256=hashlib.sha256(generated_path.read_bytes()).hexdigest(),summary=generated['summary'])
        report['summary']['generated_nav_packages']=generated['summary']['packages']
        report['summary']['generated_recast_bytes']=generated['summary']['recast_bytes']
    path=out/'geometry-readiness.json';path.write_text(json.dumps(report,ensure_ascii=False,separators=(',',':')),'utf-8')
    return dict(file=path.name,sha256=hashlib.sha256(path.read_bytes()).hexdigest(),summary=report['summary'])

if __name__=='__main__':
    import os
    print(json.dumps(main(Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES','F:/PhoneExit Resources/Vampir'))),ensure_ascii=False))
