"""Decode explicit filter CDO area records using the native property family."""
import hashlib,importlib.util,json,math
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('filter_property_reader',HERE/'decode-canvas-slots.py')
reader_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader_module)
FIELDS=['AreaClass','TravelCostOverride','EnteringCostOverride','bIsExcluded','bOverrideTravelCost','bOverrideEnteringCost']

def decode(raw,imports):
    reader=reader_module.Reader(raw);root_fields=reader.header()
    if root_fields!=[(0,False)]:raise ValueError('Unsupported filter CDO root fields')
    count=reader.read('<i')
    if not 0<=count<=1000:raise ValueError('Invalid filter area count')
    rows=[];by_id={i['index']:i for i in imports}
    def reference(index,seen=()):
        if index==0:return None
        if index not in by_id or index in seen:raise ValueError('Invalid/cyclic filter class import')
        item=by_id[index];parent=reference(item['outer'],(*seen,index)) if item['outer'] else None
        return parent+'.'+item['name'] if parent else item['name']
    for index in range(count):
        start=reader.pos;fields=reader.header();values={}
        for field,is_zero in fields:
            if not 0<=field<len(FIELDS):raise ValueError('Unknown filter area field')
            if field==0:
                value=0 if is_zero else reader.read('<i');values['AreaClassRaw']=value;value=reference(value)
            elif field in [1,2]:
                value=0. if is_zero else reader.read('<f')
                if not math.isfinite(value):raise ValueError('Nonfinite filter area value')
            else:
                value=0 if is_zero else reader.read('<B')
                if value not in [0,1]:raise ValueError('Invalid filter override bool')
                value=bool(value)
            values[FIELDS[field]]=value
        rows.append(dict(index=index,buffer_offset=start,serialized_size=reader.pos-start,raw_hex=raw[start:reader.pos].hex(),field_indices=fields,properties=values))
    suffix=raw[reader.pos:]
    if len(suffix)!=4:raise ValueError('Unexpected filter CDO suffix length')
    return dict(areas=rows,properties_consumed=reader.pos,uninterpreted_suffix_hex=suffix.hex(),runtime_filter_verified=False)

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    source_path=root/'maps/navigation-study/filter-resources/index.json';source_bytes=source_path.read_bytes();source=json.loads(source_bytes)
    proof_path=root/'code-clues/navigation-filter-code.json';proof_bytes=proof_path.read_bytes();proof=json.loads(proof_bytes)
    exe=Path(proof['source']).read_bytes()
    if hashlib.sha256(exe).hexdigest()!=proof['sha256']:raise ValueError('Changed native filter source')
    for fragment in proof['fragments']:
        off=fragment['file_offset'];size=fragment['end_rva']-fragment['begin_rva']
        if hashlib.sha256(exe[off:off+size]).hexdigest()!=fragment['sha256']:raise ValueError('Changed native filter fragment')
    if [r['name'] for r in proof['schemas']['area']['properties']]!=FIELDS:raise ValueError('Changed native filter field order')
    results=[]
    for variant_index,variant in enumerate(source['variants']):
        if variant['inheritance']['super_name']!='NavigationQueryFilter':raise ValueError('Unexpected filter superclass')
        entry=next(e for e in variant['exports'] if e['export']['index']==variant['cdo_export_index']);raw=(source_path.parent/entry['file']).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=entry['export']['sha256']:raise ValueError('Changed filter CDO')
        results.append(dict(path=variant['path'],variant_index=variant_index,source_export=entry,decoded=decode(raw,variant['imports'])))
    groups={path:[r['source_export']['export']['sha256'] for r in results if r['path']==path] for path in sorted({r['path'] for r in results})}
    report=dict(source_resource_report_sha256=hashlib.sha256(source_bytes).hexdigest(),native_proof_sha256=hashlib.sha256(proof_bytes).hexdigest(),
        variants=results,summary=dict(variants=len(results),unique_paths=len(groups),area_records=sum(len(r['decoded']['areas']) for r in results),
            same_path_differing_cdo_hashes=sum(len(set(hashes))>1 for hashes in groups.values()),runtime_filter_selection_verified=False,routes_verified=0,navigation_ready=False),
        limitations=['Only explicitly serialized fields decoded. Omitted values/archetype/runtime settings are not filled from constructor assumptions.',
            'Import paths identify area classes; flags and override values are preserved without claiming live filter activation.',
            'The four trailing bytes remain uninterpreted.'])
    path=source_path.parent/'decoded.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(**report['summary'],sha256=hashlib.sha256(path.read_bytes()).hexdigest())));return report

if __name__=='__main__':main()
