"""Source-bound PanelSlot/UniformGridSlot candidate schemas; no inherited defaults inferred."""
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
SHA = 'd00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
SIZE_GETTER=0x143572e20
SPECS = {
    'PanelSlot': dict(fields=['Parent', 'Content'], flags=[82, 82], array=0x148fdd840,
        metadata=0x148fddad0, getter=0x1435b51e0, thunk=0x14356ab00),
    'UniformGridSlot': dict(fields=['HorizontalAlignment', 'VerticalAlignment', 'Row', 'Column'],
        flags=[0, 0, 3, 3], array=0x148fe5080, metadata=0x148fe51a0, getter=0x14357f1d0),
    'ScrollBoxSlot': dict(fields=['Size', 'Padding', 'HorizontalAlignment', 'VerticalAlignment'],
        flags=[25,25,0,0], array=0x148ff13f8, metadata=0x148ff14e0, getter=0x143583190, direct_array=True),
    'NamedSlot': dict(fields=[], flags=[], array=0, metadata=0x148fd58e0, getter=0x143579140,
        parent_thunk=0x14356aad0, parent_getter=0x1435b5080, parent_name='ContentWidget', container=True),
}


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


canvas = load('basic_slot_canvas', 'decode-canvas-slots.py')
props = load('basic_slot_properties', 'extract-ui-properties.py')
native = load('basic_slot_native', 'build-native-entry-code.py')
source = load('basic_slot_source', 'audit-ui-sources.py')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw, kind, allow_size=False):
    if kind not in SPECS or SPECS[kind].get('container'):
        raise ValueError('Unsupported slot candidate class')
    fields = SPECS[kind]['fields'] + (['Parent', 'Content'] if kind != 'PanelSlot' else [])
    reader, values, explicit = canvas.Reader(raw), {}, []
    for index, zero in reader.header():
        if index >= len(fields):
            raise ValueError('Unknown property index')
        name = fields[index]
        if name in values:
            raise ValueError('Repeated property')
        if name in ('Size','Padding'):
            # Preserve omissions inside nested structs too; never supply Slate defaults.
            nested_fields = ['Value','SizeRule'] if name == 'Size' else ['Left','Top','Right','Bottom']
            nested = {}
            if not zero:
                if name=='Size' and not allow_size:
                    raise ValueError('Explicit Size struct schema unreviewed')
                for child_index, child_zero in reader.header():
                    if child_index >= len(nested_fields) or nested_fields[child_index] in nested:
                        raise ValueError('Unknown/repeated nested property')
                    key = nested_fields[child_index]
                    nested[key] = 0 if child_zero else reader.read('<B' if key=='SizeRule' else '<f')
                    if isinstance(nested[key],float) and not math.isfinite(nested[key]):
                        raise ValueError('Invalid nested float')
            values[name] = dict(serialized_zero=zero, explicit_properties=nested,
                omitted_properties=[] if zero else [f for f in nested_fields if f not in nested])
        else:
            values[name] = 0 if zero else reader.read('<B' if name.endswith('Alignment') else '<i')
        explicit.append(name)
        if name.endswith('Alignment') and values[name] not in range(4):
            raise ValueError('Unreviewed alignment')
    if reader.read('<I') != 0 or reader.pos != len(raw):
        raise ValueError('Unaccounted serialization suffix')
    if any(values.get(name, 0) <= 0 for name in ['Parent', 'Content']):
        raise ValueError('Missing local object link')
    return dict(explicit_properties=values, serialized_fields=explicit,
        omitted_properties=[f for f in fields if f not in values])


def size_schema(raw,image,fragment):
    descriptor=image.offset(0x148ff12b0-image.pe.base)
    if struct.unpack_from('<Q',raw,descriptor+56)[0]!=SIZE_GETTER:
        raise ValueError('ScrollBoxSlot Size struct getter changed')
    rows={row['address']:row for row in fragment['instructions']}
    if rows[0x143572e30]['rip_references']!=[0x14b102d08] or rows[0x143572e30]['mnemonic']!='lea':
        raise ValueError('SlateChildSize metadata reference changed')
    if rows[0x143572e3e]['direct_target']!=0x1417d2560:
        raise ValueError('SlateChildSize registration helper changed')
    at=image.offset(0x14b102d08-image.pe.base);block=raw[at:at+64]
    name_pointer,array_pointer=struct.unpack_from('<QQ',block,24)
    name=image.offset(name_pointer-image.pe.base)
    if raw[name:name+15]!=b'SlateChildSize\0' or array_pointer!=0x148fc7150:
        raise ValueError('SlateChildSize metadata/array association changed')
    schema=props.extract(raw,['Value','SizeRule'],[10,0],anchor_index=0)
    if image.pe.address(schema['array_offset'])!=array_pointer:
        raise ValueError('SlateChildSize descriptor array moved')
    return dict(getter=hex(SIZE_GETTER),descriptor_address='0x148ff12b0',
        metadata=dict(address='0x14b102d08',bytes=block.hex(),sha256=sha(block)),
        schema=schema,fragment=fragment,defaults_verified=False)


def schemas(request):
    if request['source_sha256'] != SHA or request['question'] != 'ui-nktileview-property-schema':
        raise ValueError('Unreviewed native request')
    available={int(f['address'],16) for f in request['functions']}
    selected={kind:s for kind,s in SPECS.items() if s['getter'] in available}
    roots = {s['getter'] for s in selected.values()} | {s['parent_getter'] for s in selected.values() if 'parent_getter' in s}
    if 'ScrollBoxSlot' in selected and SIZE_GETTER in available:roots.add(SIZE_GETTER)
    if not selected or not roots <= available:
        raise ValueError('Missing explicit getter root')
    raw = source.checked(Path(request['source']), SHA)
    image = native.Image(raw)
    ranges = set()
    for address in roots:
        r = image.containing(address)
        if r is None or image.pe.base + image.roots[r][0] != address:
            raise ValueError('Getter unwind boundary changed')
        ranges.add(image.roots[r])
    fragments = native.decode_ranges(image, ranges)
    result = {}
    for kind, spec in selected.items():
        descriptor = None
        if spec.get('direct_array'):
            rows=[]; array_offset=image.offset(spec['array']-image.pe.base)
            for i,(name,flag) in enumerate(zip(spec['fields'],spec['flags'])):
                pointer=struct.unpack_from('<Q',raw,array_offset+i*8)[0]; at=image.offset(pointer-image.pe.base)
                string_pointer=struct.unpack_from('<Q',raw,at)[0]; start=image.offset(string_pointer-image.pe.base)
                flags=struct.unpack_from('<I',raw,at+24)[0]
                if raw[start:start+len(name)+1] != name.encode()+b'\0' or flags&255 != flag:
                    raise ValueError('Explicit class property descriptor changed')
                rows.append(dict(index=i,name=name,descriptor_offset=at,gen_flags=flags,descriptor_prefix_hex=raw[at:at+32].hex()))
            descriptor=dict(array_offset=array_offset,properties=rows)
        elif spec['fields']:
            descriptor = props.extract(raw, spec['fields'], spec['flags'], anchor_index=0)
        if descriptor and image.pe.address(descriptor['array_offset']) != spec['array']:
            raise ValueError('Descriptor array moved')
        o = image.offset(spec['metadata'] - image.pe.base)
        block = raw[o:o+64]
        if struct.unpack_from('<Q', block, 0x28)[0] != spec['array']:
            raise ValueError('Metadata property array differs')
        pointer = struct.unpack_from('<Q', block)[0]
        thunk = None
        if 'thunk' in spec:
            at = spec['thunk']; pos = image.offset(at - image.pe.base)
            b = raw[pos:pos+5]
            if pointer != at or b[:1] != b'\xe9' or at+5+struct.unpack_from('<i', b, 1)[0] != spec['getter']:
                raise ValueError('PanelSlot getter thunk changed')
            thunk = dict(address=hex(at), bytes=b.hex(), target=hex(spec['getter']))
        elif pointer != spec['getter']:
            raise ValueError('Metadata class getter differs')
        fragment = next(f for f in fragments if f['instructions'][0]['address'] == spec['getter'])
        refs = {target for row in fragment['instructions'] for target in row['rip_references']}
        def literal(text):
            expected = text.encode('utf-16le') + b'\0\0'
            hits = []
            for target in refs:
                try:
                    at = image.offset(target-image.pe.base)
                    if raw[at:at+len(expected)] == expected:
                        hits.append(hex(target))
                except (ValueError, KeyError):
                    continue
            if len(hits) != 1:
                raise ValueError('Getter literal not uniquely referenced: ' + text)
            return hits[0]
        result[kind] = dict(descriptor=descriptor, metadata=dict(address=hex(spec['metadata']),
            sha256=sha(block), bytes=block.hex(), property_array=hex(spec['array']), getter=hex(spec['getter'])),
            thunk=thunk, class_literal=literal(kind), package_literal=literal('/Script/UMG'),
            fragment=fragment)
        if 'parent_getter' in spec:
            at=spec['parent_thunk'];pos=image.offset(at-image.pe.base);b=raw[pos:pos+5]
            if b[:1]!=b'\xe9' or at+5+struct.unpack_from('<i',b,1)[0]!=spec['parent_getter'] or at not in refs:
                raise ValueError('Container parent getter thunk differs')
            parent_fragment=next(f for f in fragments if f['instructions'][0]['address']==spec['parent_getter'])
            refs={target for row in parent_fragment['instructions'] for target in row['rip_references']}
            result[kind]['parent_candidate']=dict(thunk=hex(at),bytes=b.hex(),getter=hex(spec['parent_getter']),
                class_literal=literal(spec['parent_name']),fragment=parent_fragment)
    if SIZE_GETTER in roots:
        result['ScrollBoxSlot']['size_schema']=size_schema(raw,image,next(f for f in fragments if f['instructions'][0]['address']==SIZE_GETTER))
    return result


def run(root, request, audit_path):
    definitions = schemas(request)
    audit_raw = audit_path.read_bytes()
    audit = json.loads(audit_raw)
    if audit['kind'] != 'automated_ui_source_audit':
        raise ValueError('Wrong source audit kind')
    snapshot = Path(audit['snapshot']['path'])
    manifest = json.loads(source.checked(snapshot/'manifest.json', audit['snapshot']['manifest_sha256']))
    records, failures, cache = [], [], {}
    for record in audit['records']:
        for variant in record['variants']:
            candidates = [c for c in variant.get('unaccounted_slot_candidates', []) if c['type'] in definitions]
            if not candidates:
                continue
            identity = 'W-' + sha(record['path'].encode())[:12]
            relative = 'windows/'+identity+'.json'
            published = json.loads(source.checked(source.inventory.child(snapshot, relative), manifest['generated_files'][relative]))
            if record['task_id'] != 'UI-'+identity or record['name'] != published['name'] or record['path'] != published['path']:
                raise ValueError('Source audit identity differs from snapshot')
            original = next(v for v in published['variants'] if v['file'] == variant['file'])
            expected = dict(catalog_sha256=original['sha256'], asset_sha256=original['asset_sha256'], body_sha256=original['body_sha256'])
            if variant['source'] != expected:
                raise ValueError('Source audit hashes differ from snapshot')
            if variant['file'] not in cache:
                p = source.inventory.child(root/'ui-catalog', variant['file'])
                catalog = json.loads(source.checked(p, variant['source']['catalog_sha256']))
                file = catalog.get('source_file', catalog['file'])
                base = source.inventory.child(root/'ui-layout-study', Path(file).stem)
                asset = source.checked(base.with_suffix('.uasset'), variant['source']['asset_sha256'])
                body = source.checked(base.with_suffix('.uexp'), variant['source']['body_sha256'])
                cache[variant['file']] = (file, {e['index']:e for e in source.inspector.exports(asset,body)['exports']})
            file, exports = cache[variant['file']]
            for candidate in candidates:
                proof = dict(task_id=record['task_id'], resource_path=record['path'], catalog_file=variant['file'],
                    source_file=file, **variant['source'], export=candidate['index'], type=candidate['type'],
                    offset=candidate['offset'], size=candidate['size'], sha256=candidate['sha256'])
                try:
                    actual = exports[candidate['index']]
                    if any(actual[k] != candidate[k] for k in ['index','name','type','sha256','offset','size']):
                        raise ValueError('Candidate export differs from source bytes')
                    if SPECS[actual['type']].get('container'):
                        outer=exports[actual['outer']]
                        if outer['type']!='WidgetTree':
                            raise ValueError('NamedSlot outer is not WidgetTree')
                        records.append(dict(source=proof,decoded=None,raw_serialization_hex=actual['serialized_hex'],
                            outer={k:outer[k] for k in ['index','name','type','sha256']},candidate_role='container_class_candidate',
                            inherited_properties_decoded=False,geometry_verified=False,class_metadata_association_verified=True,
                            cooked_current_compatibility_verified=False,inherited_serialization_verified=False))
                        continue
                    value = decode(bytes.fromhex(actual['serialized_hex']), actual['type'],
                        allow_size='size_schema' in definitions.get('ScrollBoxSlot',{}))
                    fields = value['explicit_properties']; parent = exports[fields['Parent']]; content = exports[fields['Content']]
                    expected_parent={'UniformGridSlot':'UniformGridPanel','ScrollBoxSlot':'ScrollBox'}.get(actual['type'])
                    if expected_parent and parent['type']!=expected_parent:
                        raise ValueError('Unexpected layout slot parent class')
                    records.append(dict(source=proof, decoded=value, parent={k:parent[k] for k in ['index','name','type','sha256']},
                        content={k:content[k] for k in ['index','name','type','sha256']}, geometry_verified=False,
                        class_metadata_association_verified=True, cooked_current_compatibility_verified=False,
                        inherited_serialization_verified=False,
                        field_order_basis='native_own_properties' if actual['type']=='PanelSlot' else 'native_own_plus_observed_inherited_indices'))
                except (ValueError, KeyError) as error:
                    failures.append(dict(source=proof,error=str(error)))
    return dict(schema=1,kind='basic_slot_candidate_decode',native_source=dict(path=request['source'],sha256=SHA),
        source_audit=dict(path=str(audit_path),sha256=sha(audit_raw)),definitions=definitions,records=records,failures=failures,
        tools={p.name:sha(p.read_bytes()) for p in [Path(__file__),HERE/'extract-ui-properties.py',HERE/'decode-canvas-slots.py',HERE/'inspect-ui.py',HERE/'build-native-entry-code.py']},
        limits=['Static class metadata association; generic registration helper not executed.',
            'Historical cooked compatibility with current native schema is not established.',
            'UniformGridSlot/ScrollBoxSlot inherited Parent/Content indices are observed candidates, not a proven superclass contract.',
            'NamedSlot is classified as container candidate; inherited serialized fields remain opaque.',
            'Omitted values remain unknown; no defaults, runtime order, desired size or geometry applied.'])


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,default=Path('F:/PhoneExit Resources/Vampir'))
    p.add_argument('--request',type=Path,required=True)
    p.add_argument('--audit',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    if args.output.exists() or args.output.resolve().is_relative_to(HERE.parents[3]) or args.output.resolve().is_relative_to((args.root/'maps/ui-prototype').resolve()):
        p.error('Use a new external evidence path outside snapshots')
    raw=args.request.read_bytes(); result=run(args.root,json.loads(raw),args.audit)
    result['request_sha256']=sha(raw)
    with args.output.open('x',encoding='utf8') as f:json.dump(result,f,ensure_ascii=False,indent=2)
    print(json.dumps(dict(output=str(args.output),records=len(result['records']),failures=len(result['failures']))))
    return int(bool(result['failures']))


if __name__=='__main__':
    raise SystemExit(main())
