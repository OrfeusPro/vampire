"""Decode explicit link IDs and local endpoints; missing values never become defaults."""
import importlib.util,math
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('link_reader',HERE/'decode-canvas-slots.py');canvas=importlib.util.module_from_spec(spec);spec.loader.exec_module(canvas)

def decode(data):
    reader=canvas.Reader(data);fields=reader.header();result=dict(properties={},field_indices=fields,unknown_fields=[],direction=None,enabled=None,world_coordinates_verified=False,walkable_edge_verified=False)
    for index,zero in fields:
        if index not in [1,2,6,7]:
            result['unknown_fields']=[f for f,z in fields if f>=index];break
        if index in [1,2]:
            name='CustomLinkId' if index==1 else 'AuxiliaryCustomLinkId'
            if zero:value='0'
            else:
                if reader.header()!=[(0,False)]:raise ValueError('Unsupported link ID struct')
                value=str(reader.read('<Q'))
        else:
            name='LinkRelativeStart' if index==6 else 'LinkRelativeEnd'
            value=[0.,0.,0.] if zero else reader.read('<ddd')
            if not all(math.isfinite(v) for v in value):raise ValueError('Nonfinite relative endpoint')
        result['properties'][name]=value
    result['decoded_prefix_bytes']=reader.pos
    result['unresolved_suffix_hex']=data[reader.pos:].hex()
    result['observed_zero_suffix_only']=not result['unknown_fields'] and data[reader.pos:]==b'\0'*8
    result['suffix_semantics_verified']=False
    return result
