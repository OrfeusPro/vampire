"""Decode the observed Nocturne RefNav header; bounds are chunk extents, not walkable polygons."""
import importlib.util,math
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('nav_reader',HERE/'decode-canvas-slots.py');canvas=importlib.util.module_from_spec(spec);spec.loader.exec_module(canvas)

def decode(data):
    reader=canvas.Reader(data)
    if reader.header()!=[(1,False),(2,False),(3,False)]:raise ValueError('Unsupported RefNav header layout')
    maximum,declared,count=reader.read('<iii')
    if not 0<=count<=10000 or declared!=count or maximum<0:raise ValueError('Invalid chunk counts')
    chunks=[]
    for _ in range(count):
        start=reader.pos;row={}
        fields=reader.header()
        if [f for f,z in fields]!=[0,1,2]:raise ValueError('Unsupported chunk fields')
        for field,zero in fields:
            if field==0:row['chunk_ref']=0 if zero else reader.read('<i')
            elif field==1:
                if zero:raise ValueError('Missing chunk resource')
                size=reader.read('<i')
                if not 1<size<=4096 or reader.pos+size>len(data):raise ValueError('Invalid chunk path')
                raw=data[reader.pos:reader.pos+size];reader.pos+=size
                if raw[-1]!=0:raise ValueError('Unterminated chunk path')
                row['asset_file_path']=raw[:-1].decode('utf-8')
                if not row['asset_file_path'].startswith('/Game/__ExternalActors__/'):raise ValueError('Unexpected chunk resource')
            else:
                if zero:raise ValueError('Missing chunk bounds')
                values=reader.read('<ddddddB');low,high,valid=values[:3],values[3:6],values[6]
                if valid!=1 or not all(math.isfinite(v) for v in low+high) or any(a>b for a,b in zip(low,high)):raise ValueError('Invalid chunk bounds')
                row['bounds']=dict(minimum=low,maximum=high,is_valid=True)
        row.update(body_offset=start,serialized_size=reader.pos-start,walkable_polygon=False)
        chunks.append(row)
    if len({r['chunk_ref'] for r in chunks})!=count:raise ValueError('Duplicate chunk reference')
    if reader.read('<I')!=0 or reader.pos!=len(data):raise ValueError('Unaccounted header bytes')
    return dict(num_max_tiles=maximum,num_chunks=declared,chunks=chunks,schema_basis='native field descriptors + observed unversioned layout + complete export byte consumption',walkability_verified=False)
