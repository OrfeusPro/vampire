"""Observed NavigationLink records with native fields; no runtime traversal inferred."""
import importlib.util,math
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('point_reader',HERE/'decode-canvas-slots.py');canvas=importlib.util.module_from_spec(spec);spec.loader.exec_module(canvas)
BASE_NAMES=['LeftProjectHeight','MaxFallDownLength','SnapRadius','SnapHeight','SupportedAgents']+['bSupportsAgent'+str(i) for i in range(16)]+['Direction','bUseSnapHeight','bSnapToCheapestArea']+['bCustomFlag'+str(i) for i in range(8)]+['AreaClass']
FIELDS=['Left','Right']+BASE_NAMES
FLAGS=[25,25]+[10]*4+[25]+[12]*16+[0,12,12]+[12]*8+[17]

def decode(reader,zero=False):
    start=reader.pos;values={};fields=[] if zero else reader.header()
    for index,is_zero in fields:
        if not 0<=index<len(FIELDS):raise ValueError('Unknown NavigationLink property')
        flag=FLAGS[index]
        if index in [0,1]:value=[0.,0.,0.] if is_zero else reader.read('<ddd')
        elif index==6:
            # Observed native selector storage retained uninterpreted; no agent eligibility calculated.
            value=dict(raw_u32=0 if is_zero else reader.read('<I'),interpretation_verified=False)
        elif flag==10:value=0. if is_zero else reader.read('<f')
        elif flag in [0,12]:
            value=0 if is_zero else reader.read('<B')
            if flag==12:
                if value not in [0,1]:raise ValueError('Invalid link bool')
                value=bool(value)
        elif flag==17:value=0 if is_zero else reader.read('<i')
        else:raise ValueError('Unsupported NavigationLink property')
        if isinstance(value,list) and not all(math.isfinite(v) for v in value):raise ValueError('Nonfinite link vector')
        if flag==10 and not math.isfinite(value):raise ValueError('Nonfinite link parameter')
        values[FIELDS[index]]=value
    return dict(properties=values,field_indices=fields,serialized_zero=zero,serialized_size=reader.pos-start,world_coordinates_verified=False,walkable_edge_verified=False)

def array(reader,zero=False):
    count=0 if zero else reader.read('<i')
    if not 0<=count<=10000:raise ValueError('Invalid point link count')
    return [decode(reader) for _ in range(count)]
