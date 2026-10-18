"""Read explicit SceneComponent placements; do not infer root/default/world transforms."""
import importlib.util,math
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('scene_reader',HERE/'decode-canvas-slots.py');canvas=importlib.util.module_from_spec(spec);spec.loader.exec_module(canvas)

def decode(data):
    reader=canvas.Reader(data);fields=reader.header();result=dict(properties={},field_indices=fields,unknown_fields=[],world_transform_verified=False)
    names={5:'RelativeLocation',6:'RelativeRotation',7:'RelativeScale3D',10:'bAbsoluteLocation'}
    for index,zero in fields:
        if index not in names:
            result['unknown_fields']=[f for f,z in fields if f>=index];break
        if index==10:
            value=0 if zero else reader.read('<B')
            if value not in [0,1]:raise ValueError('Invalid SceneComponent bool')
            value=bool(value)
        else:
            value=[0.,0.,0.] if zero else reader.read('<ddd')
            if not all(math.isfinite(v) for v in value):raise ValueError('Nonfinite component transform')
        result['properties'][names[index]]=value
    result.update(decoded_prefix_bytes=reader.pos,unresolved_suffix_hex=data[reader.pos:].hex(),observed_zero_suffix_only=not result['unknown_fields'] and data[reader.pos:]==b'\0'*8,suffix_semantics_verified=False)
    return result
