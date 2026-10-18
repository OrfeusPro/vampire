"""Decode the native SplineActionParams struct; units and execution stay unresolved."""
import importlib.util,math
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('spline_reader',HERE/'decode-canvas-slots.py');canvas=importlib.util.module_from_spec(spec);spec.loader.exec_module(canvas)
FIELDS=['Duration','EasingFunc','BlendExp','MontageName','SocketName','FadeEnabled','FadeInTime','FadeOutTime','ParticleActorName','HideGameUI','CameraTargetYawEnabled','CameraTargetYaw','CameraTargetYawEasingFunc','CameraLagSpeedEnabled','CameraLagSpeed','CameraLagMaxDistance','CameraLagEasingFunc','FinishEffect','FinishEffectSocketName','FinishEffectLocationOffset','FinishEffectRotationOffset','FinishEffectScale']
FLAGS=[10,0,10,21,21,76,10,10,21,76,76,10,0,76,10,10,0,16,20,25,25,25]

def decode(reader,zero=False):
    start=reader.pos;result=dict(properties={},serialized_zero=zero,time_unit=None,runtime_effect_verified=False)
    if zero:return result
    for index,is_zero in reader.header():
        if not 0<=index<len(FIELDS):raise ValueError('Unknown SplineActionParams field')
        flag=FLAGS[index];value=None
        if flag==10:value=0. if is_zero else reader.read('<f')
        elif flag in [0,76]:
            value=0 if is_zero else reader.read('<B')
            if flag==76:
                if value not in [0,1]:raise ValueError('Invalid spline bool')
                value=bool(value)
        elif flag==21:
            if is_zero:value=''
            else:
                length=reader.read('<i')
                if not 0<=abs(length)<=65536:raise ValueError('Invalid spline string length')
                count=length if length>=0 else -length*2
                if reader.pos+count>len(reader.data):raise ValueError('Truncated spline string')
                raw=reader.data[reader.pos:reader.pos+count];reader.pos+=count
                if length==0:value=''
                elif length>0:
                    if raw[-1]!=0:raise ValueError('Unterminated spline string')
                    value=raw[:-1].decode('utf-8')
                else:
                    if raw[-2:]!=b'\0\0':raise ValueError('Unterminated wide spline string')
                    value=raw[:-2].decode('utf-16le')
        elif flag==16:value=0 if is_zero else reader.read('<i')
        elif flag==20:value=[0,0] if is_zero else reader.read('<ii')
        elif flag==25:value=[0.,0.,0.] if is_zero else reader.read('<ddd')
        if flag in [10,25]:
            if not all(math.isfinite(v) for v in (value if isinstance(value,list) else [value])):raise ValueError('Nonfinite spline parameter')
        result['properties'][FIELDS[index]]=value
    result['serialized_size']=reader.pos-start
    return result
