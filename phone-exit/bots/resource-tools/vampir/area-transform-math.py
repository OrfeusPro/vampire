"""Client AreaBox XY rotation model; geometry is not collision or navigation."""
import hashlib,json,math,re,struct
from pathlib import Path

def f32(value):return struct.unpack('<f',struct.pack('<f',value))[0]
DEGREES_TO_RADIANS=f32(math.pi/180)

def angle(yaw):
    result=f32(f32(float(yaw))*DEGREES_TO_RADIANS)
    if not math.isfinite(result):raise ValueError('Nonfinite AreaBox angle')
    return result

def vector(text):
    number=r'[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?'
    m=re.fullmatch(r'\s*x\s*=\s*('+number+r')\s*,\s*y\s*=\s*('+number+r')\s*',text)
    if not m:return None
    result=[float(v) for v in m.groups()]
    return result if all(math.isfinite(v) for v in result) else None

def vertices(low,high,yaw):
    if not all(math.isfinite(v) for v in low+high) or any(a>b for a,b in zip(low,high)):
        raise ValueError('Invalid AreaBox extents')
    theta=angle(yaw);c,s=math.cos(theta),math.sin(theta)
    center=[(a+b)*.5 for a,b in zip(low,high)]
    return [[center[0]+(x-center[0])*c-(y-center[1])*s,
             center[1]+(x-center[0])*s+(y-center[1])*c]
            for x,y in [low,[high[0],low[1]],high,[low[0],high[1]]]]

def contains(point,low,high,yaw):
    theta=angle(yaw);c,s=math.cos(theta),math.sin(theta)
    dx=point[0]-(low[0]+high[0])*.5;dy=point[1]-(low[1]+high[1])*.5
    return abs(dx*c+dy*s)<=(high[0]-low[0])*.5 and abs(-dx*s+dy*c)<=(high[1]-low[1])*.5

def validated_evidence(root,tables_sha256):
    path=root/'code-clues/area-box-transform.json'
    if not path.is_file():return None
    evidence=json.loads(path.read_text('utf-8'));summary=evidence['summary']
    if not summary['rotation_pivot_verified'] or not summary['rotation_direction_verified'] or not summary['point_samples']:
        raise ValueError('Incomplete AreaBox transform evidence')
    if evidence['model_sha256']!=hashlib.sha256(Path(__file__).read_bytes()).hexdigest() or evidence['tables_sha256']!=tables_sha256:
        raise ValueError('Changed AreaBox model or tables; rebuild transform evidence')
    data=Path(evidence['source']['source']).read_bytes()
    if hashlib.sha256(data).hexdigest()!=evidence['source']['sha256']:raise ValueError('Changed AreaBox transform EXE')
    for r in evidence['anchors']+evidence['constants']:
        b=bytes.fromhex(r['bytes']);off=r['file_offset']
        if data[off:off+len(b)]!=b:raise ValueError('Changed AreaBox transform anchor')
    for f in evidence['native_fragments']:
        off=f['file_offset'];size=f['end_rva']-f['begin_rva']
        if hashlib.sha256(data[off:off+size]).hexdigest()!=f['sha256']:raise ValueError('Changed AreaBox transform fragment')
    for p in evidence['emulation']['pages']:
        off=p['file_offset']
        if hashlib.sha256(data[off:off+4096]).hexdigest()!=p['sha256']:raise ValueError('Changed AreaBox emulation page')
    return dict(file='code-clues/area-box-transform.json',sha256=hashlib.sha256(path.read_bytes()).hexdigest(),summary=summary)
