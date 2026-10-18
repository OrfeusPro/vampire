"""Exercise the native portal matcher on synthetic gates and extracted tiles."""
import hashlib,importlib.util,json,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent


def triangle_tile(right=False,h0=0.,h2=0.,plane_shift=0.,side_override=None,width=1.):
    raw=bytearray(88);struct.pack_into('<H',raw,0,7)
    for offset,value in [(4,1),(6,3),(18,1),(22,1)]:struct.pack_into('<H',raw,offset,value)
    if right:
        verts=[(1+plane_shift,h0,0),(2+plane_shift,h0,0),(1+plane_shift,h2,width)]
        neis=[0,0,0x8004 if side_override is None else 0x8000|side_override]
    else:
        verts=[(0,0,0),(1,0,0),(1,0,width)];neis=[0,0x8000,0]
    raw+=struct.pack('<9d',*(v for p in verts for v in p))
    raw+=struct.pack('<I6H6HHBB',0,0,1,2,0,0,0,*neis,0,0,0,1,3,10)
    raw+=struct.pack('<HHBB',0,0,0,1)+bytes(2)
    raw+=bytes([0,1,2,0])+bytes(4)+bytes(8)
    return bytes(raw)


def main(root=Path('F:/PhoneExit Resources/Vampir')):
    spec=importlib.util.spec_from_file_location('portal_evidence_emu',HERE/'recast-portal-emulator.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    em=module.PortalEmulator(root);synthetics=[]
    cases=[('flat',{},True),('flat_below_doubled_gate',dict(h0=69,h2=69),True),
           ('flat_above_doubled_gate',dict(h0=71,h2=71),False),
           ('slope_touching',dict(h0=0,h2=100),True),
           ('slope_at_sample_limit',dict(h0=35,h2=100),True),
           ('slope_above_sample_limit',dict(h0=36,h2=100),False),
           ('crossing',dict(h0=-100,h2=100),True),
           ('plane_mismatch',dict(plane_shift=.02),False),
           ('wrong_target_side',dict(side_override=2),False),
           ('insufficient_overlap',dict(width=.005),False)]
    source=triangle_tile()
    for name,options,expected in cases:
        target=triangle_tile(right=True,**options);em.load_tiles(source,target)
        result=em.match(0,1,0,35)
        if bool(result)!=expected:raise ValueError('Unexpected synthetic native gate: '+name+' '+str(result))
        synthetics.append(dict(name=name,options=options,height_parameter=35,expected_connected=expected,result=result))
    if em.height_samples==0 or em.triangle_samples==0:raise ValueError('Detail height branch was not exercised')
    path=root/'maps/navigation-study/tile-buffer-hypothesis-97/index.json';raw=path.read_bytes();index=json.loads(raw)
    package=index['packages'][0];buffers=(path.parent/package['buffer_file']).read_bytes()
    if hashlib.sha256(buffers).hexdigest()!=package['buffer_sha256']:raise ValueError('Changed buffers')
    records=package['records'][:2];tiles=[buffers[t['buffer_offset']:t['buffer_offset']+t['actual_memory_size']] for t in records]
    em.load_tiles(*tiles);forward=em.match(0,4,0,35)
    if not any(r['polygon']==1 for r in forward):raise ValueError('Expected real seam not found')
    em.load_tiles(*tiles[::-1]);reverse=[]
    pc,nv=struct.unpack_from('<HH',tiles[1],4)
    for poly in range(pc):
        off=88+nv*24+poly*32
        for edge in range(tiles[1][off+30]):
            if struct.unpack_from('<H',tiles[1],off+16+edge*2)[0]==0x8004:
                result=em.match(poly,edge,4,35)
                reverse.append(dict(polygon=poly,edge=edge,result=result))
    if not any(r['polygon']==1 and any(x['polygon']==0 for x in r['result']) for r in reverse):raise ValueError('Real seam is not reciprocal')
    report=dict(source_buffer_report_sha256=hashlib.sha256(raw).hexdigest(),
                emulator_sha256=hashlib.sha256((HERE/'recast-portal-emulator.py').read_bytes()).hexdigest(),
                synthetics=synthetics,real_pair=dict(source_package=package['package'],buffer_file=package['buffer_file'],
                    buffer_sha256=package['buffer_sha256'],source_records=records,forward=forward,reverse=reverse),
                native=em.provenance(),limitations=['Height35 is an explicit input hypothesis, not a verified runtime parameter.',
                    'Synthetic cases and one extracted seam establish the harness; no complete graph or route claimed.'])
    output=root/'maps/navigation-study/portal-native-evidence.json';output.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(synthetics=len(synthetics),**em.provenance(),report_sha256=hashlib.sha256(output.read_bytes()).hexdigest())))
    return report


if __name__=='__main__':main()
