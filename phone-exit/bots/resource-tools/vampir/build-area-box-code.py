"""Verify AreaBox storage and callbacks; rotation consumer remains unresolved."""
import hashlib,importlib.util,json
from pathlib import Path
HERE=Path(__file__).resolve().parent

def main():
    spec=importlib.util.spec_from_file_location('native',HERE/'build-native-entry-code.py');n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
    source=json.loads((n.ROOT/'code-clues/native-enums.json').read_text('utf-8'));data=Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest()!=source['sha256']:raise ValueError('Changed EXE')
    image=n.Image(data);fragments=n.decode_ranges(image,{image.roots[image.containing(a)] for a in [0x145c3dae0,0x145c54720,0x145c2ddf0]});rows={r['address']:r for f in fragments for r in f['instructions']};anchors=[]
    for a,m,o in [(0x145c3e121,'lea','rbx, [rsi + 0x10]'),(0x145c3e16c,'call','qword ptr [rax + 0x10]'),(0x145c3e26e,'lea','rbx, [rsi + 0x20]'),(0x145c3e2b9,'call','qword ptr [rax + 0x18]'),(0x145c3e2e6,'call','0x1445efa50'),(0x145c3e2f1,'movss','dword ptr [rsi + 0x30], xmm0'),(0x145c3e2f6,'call','qword ptr [rax + 0x20]'),(0x145c54857,'lea','rdi, [rbx + 0x10]'),(0x145c54923,'lea','rdi, [rbx + 0x20]'),(0x145c549b7,'call','0x1445eb030'),(0x145c549c2,'movss','dword ptr [rbx + 0x30], xmm0'),(0x145c2de36,'lea','rax, [rip + 0x3d34313]')]:
        r=rows[a]
        if (r['mnemonic'],r['operands'])!=(m,o):raise ValueError('Changed AreaBox anchor')
        anchors.append(r)
    for a,name in [(0x145c5480c,'AreaBoxMinPos'),(0x145c548d8,'AreaBoxMaxPos'),(0x145c549a4,'Yaw')]:
        r=rows[a];off=image.offset(r['rip_references'][0]-image.pe.base);raw=name.encode()+b'\0'
        if data[off:off+len(raw)]!=raw:raise ValueError('Changed field name')
        anchors.append(r)
    vt=0x149962150;off=image.offset(vt-image.pe.base)
    for slot in [0x10,0x18,0x20]:
        if int.from_bytes(data[off+slot:off+slot+8],'little')!=0x1413fe190:raise ValueError('Changed callback')
    ret=image.offset(0x13fe190)
    if data[ret:ret+3]!=b'\xc2\x00\x00':raise ValueError('Changed ret0')
    report=dict(source=source['source'],sha256=source['sha256'],anchors=anchors,fragments=fragments,vtable=dict(address=vt,file_offset=off,bytes=data[off:off+0x28].hex()),callback=dict(address=0x1413fe190,file_offset=ret,bytes=data[ret:ret+3].hex()),storage={'AreaBoxMinPos':'record+0x10 FString','AreaBoxMaxPos':'record+0x20 FString','Yaw':'record+0x30 float32'},rotation_pivot_verified=False,rotation_direction_verified=False,limitations=['Base record post-write callbacks for Min/Max/Yaw are ret0. No transform consumer identified here.','No center/origin pivot, angle direction, collision rule or walkable path inferred from field names.'])
    path=n.ROOT/'code-clues/area-box-code.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8');print(json.dumps(dict(anchors=len(anchors),sha256=hashlib.sha256(path.read_bytes()).hexdigest())))
if __name__=='__main__':main()
