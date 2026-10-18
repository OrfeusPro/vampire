"""Verify ItemBox mode through loader, record lookup and reflected UI enum argument."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent


def main():
    spec=importlib.util.spec_from_file_location('box_native',HERE/'build-native-entry-code.py')
    n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
    source=json.loads((n.ROOT/'code-clues/native-enums.json').read_text('utf-8'))
    d=Path(source['source']).read_bytes()
    if hashlib.sha256(d).hexdigest()!=source['sha256'] or n.capstone.__version__!='5.0.6':
        raise ValueError('Changed client or decoder')
    im=n.Image(d)
    roots={im.roots[im.containing(a)] for a in [0x145a65f20,0x145a55db0,0x145a5e200,0x146370b50,0x1456b7090,0x14634f2d0]}
    fragments=n.decode_ranges(im,roots)
    rows={r['address']:r for f in fragments for r in f['instructions']}
    anchors=[];blobs=[]
    def check(a,m,o):
        r=rows[a]
        if (r['mnemonic'],r['operands'])!=(m,o):raise ValueError('Changed box mode anchor '+hex(a))
        anchors.append(r);return r
    def blob(a,expected,role):
        off=im.offset(a-im.pe.base)
        if d[off:off+len(expected)]!=expected:raise ValueError('Changed box mode data '+role)
        blobs.append(dict(address=a,file_offset=off,bytes=expected.hex(),role=role))
    def literal(a,name):
        r=rows[a];va=r['rip_references'][0]
        if r['mnemonic']!='lea':raise ValueError('Expected literal LEA')
        blob(va,name.encode()+b'\0',name);anchors.append(r)
    literal(0x145a65fe6,'ItemBox.csv')
    literal(0x145a6607b,'FRdItemBoxInfoManagerTemplate::Load')
    literal(0x145a660d6,'RewardGroupType')
    for a,m,o in [
        (0x145a660dd,'mov','qword ptr [rbp + 0x140], rax'),
        (0x145a663f5,'movzx','edx, word ptr [rbp + 0x194]'),
        (0x145a66400,'call','0x1445efb80'),(0x145a66405,'mov','byte ptr [rbx + 0x28], al'),
        (0x145a55dc1,'call','0x145a5e200'),(0x145a55df6,'mov','rdx, qword ptr [r9 + 0x18]'),
        (0x145a55e02,'imul','rcx, rax, 0x70'),(0x145a55e2c,'lea','rax, [rax + 8]'),
        (0x145a55e39,'mov','qword ptr [rbx + 8], rax'),
        (0x145a5e229,'lea','rax, [rip + 0x56f3a30]'),
        (0x146370c56,'call','0x145a55db0'),(0x146370c6f,'call','0x141482990'),
        (0x146370c74,'movzx','ecx, byte ptr [rax + 0x28]'),
        (0x146370c78,'mov','byte ptr [rsp + 0x30], cl'),
        (0x146370c94,'mov','rdx, qword ptr [rip + 0x5218d25]'),
        (0x146370c9e,'call','0x1417d0080'),(0x146370ca6,'lea','r8, [rsp + 0x30]'),
        (0x146370cb1,'call','qword ptr [r9 + 0x278]'),
        (0x14634f2e0,'lea','rdx, [rip + 0x38bf9d9]'),
        (0x14634f2ee,'call','0x1417cbfb0'),
        (0x1456b70a0,'lea','rdx, [rip + 0x5a937a9]'),
        (0x1456b70ae,'call','0x1417cc270')]:check(a,m,o)
    # ItemBox manager secondary vtable and its Load slot.
    blob(0x14b151c68,struct.pack('<Q',0x14997fc80),'ItemBox manager secondary vtable')
    blob(0x14997fcb8,struct.pack('<Q',0x145a65f20),'ItemBox Load virtual entry')
    blob(0x141482990,bytes.fromhex('488b4108c3'),'record handle returns pointer at +8')
    # Exact leaf initializer binds the FName used by ProcessEvent.
    blob(0x141275560,bytes.fromhex('41b801000000488d15838f9908488d0d4c44310ae907393300'),'OnItemBoxUpdated FName initializer')
    blob(0x149c0e4f0,'OnItemBoxUpdated'.encode('utf-16le')+b'\0\0','event FName literal')
    blob(0x14b15c480,struct.pack('<QQQQ',0x149c0e6b8,0,0,0x149c0e690),'event registration and parameter list')
    blob(0x149c0e6b8,b'OnItemBoxUpdated\0','event registration name')
    blob(0x149c0e690,struct.pack('<QQQ',0x149c0e5c0,0x149c0e610,0x149c0e650),'event parameter descriptors')
    blob(0x149c0e610,bytes.fromhex('28fe974901000000000000000000000080000000000010001e0000004500000000000000000000000000000000000000010000000000000090706b4501000000'),'RewardGroupType enum parameter at offset zero')
    blob(0x14b14a850,struct.pack('<QQQQQ',0x1456b0130,0,0x1498c9600,0x1498c9600,0x1498c94a0),'ERewardGroup registration and entries')
    blob(0x1498c9600,b'ERewardGroup\0','enum name')
    expected=[('Fixed',0),('ClassFixed',1),('Random',2),('ClassRandom',3),('RandomEach',4),('Select',5),('ClassSelect',6),('Max',7)]
    for i,(name,value) in enumerate(expected):
        row=source['enums']['ERewardGroup'][i]
        if row['name']!='ERewardGroup::'+name or row['value']!=value or row['descriptor_offset']!=im.offset(0x1498c94a0-im.pe.base)+16*i:
            raise ValueError('Changed enum entry')
        blob(0x1498c94a0+16*i,struct.pack('<Qq',im.pe.address(row['name_offset']),value),'enum entry '+name)
    report=dict(source=source['source'],sha256=source['sha256'],field='ItemBox.RewardGroupType',enum='ERewardGroup',field_binding_verified=True,
        runtime_selection_verified=False,anchors=anchors,data_anchors=blobs,fragments=fragments,
        limitations=['UI argument type and source record field verified; runtime award selection and Rate formula remain unverified.'])
    path=n.ROOT/'code-clues/item-box-mode-binding.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(anchors=len(anchors),data_anchors=len(blobs),sha256=hashlib.sha256(path.read_bytes()).hexdigest())))


if __name__=='__main__':main()
