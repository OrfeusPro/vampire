"""Whole ID206 nonempty arrays with actual item readers and bounded storage."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('world_collections_base',HERE/'replay-world-move-finish-reader.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
native,x=base.native,base.x


def e8_bytes(value):
    enum,raw_c,raw10,raw18,present,vx,vy,vz,heading=value
    return struct.pack('<BIQQB',enum,raw_c,raw10,raw18,present)+(struct.pack('<fffB',vx,vy,vz,heading) if present else b'')


def body_bytes(arrays,text=''):
    regular={k:v for k,v in arrays.items() if k!='e8'}
    data=base.body_bytes(text=text,arrays=regular,heading=45,raw_type=255,enum70=255,enum118=255)
    # Locate the e8 count after the two variable preceding arrays and raw time.
    offset=65+len(text.encode('utf-8'))+7*len(arrays.get('appearance',()))
    offset+=sum(len(base.base.base.base.item_bytes(field,v)) for name,field in (('b8',0x1c8),('c8',0x1f8)) for v in arrays.get(name,()))
    values=arrays.get('e8',())
    return data[:offset]+struct.pack('<H',len(values))+b''.join(e8_bytes(v) for v in values)+data[offset+2:]


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        manifest=json.loads((native.ROOT/'ghidra/entry-manifest.json').read_text('utf-8'))
        names={'WorldFinishSupport_SpatialConstruct','CharacterSelect_Block290ArrayResize','Archive_ReadScalar20'}
        self.support_ranges=[r for f in manifest['functions'] if f['name'] in names for r in f['ranges']]
        if len(self.support_ranges)<3:raise ValueError('Missing world collection support')
        for r in self.support_ranges:
            lo,hi=int(r['start'],16),int(r['end_exclusive'],16)
            if hashlib.sha256(self.raw[r['file_offset']:r['file_offset']+hi-lo]).hexdigest()!=r['sha256']:
                raise ValueError('World support source changed')
            self.ranges.append((lo,hi))
            for page in range(lo & ~4095,(hi+4095)&~4095,4096):self.map_source_page(page)
        self.world_hooks.remove(0x1456b6020);self.world_hooks.remove(0x145784520)
        self.collection_allocators.update({0x14167f710:0x78,0x14167f160:0x78})
        self.collection_cleanup.add(0x145770460)
        for a in (0x14167f710,0x14167f160,0x145770460):self.map_source_page(a & ~4095)

    def read_collections_world(self,data):
        c=self.read_world(data);packet=self.scratch+0x1000
        layouts={'appearance':(0xa8,0x10,((8,4),(12,1),(14,2))),
            'b8':(0xb8,0x18,((8,4),(16,8))),
            'c8':(0xc8,0x70,base.base.base.base.LAYOUT[0x1f8][2]),
            'e8':(0xe8,0x78,((8,1),(12,4),(16,8),(24,8),(40,1),(56,8),(64,8),(72,8),(88,1))),
            '100':(0x100,4,((0,4),))}
        c['collections']={}
        for name,(offset,stride,fields) in layouts.items():
            p,n,cap=struct.unpack('<QII',bytes(self.uc.mem_read(packet+offset,16)))
            if not 0<=n<=cap<=8:raise ValueError('World array output bound')
            c['collections'][name]=[[int.from_bytes(self.uc.mem_read(p+i*stride+o,size),'little') for o,size in fields] for i in range(n)]
        return c


def build():
    em=Emulator();cases=[]
    values={'appearance':((0,0,0),(0xffffffff,255,65535)),
        'b8':((0,0),(0xffffffff,2**64-1)),
        'c8':((0,0,0,0,0,0,0,0,0,0,0,0.,0.,0.,0),
            (2**64-1,0xffffffff,0x80000000,65535,32768,1234,1,2,3,0xffffffff,255,1.5,-2.25,-0.,255)),
        'e8':((0,0,0,0,0,0.,0.,0.,0),(255,0xffffffff,2**64-1,0x8000000000000000,255,1.5,-2.25,-0.,45)),
        '100':(0,0xffffffff)}
    fixtures=[{name:(v*n)[:n]} for name,v in values.items() for n in (1,2,8)]
    fixtures.append(values)
    for arrays in fixtures:
        data=body_bytes(arrays,'Ж界🙂');c=em.read_collections_world(data)
        if c['returned']!=1 or c['consumed']!=len(data):raise ValueError('Nonempty world reader mismatch')
        c['input_arrays']={name:[list(row) if isinstance(row,tuple) else row for row in v] for name,v in arrays.items()};cases.append(c)
        for name in values:
            if len(c['collections'][name])!=len(arrays.get(name,())):raise ValueError('World collection count mismatch')
        for source,dest in zip(arrays.get('e8',()),c['collections']['e8']):
            expected=list(source[:4]);expected[0]=min(expected[0],5);expected.append(int(bool(source[4])))
            if dest[:5]!=expected:raise ValueError('World e8 scalar mismatch')
            if source[4]:
                expected=[int.from_bytes(struct.pack('<d',v),'little') for v in source[5:8]]
                if dest[5:8]!=expected or dest[8]!=45:raise ValueError('World e8 spatial mismatch')
    # Every prefix of a representative body containing all five arrays,
    # nested optional vectors and a multibyte string must fail safely.
    data=body_bytes(values,'Ж界🙂');short=[]
    for n in range(len(data)):
        c=em.read_world(data[:n])
        if c['returned'] or c['consumed']>n:raise ValueError('Short nonempty body accepted')
        short.append(dict(size=n,consumed=c['consumed'],returned=c['returned']))
    return dict(schema_version=1,source=em.bindings['source'],sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        dependency_sha256=hashlib.sha256((HERE/'replay-world-move-finish-reader.py').read_bytes()).hexdigest(),
        support_ranges=em.support_ranges,cases=cases,short=short,native_execution=True,network_ready=False,
        limitations=['Whole ID206 reader/item readers/constructors/native append execute. Arrays bounded to 8 elements with explicit storage allocator/cleanup fixtures.',
            'Fresh objects per case; no genuine allocation lifetime, engine object, socket or live session. No semantic coordinate claim.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/world-move-finish-collections-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']),short=len(report['short']))))
