"""Finite current SightEnter descriptor -> callback -> constructed record contract."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
SHA='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
# Object offset, descriptor, resize, callback, constructor, vtable, reader, native stride.
ROWS=[
    (0x10,0x149924cd8,0x1456d1d30,0x1456c5e60,0x145783670,0x149921ca8,0x145788180,0x230,'PktCharacterOther'),
    (0x20,0x149924cf0,0x1456d1f30,0x1456c6400,0x14579a5a0,0x149921f40,0x14579e590,0x240,'PktNpcCreateData'),
    (0x30,0x149924d08,0x1456d1ef0,0x1456c62f0,0x14578fef0,0x1499223d8,0x145793a90,0x78,'PktGroundEffectData'),
    (0x40,0x149924d20,0x1456d1eb0,0x1456c6270,0x14578fe30,0x1499218e0,0x1457938b0,0xd0,'PktGadget'),
    (0x70,0x149924d38,0x1456d1ff0,0x1456c67a0,0x1457a3480,0x149922420,0x1457a83c0,0x90,'PktTetherEffectData')]
ANCHORS={
    0x1456c53da:'488d5610',0x1456c541f:'488d5620',0x1456c5464:'488d5630',
    0x1456c54a9:'488d5640',0x1456c54fe:'488d5670',
    0x1456c54b8:'488d5650',0x1456c54bf:'e8cc7c3eff',
    0x1456c5520:'ba20000000',0x1456c552c:'889680000000',
    0x1456c5ebd:'4869cb30020000',0x1456c645d:'488d0cdb',0x1456c6461:'48c1e106',
    0x1456c633e:'486bcb78',0x1456c62bb:'4869cbd0000000',
    0x1456c67ee:'488d0cdb',0x1456c67fb:'48c1e104'}


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def run():
    native=load('build-native-entry-code')
    raw=(native.ROOT/'client-code-snapshots'/SHA/'ProjectRED-Win64-Shipping.exe').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SHA:raise ValueError('SightEnter source differs')
    if native.capstone.__version__!='5.0.6':raise ValueError('Pinned Capstone required')
    image=native.Image(raw)
    def data(at,size):return raw[image.offset(at-image.pe.base):image.offset(at-image.pe.base)+size]
    def instructions(at):
        owner=image.containing(at)
        if owner is None or image.pe.base+image.roots[owner][0]!=at:raise ValueError('Explicit unwind root required')
        return native.decode_ranges(image,{image.roots[owner]})
    roots={0x1456c5390}|{at for row in ROWS for at in row[2:5]}
    fragments=[fragment for at in sorted(roots) for fragment in instructions(at)]
    all_rows={r['address']:r for f in fragments for r in f['instructions']}
    if any(all_rows.get(at,{}).get('bytes')!=value for at,value in ANCHORS.items()):raise ValueError('SightEnter anchor differs')
    outer=[r for f in instructions(0x1456c5390) for r in f['instructions']]
    if [r['rip_references'][0] for r in outer if r['mnemonic']=='lea' and r['rip_references']]!=[r[1] for r in ROWS]:
        raise ValueError('SightEnter descriptor order differs')
    checked=[]
    for offset,descriptor,resize,callback,constructor,table,reader,stride,name in ROWS:
        if struct.unpack('<3Q',data(descriptor,24))!=(0x141b0aa50,resize,callback):raise ValueError('SightEnter descriptor differs')
        callback_rows=[r for f in instructions(callback) for r in f['instructions']]
        if not any(r['direct_target']==constructor for r in callback_rows) or not any(r['direct_target']==0x144aad190 for r in callback_rows):
            raise ValueError('SightEnter callback dispatch differs')
        ctor=[r for f in instructions(constructor) for r in f['instructions']]
        first=next(i for i,r in enumerate(ctor) if r['rip_references'])
        stores=ctor[first+1:first+3] if constructor==0x14579a5a0 else ctor[first+1:first+2]
        if constructor==0x14579a5a0 and stores[0]['bytes']!='33ff':raise ValueError('SightEnter NPC constructor interleave differs')
        if ctor[first]['rip_references']!=[table] or stores[-1]['bytes']!='488901':raise ValueError('SightEnter constructed table differs')
        slots=struct.unpack('<6Q',data(table,48))
        if slots[4]!=reader:raise ValueError('SightEnter virtual reader differs')
        # Name getter explicitly loads the adjacent literal as its string argument.
        getter=slots[5];prefix=data(getter,16)
        if prefix[:12]!=bytes.fromhex('40534883ec20488bda488d15'):raise ValueError('SightEnter name getter shape differs')
        literal=getter+16+struct.unpack_from('<i',prefix,12)[0]
        if literal!=table+48 or data(literal,len(name)+1)!=name.encode()+b'\0':raise ValueError('SightEnter record name differs')
        checked.append(dict(offset=hex(offset),descriptor=hex(descriptor),resize=hex(resize),callback=hex(callback),
            constructor=hex(constructor),vtable=hex(table),reader=hex(reader),native_stride=stride,name=name))
    report=dict(source_sha256=SHA,tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        arrays=checked,anchors={hex(k):v for k,v in ANCHORS.items()},fragments=fragments,network_used=False,
        limits=['Static descriptor/constructor/vtable chain and native storage strides; no wire size from native stride.',
            'Record at packet+50, nested readers and handler semantics require separate proof. No live visibility claim.'])
    path=load('audit-client-release').save_snapshot(native.ROOT/'code-clues/sight-enter-11316',report)
    return path,checked


if __name__=='__main__':
    path,rows=run();print(json.dumps(dict(report=str(path),arrays=rows)))
