"""Current ID301 registration and field -> model -> typed actor bindings."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
SHA='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
ANCHORS={
    0x1467b603c:'488d05dd006103',0x1467b6043:'488907',0x1467b605d:'e89ea2f0fe',
    0x1467b6067:'4c8bc7',0x1467b606a:'488bd0',0x1467b606d:'488bce',0x1467b6070:'e84b560100',
    0x14679e301:'4c8b6a20',0x14679e305:'48634228',0x14679e30e:'488d04c0',0x14679e312:'48c1e006',
    0x14679e3fa:'498bd5',0x14679e3fd:'488bce',0x14679e400:'e82b5f5dff',0x14679e4ac:'e86f02eefe',0x14679e8dc:'4981c540020000',
    0x14679e95f:'488b5a10',0x14679e966:'48634218',0x14679e96a:'4869c030020000',0x14679e9b1:'4c8d7b78',
    0x14679eb80:'498b4790',0x14679eb84:'48394108',0x14679ebd6:'488d4c2438',0x14679ebdb:'e870ffedfe',
    0x145d7460c:'488b4208',0x145d74610:'48894108',0x145d74657:'0f108588000000',0x145d7466a:'0f114720',
    0x145d7466e:'f20f108d98000000',0x145d74676:'f20f114f30',0x145d746af:'488d95c8000000',0x145d746b6:'488bcf',0x145d746b9:'e812720100',
    0x145d74758:'488d5520',0x145d7475c:'488d8f28010000',0x145d7476c:'e8efd56cfb',
    0x145d8b920:'448b4f08',0x145d8b924:'4181f986000000',0x145d8b948:'488b5710',0x145d8b94c:'4c8bc2',
    0x145d8b94f:'498bce',0x145d8b952:'418bd1',0x145d8b955:'e8965786ff',
    0x14567ebec:'488bd7',0x14567ebef:'488bc8',0x14567ebf2:'e8494be9ff',0x145513753:'e838d6fbff',
    0x1454d0dd6:'488d1565fc3d04',0x1454d0de5:'488d0d24323704',0x1454d0e2d:'e89eaa1dfc'}
ROOTS={0x14679c530,0x14679e2f0,0x14679e940,0x145d745f0,0x145d8b8d0,0x14567eb50,0x145513740,0x1454d0d90}


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def run():
    # Reuse the established NPC key/XYZ/Hp/MaxHp field proof and its bounded
    # registration-owner decode; do not export the huge owner again.
    supporting,_=load('inspect-world-registrations-11316').run()
    support_raw=supporting.read_bytes();support=json.loads(support_raw)
    native,scan=load('build-native-entry-code'),load('build-entry-window-code')
    raw=(native.ROOT/'client-code-snapshots'/SHA/'ProjectRED-Win64-Shipping.exe').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SHA or native.capstone.__version__!='5.0.6':raise ValueError('Sight binding source/runtime differs')
    image=native.Image(raw)
    def data(at,size):return raw[image.offset(at-image.pe.base):image.offset(at-image.pe.base)+size]
    roots={image.roots[image.containing(at)] for at in ROOTS}
    if len(roots)!=len(ROOTS) or any(image.pe.base+b not in ROOTS for b,_,_ in roots):raise ValueError('Sight binding explicit roots differ')
    fragments=native.decode_ranges(image,roots)
    rows={r['address']:r for f in support['fragments']+fragments for r in f['instructions']}
    if any(rows.get(at,{}).get('bytes')!=value for at,value in ANCHORS.items()):raise ValueError('Sight semantic anchor differs')
    if struct.unpack('<Q',data(0x149922490+0x20,8))[0]!=0x1456c5390 or struct.unpack('<Q',data(0x149922490+0x28,8))[0]!=0x1456cf150:
        raise ValueError('Sight packet reader/ID getter differs')
    if data(0x1456cf150,6)!=bytes.fromhex('b82d010000c3') or struct.unpack('<Q',data(0x149dc6120+0x10,8))[0]!=0x14679c530:
        raise ValueError('Sight ID301/handler binding differs')
    handler_rows=[r for f in fragments if f['root_begin_rva']==0x14679c530-image.pe.base for r in f['instructions']]
    for at in (0x14679e940,0x14679e2f0,0x14679e000):
        if not any(scan.checked_call(row,at) for row in handler_rows):raise ValueError('Sight handler branch differs')
    literals={0x149844010:'/Script/NnFramework',0x1498b0a42:'NnCharacterPC'}
    for at,text in literals.items():
        if data(at,len(text.encode('utf-16le'))+2)!=text.encode('utf-16le')+b'\0\0':raise ValueError('Sight PC class literal differs')
    report=dict(source_sha256=SHA,tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        supporting=dict(path=str(supporting),sha256=hashlib.sha256(support_raw).hexdigest()),
        packet_id=301,handler='0x14679c530',npc_initializer='0x145d74330',player_initializer='0x145d745f0',
        actor_class='NnCharacterPC',anchors={hex(at):value for at,value in ANCHORS.items()},fragments=fragments,
        literals={hex(at):text for at,text in literals.items()},network_used=False,
        limits=['Static current registration/arguments/field/class chain; no full handler/engine/listener execution.',
            'NpcCreateData reuses the existing key/XYZ/Hp/MaxHp initializer. PC fields key/label/XYZ and EStat3/4/5/9/10 are source-bound; positions/stats remain entry observations.'])
    return load('audit-client-release').save_snapshot(native.ROOT/'code-clues/sight-bindings-11316',report)


if __name__=='__main__':print(json.dumps(dict(report=str(run()))))
