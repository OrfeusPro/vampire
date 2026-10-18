"""Bind cooldown storage to the engine DeltaSeconds tick, with checked native bytes."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main():
    spec = importlib.util.spec_from_file_location('tick_native', HERE/'build-native-entry-code.py')
    native = importlib.util.module_from_spec(spec); spec.loader.exec_module(native)
    source = json.loads((native.ROOT/'code-clues/native-enums.json').read_text('utf-8'))
    data = Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != source['sha256'] or native.capstone.__version__ != '5.0.6':
        raise ValueError('Changed executable or decoder')
    image = native.Image(data)
    roots = {image.roots[image.containing(a)] for a in [0x143c28240, 0x1442b8f70,
        0x144280630, 0x14557fdb0, 0x145596ec0, 0x145595e60, 0x1455965c0]}
    fragments = native.decode_ranges(image, roots)
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    expected = [
        (0x143c2826b,'movaps','xmm6, xmm1'),
        (0x143c28745,'movaps','xmm3, xmm6'),
        (0x143c28748,'xor','ecx, ecx'),
        (0x143c2874e,'call','0x1442b8f70'),
        (0x1442b8f9d,'movaps','xmm6, xmm3'),
        (0x1442b8fa0,'call','0x144297c30'),
        (0x1442b903d,'movaps','xmm1, xmm6'),
        (0x1442b9040,'mov','rcx, rbx'),
        (0x1442b9043,'call','qword ptr [rax]'),
        (0x14557fdec,'add','rcx, 0x28'),
        (0x14557fdf0,'call','0x144280630'),
        (0x14557fe0f,'lea','rax, [rip + 0x432bda2]'),
        (0x14557fe16,'mov','qword ptr [rdi + 0x28], rax'),
        (0x144280645,'call','0x144297c30'),
        (0x14428064d,'mov','qword ptr [rsp + 0x60], rsi'),
        (0x144280689,'call','0x14427cbf0'),
        (0x145596eda,'movaps','xmm6, xmm1'),
        (0x145596ef7,'lea','rbx, [rsi + 8]'),
        (0x145597014,'cvtss2sd','xmm6, xmm6'),
        (0x145597035,'addsd','xmm0, qword ptr [rcx + rax + 0x18]'),
        (0x14559703b,'movsd','qword ptr [rcx + rax + 0x18], xmm0'),
        (0x14559704d,'movsd','xmm2, qword ptr [r8 + 0x10]'),
        (0x145597053,'comisd','xmm1, xmm2'),
        (0x145595e8e,'movaps','xmm6, xmm3'),
        (0x145595ec5,'movsd','qword ptr [rax + 8], xmm6'),
        (0x145595eca,'movsd','qword ptr [rax + 0x10], xmm1'),
        (0x145595fb4,'lea','rcx, [rsi + 0x30]'),
        (0x14559661c,'call','0x14568a410'),
        (0x14559662a,'cvtss2sd','xmm6, xmm0'),
        (0x145596634,'movaps','xmm3, xmm6'),
        (0x145596652,'call','0x145595e60'),
    ]
    anchors = []
    for a, mnemonic, operands in expected:
        row = rows[a]
        if (row['mnemonic'],row['operands']) != (mnemonic,operands):
            raise ValueError('Changed tick anchor '+hex(a)+': '+row['operands'])
        anchors.append(row)
    literals = []
    for a, text in [(0x143c2828e,r'E:\Work\UE5\Release-5.5\Engine\Source\Runtime\Engine\Private\GameEngine.cpp'),
                    (0x143c2833b,'UGameEngine::Tick.ViewportClosed')]:
        row = rows[a]; offset = image.offset(row['rip_references'][0]-image.pe.base)
        raw = (text+'\0').encode('ascii' if a == 0x143c2828e else 'utf-16le')
        if data[offset:offset+len(raw)] != raw:
            raise ValueError('Changed engine identity literal')
        anchors.append(row)
        literals.append(dict(text=text,file_offset=offset,bytes=raw.hex()))
    # No write to the incoming interval between save and dispatch.
    writes = [r for a,r in sorted(rows.items()) if 0x143c2826b < a < 0x143c2874e
              and r['operands'].split(',')[0] == 'xmm6'
              and r['mnemonic'] not in ['comiss','ucomiss']]
    if writes:
        raise ValueError('Engine interval changed before dispatch')
    address = 0x1498abbb8; offset = image.offset(address-image.pe.base)
    raw = struct.pack('<Q',0x145596ec0)
    if data[offset:offset+8] != raw:
        raise ValueError('Changed cooldown tick vtable')
    dependencies = []
    # Level report also audits the generated atlas manifest. Depending on its
    # whole hash here would create a report→manifest→report rebuild cycle.
    # The time report already contains both getters and base-field stores.
    for name in ['skill-time-code.json']:
        path = native.ROOT/'code-clues'/name; report = json.loads(path.read_text('utf-8'))
        if report['sha256'] != source['sha256']:
            raise ValueError('Different cooldown evidence source')
        for row in report['anchors']:
            o=row['file_offset']; b=bytes.fromhex(row['bytes'])
            if data[o:o+len(b)] != b:
                raise ValueError('Changed cooldown dependency anchor')
        dependencies.append(dict(file='code-clues/'+name,sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    result = dict(source=source['source'],sha256=source['sha256'],anchors=anchors,
        fragments=fragments,literals=literals,
        vtable_slots=[dict(address=address,file_offset=offset,bytes=raw.hex())],
        dependencies=dependencies,
        documentation=[
            dict(url='https://dev.epicgames.com/documentation/en-us/unreal-engine/API/Runtime/Engine/Engine/UGameEngine?application_version=5.5',
                 contract='Tick(float DeltaSeconds, bool bIdleMode)',retrieved='2026-10-17'),
            dict(url='https://dev.epicgames.com/documentation/en-us/unreal-engine/API/Runtime/Engine/FTickableGameObject/TickObjects?application_version=5.5',
                 contract='TickObjects(UWorld*, ELevelTick, bool, float DeltaSeconds)',retrieved='2026-10-17')],
        verified=dict(cooldown_counter_unit='seconds',table_fields=['MinCoolTime','MaxCoolTime'],
            table_unit='milliseconds',seconds_divisor=1000,static_client_path=True),
        relations=[
            'UGameEngine::Tick incoming DeltaSeconds → unchanged XMM6 → dispatcher fourth argument XMM3',
            'dispatcher → registered object vtable slot0 → XMM1 → cooldown tick 0x145596ec0',
            'manager+0x28 registered tick interface → tick map at interface+8 = manager+0x30',
            'cooldown calculation 0x14568a410 → setter0x145595e60 → map duration; tick adds DeltaSeconds to elapsed and compares',
            'Skill MinCoolTime/MaxCoolTime → level-aware getters → raw ×0.001 → duration measured against DeltaSeconds'],
        limitations=['Static client-code proof with Unreal Engine 5.5 API contract; no live server/Android validation.',
            'Seconds for the base min/max fields do not predict actual NPC cooldown with runtime modifiers.',
            'TotalTime, Effect.Duration/Period and Item.CoolTime have independent, still unverified units.'])
    path = native.ROOT/'code-clues/skill-tick-code.json'
    path.write_text(json.dumps(result,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(anchors=len(anchors),fragments=len(fragments),
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),verified=result['verified'])))


if __name__ == '__main__':
    main()
