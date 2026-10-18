"""Verify the client monster reward UI's NpcSpawn.AreaInfoId selection branch.

Static client code only: this is not a verified server roll or percentage formula.
"""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main():
    spec = importlib.util.spec_from_file_location('drop_native', HERE/'build-native-entry-code.py')
    native = importlib.util.module_from_spec(spec); spec.loader.exec_module(native)
    source = json.loads((native.ROOT/'code-clues/native-enums.json').read_text('utf-8'))
    data = Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != source['sha256']:
        raise ValueError('Changed executable')
    if native.capstone.__version__ != '5.0.6':
        raise ValueError('Use pinned Capstone 5.0.6')
    image = native.Image(data)
    addresses = [0x145ad95c0,0x145ae1080,0x145ae18a0,0x145afb8b0,
        0x145ad8b10,0x145ad7dd0,0x145ad68b0,0x1460b31f0,
        0x1460bfc60,0x1460c3990,0x1464cbd10,0x145c30470,0x145c39430]
    roots = {image.roots[image.containing(address)] for address in addresses}
    fragments = native.decode_ranges(image,roots)
    rows = {r['address']:r for f in fragments for r in f['instructions']}
    anchors = [
        (0x145ae18a9,'lea','NpcSpawnInfo'),
        (0x145ae10a9,'lea','rax, [rip + 0x5672b20]'),
        (0x145ad6916,'lea','rax, [rip + 0x3ebdb0b]'),
        (0x145afba95,'lea','NpcInfoId'),(0x145afbab0,'mov','dword ptr [rdi + 0x20], eax'),
        (0x145afc4d4,'lea','AreaInfoId'),(0x145afc4f2,'mov','dword ptr [rdi + 0xf0], eax'),
        (0x145ad95d1,'call','0x145ae1080'),(0x145ad95db,'call','0x1459dc780'),
        (0x1460b3252,'call','0x145ad95c0'),
        (0x1460b3276,'call','qword ptr [rdx + 0x38]'),
        (0x1460b327e,'mov','dword ptr [rbx + 0xe78], eax'),
        (0x1460b3289,'mov','ecx, dword ptr [rax + 0xf0]'),
        (0x1460b328f,'mov','dword ptr [rbx + 0xe7c], ecx'),
        (0x1460b341e,'mov','eax, dword ptr [rip + 0x3566f5c]'),
        (0x1460b3441,'cmp','dword ptr [rbx + 0xe7c], eax'),
        (0x1460b3447,'je','0x1460b3457'),
        (0x1460b3449,'call','0x1460bfc60'),(0x1460b3457,'call','0x1460c3990'),
        (0x1460bfcac,'lea','rdx, [rbx + 0xe7c]'),(0x1460bfce2,'call','0x145b5a790'),
        (0x1460c39d0,'lea','rdx, [r13 + 0xe78]'),(0x1460c3a02,'call','0x145b5aee0'),
        (0x1464cbd3e,'call','0x145c30470'),
        (0x1464cbdf2,'mov','ecx, dword ptr [rax + 8]'),
        (0x1464cbdfd,'call','0x145b5a790'),
    ]
    checked = []
    for address,mnemonic,operand in anchors:
        row = rows[address]
        if row['mnemonic'] != mnemonic:
            raise ValueError('Changed anchor mnemonic')
        if mnemonic == 'lea' and operand in ['AreaInfoId','NpcInfoId','NpcSpawnInfo']:
            if len(row['rip_references']) != 1:
                raise ValueError('Changed field reference')
            offset = image.offset(row['rip_references'][0]-image.pe.base)
            expected = operand.encode()+b'\0'
            if data[offset:offset+len(expected)] != expected:
                raise ValueError('Changed field name')
        elif row['operands'] != operand:
            raise ValueError('Changed anchor operands')
        checked.append(row)
    def pointer(address,expected):
        offset=image.offset(address-image.pe.base)
        if struct.unpack_from('<Q',data,offset)[0] != expected:
            raise ValueError('Changed vtable pointer')
        return dict(address=address,file_offset=offset,target=expected)
    pointers=[pointer(0x14b153bd0,0x149994680),pointer(0x149994680+0x80,0x145ae18a0),
        pointer(0x149994428+0x38,0x141977130)]
    leaves=[]
    for address,expected in [(0x141977130,'8b4120c3'),(0x141482990,'488b4108c3')]:
        offset=image.offset(address-image.pe.base);raw=bytes.fromhex(expected)
        if data[offset:offset+len(raw)] != raw:
            raise ValueError('Changed leaf getter')
        leaves.append(dict(address=address,file_offset=offset,bytes=expected))
    sentinel=rows[0x1460b341e]['rip_references'][0]
    if struct.unpack_from('<i',data,image.offset(sentinel-image.pe.base))[0] != 0:
        raise ValueError('Selection sentinel is not zero')
    result=dict(source=source['source'],sha256=source['sha256'],anchors=checked,
        fragments=fragments,pointers=pointers,leaf_getters=leaves,zero_sentinel_address=sentinel,
        rule='Client monster reward UI: nonzero NpcSpawn.AreaInfoId selects AreaReward.GroupId; zero selects NpcReward.GroupId using NpcSpawn.NpcInfoId.',
        client_ui_selection_verified=True,server_kill_application_verified=False,
        chance_percent_verified=False,limits=['The branch is for the client reward window, not a verified server roll.',
            'No addition of AreaReward and NpcReward is implied.',
            'Selection of the active spawn inside the window is not fully reconstructed.'])
    path=native.ROOT/'code-clues/drop-selection-code.json'
    path.write_text(json.dumps(result,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(output=str(path),anchors=len(checked),fragments=len(fragments))))


if __name__ == '__main__':
    main()
