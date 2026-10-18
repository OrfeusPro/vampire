"""Verify Item.EffectType parser vocabulary without inferring EffectParams targets."""
import hashlib,importlib.util,json
from pathlib import Path
HERE=Path(__file__).resolve().parent

def main():
    spec=importlib.util.spec_from_file_location('native',HERE/'build-native-entry-code.py');n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
    source=json.loads((n.ROOT/'code-clues/native-enums.json').read_text('utf-8'));data=Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest()!=source['sha256']:raise ValueError('Changed EXE')
    im=n.Image(data);roots={im.roots[im.containing(a)] for a in [0x1457b2ce0,0x145aa2a55]};fragments=n.decode_ranges(im,roots)
    rows={r['address']:r for f in fragments for r in f['instructions']};anchors=[];types={}
    pairs=[(11,'BenefitEffect',0x1457b2de8,0x1457b2dfc),(1,'Effect',0x1457b2e08,0x1457b2e28),(18,'FollowerDrainCountRecovery',0x1457b2e34,0x1457b2e54),(17,'FollowerExpGain',0x1457b2e60,0x1457b2e80),(19,'FollowerPotion',0x1457b2e8c,0x1457b2eac),(14,'GachaDirectSummmon',0x1457b2eb8,0x1457b2ed8),(6,'GachaSummon',0x1457b2ee4,0x1457b2f04),(3,'Gadget',0x1457b2f10,0x1457b2f30),(13,'HiddenGrowth',0x1457b2f3c,0x1457b2f5c),(2,'ItemBox',0x1457b2f68,0x1457b2f88),(0,'None',0x1457b2f94,0x1457b2fb4),(12,'PaidAttendanceOpen',0x1457b2fc0,0x1457b2fe0),(10,'PaidSeasonPassOpen',0x1457b2fec,0x1457b300c),(16,'QuestStart',0x1457b3018,0x1457b3038),(9,'Recovery',0x1457b3044,0x1457b3064),(7,'SeasonPassPoint',0x1457b3070,0x1457b3090),(4,'SkillAcquire',0x1457b309c,0x1457b30be),(15,'TombDiggerReduceTime',0x1457b30ca,0x1457b30ec),(8,'UnlockCharacterSlot',0x1457b30f8,0x1457b311a)]
    for value,name,lea,store in pairs:
        row=rows[lea];offset=im.offset(row['rip_references'][0]-im.pe.base);raw=name.encode()+b'\0'
        if row['mnemonic']!='lea' or data[offset:offset+len(raw)]!=raw:raise ValueError('Changed effect name '+name)
        stored=rows[store]
        if stored['mnemonic']!='mov' or not stored['operands'].startswith('byte ptr [rsp + ') or int(stored['operands'].split(', ')[-1],0)!=value:raise ValueError('Changed effect value '+name)
        anchors.extend([row,stored]);types[str(value)]=dict(value=value,name=name,name_offset=offset,parser_name_verified=True,param_relation_verified=False,runtime_verified=False)
    for address,mnemonic,operands in [(0x145aa2a9b,'call','0x1457f9860'),(0x145aa2aa0,'mov','byte ptr [rbx + 0x68], al'),(0x1457b3156,'call','0x14450dc60'),(0x1457b2d8c,'mov','al, 0x14')]:
        row=rows[address]
        if (row['mnemonic'],row['operands'])!=(mnemonic,operands):raise ValueError('Changed effect anchor')
        anchors.append(row)
    address=0x1457f9860;offset=im.offset(address-im.pe.base);raw=data[offset:offset+5]
    if raw[0]!=0xe9 or address+5+int.from_bytes(raw[1:],'little',signed=True)!=0x1457b2ce0:raise ValueError('Changed parser thunk')
    anchors.append(dict(address=address,file_offset=offset,bytes=raw.hex(),mnemonic='jmp',operands='0x1457b2ce0'))
    report=dict(source=source['source'],sha256=source['sha256'],types=types,unknown_value=20,anchors=anchors,fragments=fragments,limitations=['Names and byte values from Item.EffectType parser; EffectParams targets, runtime activation, formulas and durations are not established.','20 is parser fallback, not proof of None or unrestricted behavior.'])
    path=n.ROOT/'code-clues/item-effect-semantics.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8');print(json.dumps(dict(types=len(types),anchors=len(anchors),sha256=hashlib.sha256(path.read_bytes()).hexdigest())))
    return report
if __name__=='__main__':main()
