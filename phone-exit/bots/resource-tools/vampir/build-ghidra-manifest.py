"""Build source-bound Ghidra function seeds from PE unwind ranges, without execution."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('ghidra_native',HERE/'build-native-entry-code.py')
native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
ROOT=Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES','F:/PhoneExit Resources/Vampir'))
SUPPORTED_SOURCE_SHA256='c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8'
SEEDS=[
 ('Login_Prepare',0x1467a9700),('PktLogin_Constructor',0x1456d4c80),
 ('PktLogin_Write',0x1456e57c0),('PktLogin_Read',0x1456d9370),
 ('PktLoginResult_Read',0x1456d9600),('LoginResult_Handler',0x146765540),
 ('Version_Prepare',0x1467a9cd0),('PktVersion_Constructor',0x1456d53b0),
 ('PktVersion_Write',0x1456e5cf0),('PktVersionResult_Read',0x1456d9b10),
 ('VersionResult_Handler',0x146768360),('Result_Gate',0x1467a8e10),
 ('Game_SendWrapper',0x1467aaa10),('Transport_SendB',0x144aaccf0),
 ('Request_Handoff',0x144aa8020),('SDK_TokenAccessor',0x1456039c0),
 ('SDK_NetmarbleIdAccessor',0x145604b90),('Settings_GetNetmarbleId',0x144524940),
 ('Archive_WriteFString',0x144aa6a30),('BeginGameImpl',0x146425730),
 ('Transport_ConnectToServer',0x144aabcc0),('SDK_SignInResponse',0x1444cc1a0)]


def build():
    evidence_path=ROOT/'code-clues/login-packet-fields-replay.json'
    evidence=json.loads(evidence_path.read_text('utf-8'))
    source=Path(evidence['source']);raw=source.read_bytes();digest=hashlib.sha256(raw).hexdigest()
    if digest!=evidence['sha256']:raise ValueError('Client changed: refresh source evidence before Ghidra import')
    if digest!=SUPPORTED_SOURCE_SHA256:raise ValueError('Seed addresses belong to another build; verify and update mappings first')
    image=native.Image(raw);functions=[]
    for name,address in SEEDS:
        containing=image.containing(address)
        if containing is None:raise ValueError('Missing seed unwind range '+name)
        root=image.roots[containing]
        if root[0]+image.pe.base!=address:raise ValueError('Seed does not match unwind root '+name)
        ranges=[]
        for row in image.ranges:
            if image.roots[row]!=root:continue
            start,end,unwind=row;off=image.offset(start);data=raw[off:off+end-start]
            ranges.append(dict(start=hex(image.pe.base+start),end_exclusive=hex(image.pe.base+end),
                file_offset=off,sha256=hashlib.sha256(data).hexdigest(),unwind_rva=unwind))
        functions.append(dict(name=name,address=hex(address),ranges=ranges,name_origin='analyst_hint_from_shared_evidence'))
    return dict(schema_version=1,source=str(source),source_sha256=digest,image_base=hex(image.pe.base),
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        upstream_sha256=hashlib.sha256(evidence_path.read_bytes()).hexdigest(),functions=functions,
        limitations=['Analyst labels, not recovered original C++ symbols.',
            'Ranges from existing PE unwind evidence; chained fragments may contain switch data.',
            'Decompiler output is an analysis aid, not runtime/protocol/session verification.'])


if __name__=='__main__':
    result=build();out=ROOT/'ghidra/entry-manifest.json';out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(path=str(out),functions=len(result['functions']),sha256=hashlib.sha256(out.read_bytes()).hexdigest())))
