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
 ('Transport_ConnectToServer',0x144aabcc0),('SDK_SignInResponse',0x1444cc1a0),
 ('PktLoginResult_Constructor',0x1456d4da0),('PktLoginResult_Write',0x1456e5a20),
 ('Archive_ReadFString',0x144aa66f0),('PktPeriodServerDate_Constructor',0x145794c20),
 ('PktTimeBase_Read',0x1457f0a90),('PktPeriodServerDate_Read',0x1457986b0),
 ('UTF8_DecodedLength',0x141446940),('UTF8_DecodeWrapper',0x141440ba0),
 ('Archive_ReadStdString',0x144aa5ab0),('UTF8_DecodeCore',0x141436230),
 ('Login_PostState',0x1467259c0),('LoginContinuation_SingletonInit',0x14647f9f0),
 ('LoginContinuation_Virtual28',0x1464846c0),
 ('CharacterList_RequestA',0x145dbd4b0),('CharacterList_RequestB',0x145dbfe50),
 ('CharacterList_RequestCaller',0x146768540),('CharacterList_SelectionPredicate',0x145c85d90),
 ('SelectionService_SingletonInit',0x1455f9ee0),('SelectionService_DerivedInit',0x145dc6b20),
 ('SelectionService_Virtual40',0x145dbba60),('SelectionService_Virtual50',0x145dc05f0),
 ('SelectionService_BaseReset',0x14560a6f0),('SelectionService_SetState',0x14560a400),
 ('SelectionService_StateLabel',0x145dc3f30),('SelectionService_AuthGuard',0x145609b00),
 ('SelectionService_DeferredState',0x145600690),('SelectionState_Lookup',0x145c5d860),
 ('SelectionState_Registry',0x145c38ab0),('SelectionState_LoadRows',0x145c61030),
 ('SelectionState_LoadSource',0x145c60c10),('SelectionState_Register',0x145c6d670),
 ('SelectionState_Initialize',0x145c395b0),('SelectionState_RecordSource',0x145c6d350),
 ('SelectionState_RegistryUse',0x145c31110),('WorldRecord_ParseA',0x145c62130),
 ('WorldRecord_ParseB',0x145c65ef0),('WorldRecord_ParseC',0x145c6aab0),
 ('WorldRecord_FindOrAdd',0x145c5d390),('WorldRecord_Insert',0x145c5cca0),
 ('WorldRecord_Construct',0x145c5c780),('WorldRecord_Copy',0x145c5d5a0),
 ('SelectionLifecycle_Base08',0x14560e7d0),('SelectionLifecycle_Virtual10',0x145db6550),
 ('SelectionLifecycle_Virtual28',0x145dac030),('SelectionLifecycle_Virtual30',0x145dbdd20),
 ('SelectionLifecycle_Base80',0x14560dc10),('SelectionLifecycle_Base88',0x14560dd40),
 ('SelectionLifecycle_Base98',0x14560dcc0),('SelectionLifecycle_RequestEvent',0x14561af60),
 ('SelectionLifecycle_WorldEvent',0x14561b000),
 ('SelectionLifecycle_StateDispatch',0x145619e40),
 ('SelectionLifecycle_Virtual70',0x145dc2930),('SelectionLifecycle_Virtual38',0x145dbbb10),
 ('SelectionLifecycle_Virtual78',0x145dbcbe0),
 ('SelectionLifecycle_Complete',0x14561a8d0),('SelectionLifecycle_Base78',0x14560d7b0),
 ('SelectionLifecycle_DelegateComplete',0x145dc5ae0),
 ('SelectionLifecycle_Request90Caller',0x1468f1d70),
 ('PktCharacterListResult_Read',0x1456d8d80),
 ('PktCharacterListResult_Write',0x1456e51e0),
 ('CharacterListResult_Handler',0x14675dce0),
 ('PktCharacterSelect_Write',0x1456e53a0),
 ('PktCharacterSelectResult_Read',0x1456d8f80),
 ('CharacterSelectResult_Handler',0x14675e9a0),
 ('CharacterList_ArrayRead',0x1456da1a0),
 ('CharacterList_ArrayResize',0x1456e3ea0),
 ('SelectionOwner_Construct',0x1468e29a0),
 ('SelectionOwner_VirtualA00',0x1468f09a0),
 ('CharacterList_RecordConstruct',0x14577d3d0),
 ('CharacterList_RecordRead',0x145781c80),
 ('CharacterList_RecordWrite',0x145786650),
 ('Archive_ReadArray',0x144aa5c50),
 ('CharacterList_RecordNestedB0_Read',0x1457812a0),
 ('CharacterList_RecordNested110_Read',0x1456bf640),
 ('CharacterList_RecordNested68_Read',0x14578dfa0),
 ('CharacterList_AppearanceArrayRead',0x145737650),
 ('CharacterList_AppearanceArrayResize',0x1456b60e0),
 ('CharacterList_OptionalArrayRead',0x1456c3890),
 ('CharacterList_OptionalArrayResize',0x1456cf6b0),
 ('CharacterList_AppearanceItemRead',0x145771b40),
 ('CharacterList_OptionalInsert',0x1456b99b0),
 ('CharacterList_OptionalPairConstruct',0x1456b7b90),
 ('CharacterList_OptionalValueConstruct',0x14577dd50),
 ('CharacterList_OptionalValueRead',0x145782b30),
 ('CharacterState_SetRawF0',0x145c930d0),
 ('CharacterState_F0ActionCaller',0x145f434a0),
 ('CharacterSelect_StoredCaller',0x145d43290),
 ('PktCharacterSelectResult_Construct',0x1456d4a40),
 ('PktCharacterSelectResult_Write',0x1456e5410),
 ('CharacterSelect_ApplyPlayer',0x145d61e60),
 ('CharacterSelect_ServiceResult',0x145dbe660),
 ('CharacterSelect_PlayerConstruct',0x14577ce10),
 ('CharacterSelect_Block2B8Construct',0x145789c10),
 ('CharacterSelect_DirectionToAngles',0x1415055b0),
 ('CharacterSelect_Block290Read',0x1457f0c90),
 ('CharacterSelect_PlayerRead',0x145780eb0),
 ('CharacterSelect_Player90Read',0x1457817e0),
 ('CharacterSelect_Player98Read',0x1456d7ae0),
 ('CharacterSelect_Block2B8Read',0x14578ecd0),
 ('CharacterSelect_Block290ArrayRead',0x1457f1720),
 ('CharacterSelect_Block290ArrayResize',0x1456b6020),
 ('CharacterSelect_Player40Read',0x145798990),
 ('CharacterSelect_Player1A0Read',0x145818150),
 ('CharacterSelect_ReadVector',0x144aa6660),
 ('CharacterSelect_DirectionVector',0x141507880),
 ('Archive_ReadScalar20',0x144aa5b90),
 ('CharacterSelect_Array168Read',0x1456b0ca0),
 ('CharacterSelect_Array1C8Read',0x145731010),
 ('CharacterSelect_Array1F8Read',0x14577b860),
 ('CharacterSelect_Array250Read',0x1456e6280),
 ('CharacterSelect_Array158Item',0x145784180),
 ('CharacterSelect_Array178Item',0x145784210),
 ('CharacterSelect_Array178Resize',0x145784760),
 ('CharacterSelect_Array1D8Item',0x1456b3730),
 ('CharacterSelect_Array238Item',0x1456ef840),
 ('CharacterSelect_Array238Resize',0x1456fa260),
 ('CharacterSelect_Map98Item',0x1456da4b0),
 ('CharacterSelect_Map98Resize',0x1456e3f60),
 ('CharacterSelect_Block290ItemRead',0x1457f0c00),
 ('CharacterSelect_Array168Item',0x1456b3640),
 ('CharacterSelect_Array1C8Item',0x145738b70),
 ('CharacterSelect_Array1F8Item',0x145783f30),
 ('CharacterSelect_Array1F8Resize',0x1457846e0),
 ('CharacterSelect_Array250Item',0x1456f0170),
 ('CharacterSelect_Array158Read',0x14578bd80),
 ('CharacterSelect_Array178Read',0x1457f0170),
 ('CharacterSelect_Array178NestedRead',0x1457f0220),
 ('CharacterSelect_Array1D8Read',0x145780300),
 ('CharacterSelect_Map98FindValue',0x1456d37a0)]

# This source-bound callback has no PE unwind entry: two straight blocks and
# one internal conditional branch, ending at RET after an allocator tail jump.
# Its reviewed 28-byte range includes both paths; do not manufacture .pdata.
REVIEWED_LEAF_RANGES={0x1456fa260:28}


def build():
    evidence_path=ROOT/'code-clues/login-packet-fields-replay.json'
    evidence=json.loads(evidence_path.read_text('utf-8'))
    source=Path(evidence['source']);raw=source.read_bytes();digest=hashlib.sha256(raw).hexdigest()
    if digest!=evidence['sha256']:raise ValueError('Client changed: refresh source evidence before Ghidra import')
    if digest!=SUPPORTED_SOURCE_SHA256:raise ValueError('Seed addresses belong to another build; verify and update mappings first')
    image=native.Image(raw);functions=[]
    for name,address in SEEDS:
        containing=image.containing(address)
        if containing is None:
            length=REVIEWED_LEAF_RANGES.get(address)
            if length is None:raise ValueError('Missing seed unwind range '+name)
            off=image.offset(address-image.pe.base);data=raw[off:off+length]
            if len(data)!=length or data[-1]!=0xc3:raise ValueError('Reviewed leaf boundary changed '+name)
            functions.append(dict(name=name,address=hex(address),name_origin='analyst_hint_from_shared_evidence',
                ranges=[dict(start=hex(address),end_exclusive=hex(address+length),file_offset=off,
                    sha256=hashlib.sha256(data).hexdigest(),unwind_rva=None,range_origin='reviewed_bounded_leaf')]))
            continue
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
