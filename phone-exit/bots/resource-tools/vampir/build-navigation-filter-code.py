"""Pin class identities, area IDs, constructor cost writes and filter schemas."""
import hashlib,importlib.util,json,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
AREA_FIELDS=['AreaClass','TravelCostOverride','EnteringCostOverride','bIsExcluded','bOverrideTravelCost','bOverrideEnteringCost']
AREA_FLAGS=[17,10,10,12,12,12]
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    native=load('filter_code_native','build-native-entry-code.py');properties=load('filter_code_properties','extract-ui-properties.py')
    source=json.loads((root/'code-clues/native-enums.json').read_bytes());data=Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest()!=source['sha256']:raise ValueError('Changed EXE')
    image=native.Image(data)
    functions=[0x1454c54e0,0x1454d0020,0x145297f60,0x14526edf0,0x1454e0230,
        0x1454c6ef0,0x1454c7090,0x1454c7240,0x145267900,0x145268f90,
        0x1454cd3b0,0x1454cd3f0,0x1454cd430,0x14526ef70,0x14526c030,0x14526c170,0x145268210,0x145267a60,0x1452681d0]
    fragments=native.decode_ranges(image,{image.roots[image.containing(a)] for a in functions})
    rows={r['address']:r for f in fragments for r in f['instructions']};anchors=[]
    for address,mnemonic,operands in [
        (0x1454c5547,'lea','rax, [rip + 0x7862]'),(0x1454c554e,'mov','qword ptr [r11 - 0x30], rax'),
        (0x1454d002c,'call','0x145297f60'),(0x1454d009d,'mov','qword ptr [rdi + 0x780], rbx'),
        (0x1454d00e0,'mov','qword ptr [rdi + 0x788], rbx'),(0x1454d0123,'mov','qword ptr [rdi + 0x790], rbx'),
        (0x1454d0149,'call','0x145268f90'),(0x1454d016c,'mov','r8d, 0xa'),(0x1454d017f,'call','0x14526edf0'),
        (0x1454d01f6,'call','0x1454c7090'),(0x1454d0219,'mov','r8d, 0xb'),(0x1454d022c,'call','0x14526edf0'),
        (0x1454d02a3,'call','0x1454c7240'),(0x1454d02c6,'mov','r8d, 0xc'),(0x1454d02d9,'call','0x14526edf0'),
        (0x1454d0350,'call','0x1454c6ef0'),(0x1454d0370,'mov','r8d, 0xd'),(0x1454d0380,'call','0x14526edf0'),
        (0x14526ee07,'mov','dword ptr [rcx + 0x10], r8d'),(0x14526ee4c,'mov','qword ptr [rbx + 0x18], rcx'),
        (0x145298394,'call','0x145267900'),(0x1452983b7,'mov','r8d, 0x3f'),(0x1452983ca,'call','0x14526edf0'),
        (0x1454e0240,'call','0x145268f90'),(0x1454e024a,'mov','eax, 0xa'),
        (0x1454e025a,'call','0x1454c7090'),(0x1454e0264,'mov','eax, 0xb'),
        (0x14526ef96,'mov','qword ptr [rbx + 0x30], 0x3f800000'),
        (0x14526c061,'mov','qword ptr [rbx + 0x30], 0x3f800000'),
        (0x14526c1ba,'mov','qword ptr [rbx + 0x30], 0x49742400'),
        (0x1454cd3c4,'call','0x14526ef70'),(0x1454cd3e2,'mov','dword ptr [rbx + 0x30], 0x49f42400'),
        (0x1454cd404,'call','0x14526ef70'),(0x1454cd422,'mov','dword ptr [rbx + 0x30], 0x3f800000'),
        (0x1454cd444,'call','0x14526ef70'),(0x1454cd462,'mov','dword ptr [rbx + 0x30], 0x3f000000'),
        (0x1452681e0,'lea','rdx, [rip + 0x44b7b79]'),(0x1452681ee,'call','0x1417cbfb0')]:
        row=rows[address]
        if (row['mnemonic'],row['operands'])!=(mnemonic,operands):raise ValueError('Changed filter source anchor '+hex(address))
        anchors.append(row)
    literals=[]
    for address,text in [(0x1454c5526,'NnRecastNavMesh'),(0x145267a9f,'NavigationQueryFilter'),(0x145268fd6,'NavArea_Obstacle'),
        (0x145267946,'NavArea_Default'),(0x1454c6f36,'NnNavArea_Forbidden'),
        (0x1454c70d6,'NnNavArea_HiddenPath'),(0x1454c7286,'NnNavArea_MainRoad'),
        (0x1454d006e,'/Game/RED/Blueprint/Navigation/BP_NavQuery_Default.BP_NavQuery_Default_C'),
        (0x1454d00b1,'/Game/RED/Blueprint/Navigation/BP_NavQuery_ShortPath.BP_NavQuery_ShortPath_C'),
        (0x1454d00f4,'/Game/RED/Blueprint/Navigation/BP_NavQuery_ExcludeHiddenPath.BP_NavQuery_ExcludeHiddenPath_C')]:
        row=rows[address];offset=image.offset(row['rip_references'][0]-image.pe.base);raw=text.encode('utf-16le')+b'\0\0'
        if data[offset:offset+len(raw)]!=raw:raise ValueError('Changed filter class/resource literal')
        anchors.append(row);literals.append(dict(instruction=address,text=text,file_offset=offset,raw_hex=raw.hex()))
    wrapper=0x1454ccdb0;wo=image.offset(wrapper-image.pe.base);expected='488b014885c0740b488bd1488bc8e95d320000c3'
    if data[wo:wo+20].hex()!=expected:raise ValueError('Changed NnRecastNavMesh constructor wrapper')
    schemas={}
    for key,fields,flags,anchor in [('area',AREA_FIELDS,AREA_FLAGS,1),
        ('filter',['Areas','Areas','IncludeFlags','ExcludeFlags'],[25,22,25,25],1),
        ('area_costs',['DefaultCost','FixedAreaEnteringCost'],[10,10],0)]:
        schema=properties.extract(data,fields,flags,anchor_index=anchor)
        for row in schema['properties']:
            offset=row['descriptor_offset'];row['raw64_hex']=data[offset:offset+64].hex()
        schemas[key]=schema
    # The nested array struct explicitly points to the reflected area struct getter.
    inner=schemas['filter']['properties'][0];inner_offset=inner['descriptor_offset']
    if struct.unpack_from('<Q',data,inner_offset+56)[0]!=0x145268210:raise ValueError('Changed filter array inner struct')
    registry=rows[0x145268220]['rip_references'][0];ro=image.offset(registry-image.pe.base);registry_raw=data[ro:ro+56]
    if struct.unpack_from('<Q',registry_raw,32)[0]!=image.pe.address(schemas['area']['array_offset']):raise ValueError('Changed filter area property registry')
    name_offset=image.offset(struct.unpack_from('<Q',registry_raw,24)[0]-image.pe.base)
    struct_name=b'NavigationFilterArea\0'
    if data[name_offset:name_offset+len(struct_name)]!=struct_name:raise ValueError('Changed filter area struct identity')
    class_params=rows[0x1452681e0]['rip_references'][0];cp=image.offset(class_params-image.pe.base);class_raw=data[cp:cp+56]
    if struct.unpack_from('<Q',class_raw)[0]!=0x145267a60 or struct.unpack_from('<Q',class_raw,40)[0]!=image.pe.address(schemas['filter']['array_offset']):raise ValueError('Changed NavigationQueryFilter class property array')
    cost_offsets={}
    for row in schemas['area_costs']['properties']:cost_offsets[row['name']]=struct.unpack_from('<I',data,row['descriptor_offset']+50)[0]
    if cost_offsets!={'DefaultCost':48,'FixedAreaEnteringCost':52}:raise ValueError('Changed native area cost layout')
    area_ids={10:'NavArea_Obstacle',11:'NnNavArea_HiddenPath',12:'NnNavArea_MainRoad',13:'NnNavArea_Forbidden',63:'NavArea_Default'}
    defaults={'NavArea_Obstacle':1000000.,'NnNavArea_HiddenPath':1.,'NnNavArea_MainRoad':.5,'NnNavArea_Forbidden':2000000.,'NavArea_Default':1.}
    report=dict(source=source['source'],sha256=source['sha256'],anchors=anchors,fragments=fragments,literals=literals,schemas=schemas,
        constructor_wrapper=dict(address=wrapper,file_offset=wo,raw_hex=expected,target=0x1454d0020),
        area_struct_registry=dict(address=registry,file_offset=ro,raw_hex=registry_raw.hex(),name_file_offset=name_offset),
        filter_class_params=dict(address=class_params,file_offset=cp,raw_hex=class_raw.hex(),class_getter=0x145267a60),
        cost_field_offsets=cost_offsets,native_area_ids=area_ids,
        constructor_cost_writes={name:dict(DefaultCost=value,FixedAreaEnteringCost=0.,runtime_value_verified=False) for name,value in defaults.items()},
        filter_class_fields=dict(Default=0x780,ShortPath=0x788,ExcludeHiddenPath=0x790),
        limitations=['Area IDs describe constructor/default registration and two explicit lookup branches, not live remapping or activation.',
            'Constructor writes precede CDO/Blueprint/instance/runtime overrides. Do not substitute omitted serialized values.',
            'Filter class fields at 0x780/0x788/0x790 are not yet linked to the active shared filter object at owner+0x400.'])
    path=root/'code-clues/navigation-filter-code.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(anchors=len(anchors),fragments=len(fragments),area_ids=area_ids,sha256=hashlib.sha256(path.read_bytes()).hexdigest())));return report

if __name__=='__main__':main()
