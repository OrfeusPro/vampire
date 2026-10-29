"""Pure six-root Login metadata transfer; no SDK state, userdata or execution.

Source/export admission and bounded semantic replay belong to the caller.
Compiled strings and code layout are exact; all external primitive bodies remain fixtures.
"""
import copy
import hashlib
from importlib.util import spec_from_file_location, module_from_spec
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
FUNCTIONS=('collector','selector','loader','writer','copy','move')
METADATA={'schema','source','source_sha256','exports','family','layout','transfer_proof','release_id'}
FIELDS={'helpers','functions','fixtures','globals','collector_order','call_sites','verify_whole_exports'}
SYNTHETIC={'strong_destroy':0x2800e000,'weak_destroy':0x2800e010}
FIXTURES={'marketing','construct_info','destroy_info','backend','unwrap_backend','shared_info','settings','source_info',
    'memset','copy_string','wide_string','ascii_string','append','format','idfv','nm_key','adid','variant_text',
    'variant_number','variant_destroy','insert','hash','lookup','value_text','map_destroy','optional_store',
    'optional_resolve','device_key','security','free','diagnostic_text','diagnostic_log',*SYNTHETIC}
ORDER=('I_GameCode','I_GameVersion','I_TID','I_CountryCD','I_PID','I_ChannelType','I_SDKVersion','I_World',
    'I_PlatformADID','I_ConnectIP','I_UDID','I_JoinedCountryCode','I_DeviceOSVersion','I_DeviceModel','I_OS',
    'I_Region','I_TimeZone','I_LanguageCD','I_NMDeviceKey','I_NMIDFV','I_World','I_NMMarket','I_NMNID',
    'I_PCSeq','I_NMCPU','I_NMRAM','I_NMVGA')
FIELD_MAP={'I_OS':0,'I_DeviceOSVersion':0x10,'I_DeviceModel':0x20,'I_NMManufacturer':0x30,'I_NMModel':0x40,
    'I_UDID':0x60,'I_GameVersion':0x80,'I_SDKVersion':0x90,'I_GameCode':0xa0,'I_NMBuildCode':0xb0,
    'I_NMMarket':0xc0,'I_TID':0xd0,'I_ConnectIP':0xe0,'I_NMMobileIP':0xf0,'I_CountryCD':0x100,'I_City':0x110,
    'I_ChannelType':0x120,'I_NMChannelCode':0x130,'I_NMChannelUserID':0x140,'I_PID':0x150,'I_Region':0x160,
    'I_JoinedCountryCode':0x170,'I_LanguageCD':0x180,'I_World':0x190,'I_NMCharacterID':0x1a0,
    'I_NMSessionID':0x1b0,'I_TimeZone':0x1c0,'I_NMCPU':0x1f0,'I_NMRAM':0x200,'I_NMVGA':0x210,
    'I_NMResolution':0x220,'I_NMNID':0x230,'I_NMNIDChannelType':0x240}
WRITER_KEYS={397:'I_DeviceModel',566:'I_GameCode',686:'I_NMBuildCode',802:'I_PID',959:'I_CountryCD',1122:'I_LanguageCD',
    1281:'I_OS',1441:'I_DeviceOSVersion',1604:'I_TimeZone',1767:'I_SDKVersion',1930:'I_ChannelType',2093:'I_NMChannelCode',
    2256:'I_NMChannelUserID',2419:'I_ConnectIP',2582:'I_TID',2745:'I_GameVersion',2908:'I_Region',3068:'I_UDID',
    3227:'I_PlatformADID',3388:'I_NMAppSetID',3546:'I_NMAppSetIDScope',3707:'I_NMInstallPackageName',3870:'I_JoinedCountryCode',
    3987:'I_World',4104:'I_City',4230:'I_NMCharacterID',4347:'I_NMMarket',4464:'I_NMSessionID',4584:'I_NMIDFV',
    4701:'I_NMMobileIP',4815:'I_NMManufacturer',4929:'I_NMModel',5046:'I_NMCPU',5163:'I_NMRAM',5280:'I_NMVGA',
    5443:'I_NMResolution',5602:'I_NMDeviceKey',5771:'I_NMNID',5879:'I_NMNIDChannelType'}
GLOBAL_RIPS={'collector':{19:'cookie',1524:'optional_manager'},'selector':{},'loader':{},
    'writer':{45:'log_level',57:'log_enabled',118:'log_level'},'copy':{},'move':{}}


def wide(value):return (value+'\0').encode('utf-16le')


LITERALS={
    'collector':{240:wide('{'),**{255+47*n:wide(key) for n,key in enumerate(ORDER)},1531:wide(''),
        1627:wide(',"I_DeviceKey":"%s"'),1729:wide(',"I_LogDes":{'),1749:wide('"MktClickId":"%s",'),
        1826:wide('"MktChannel":%d'),1895:wide('}'),1916:wide('}')},
    'selector':{22:wide(''),149:wide(','),201:wide('"%s":"%s"')},'loader':{},
    'writer':{66:b'void __cdecl Netmarble::Service::FCommonLogData::ToMap(class TMap<class FString,struct FJsonLibraryValue,class FDefaultSetAllocator,struct TDefaultMapHashableKeyFuncs<class FString,struct FJsonLibraryValue,0> > &,bool)\0',
        94:wide(''),111:wide('%s'),264:wide(''),**{offset:(key+'\0').encode('ascii') for offset,key in WRITER_KEYS.items()}},
    'copy':{},'move':{}}
CALL_GROUPS={
    'collector':{'marketing':[163],'construct_info':[177],'root:loader':[190],'root:writer':[229],
        'append':[250,1679,1739,1801,1869,1905,1926],'wide_string':[267+47*n for n in range(27)]+[1617],
        'root:selector':[282+47*n for n in range(27)],'free':[297+47*n for n in range(27)]+[1694,1709,1816,1884,1977,2009,2040,2057],
        'optional_store':[1557],'optional_resolve':[1577],'device_key':[1602],'format':[1648,1770,1838],
        'destroy_info':[1946],'map_destroy':[2023],'security':[2075]},
    'selector':{'hash':[61],'lookup':[74],'append':[156,241],'value_text':[172],'format':[213],'free':[256,271]},
    'loader':{'backend':[21],'unwrap_backend':[56],'shared_info':[74],'settings':[89],'source_info':[97],'root:copy':[108],
        'qword ptr [rax]':[146,215],'qword ptr [rax + 8]':[166,235],'memset':[251],'construct_info':[261],
        'root:move':[272],'destroy_info':[282]},
    'writer':{'diagnostic_text':[78],'diagnostic_log':[132],
        'free':[147,192,237,305,355,376,475,647,749,877,1040,1203,1362,1522,1685,1848,2011,2174,2337,2500,2663,2826,2989,3149,3308,3469,3627,3788,3951,4068,4185,4311,4428,4545,4665,4782,4896,5010,5127,5244,5361,5524,5683,5847,5944,5969,5984,5998],
        'idfv':[156],'nm_key':[166],'adid':[252],'wide_string':[275],
        'variant_text':[392,561,681,797,954,1117,1276,1436,1599,1762,1925,2088,2251,2414,2577,2740,2903,3063,3222,3383,3702,3865,3982,4099,4225,4342,4459,4579,4696,4810,4924,5041,5158,5275,5438,5597,5766,5874],
        'ascii_string':[411,580,697,816,973,1136,1295,1455,1618,1781,1944,2107,2270,2433,2596,2759,2922,3082,3241,3402,3560,3721,3884,4001,4118,4244,4361,4478,4598,4715,4829,4943,5060,5177,5294,5457,5616,5785,5891],
        'insert':[458,630,735,860,1023,1186,1345,1505,1668,1831,1994,2157,2320,2483,2646,2809,2972,3132,3291,3452,3610,3771,3934,4051,4168,4294,4411,4528,4648,4765,4879,4993,5110,5227,5344,5507,5666,5830,5929],
        'qword ptr [rax]':[515,912,1075,1238,1397,1557,1720,1883,2046,2209,2372,2535,2698,2861,3024,3184,3343,3504,3662,3823,5396,5559,5718],
        'qword ptr [rax + 8]':[538,937,1100,1263,1422,1582,1745,1908,2071,2234,2397,2560,2723,2886,3049,3209,3368,3529,3687,3848,5421,5584,5738],
        'variant_destroy':[656,758,3963,4080,4197,4323,4440,4557,4677,4794,4908,5022,5139,5256,5857,5954],'variant_number':[3541]},
    'copy':{'copy_string':list(range(16,108,13))+list(range(126,659,19))},
    'move':{'free':[47,98,151,204,257,310,363,416]+list(range(475,2128,59))}}
# These four bodies are replaced, never admitted as additional executed roots.
LEAF_BYTES={
    'construct_info':b'\x33\xc0\x48\x89\x01'+b''.join(b'\x48\x89\x41'+bytes([n]) for n in range(8,128,8))
        +b''.join(b'\x48\x89\x81'+struct.pack('<I',n) for n in range(128,0x250,8))+b'\x48\x8b\xc1\xc3',
    'settings':bytes.fromhex('488b01480510030000c3'),
    'source_info':bytes.fromhex('488b01488b40284883c028c3'),
    'optional_resolve':bytes.fromhex('488b0148ffa010040000')}


def load(name):
    spec=spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=module_from_spec(spec);spec.loader.exec_module(module);return module


def tools():
    return {**load('version-system-transfer-rules').tools(),str(Path(__file__).resolve()):hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


def functional(context):
    if set(context)-METADATA!=FIELDS or context['verify_whole_exports'] is not True:raise ValueError('Metadata functional fields or optional native scope differ')
    if set(context['functions'])!=set(FUNCTIONS) or set(context['fixtures'])!=FIXTURES or set(context['helpers'])!={'memcpy'}:
        raise ValueError('Metadata function/fixture/helper roles differ')
    if set(context['globals'])!={'optional_manager','log_level','log_enabled','cookie'} or context['collector_order']!=list(ORDER):
        raise ValueError('Metadata global roles or collector order differ')
    if not isinstance(context['call_sites'],dict) or any(set(v)!={'target'} or not isinstance(v['target'],str) for v in context['call_sites'].values()):
        raise ValueError('Metadata call-site declaration differs')
    utility=load('version-system-transfer-rules')
    for group in ('functions','fixtures','helpers','globals'):
        for value in context[group].values():utility.address(value)
    for role,at in SYNTHETIC.items():
        if utility.address(context['fixtures'][role])!=at:raise ValueError('Metadata synthetic destructor hook moved')
    return {key:copy.deepcopy(context[key]) for key in FIELDS}


def roots(context):
    functional(context);values=[int(context['functions'][key],16) for key in FUNCTIONS]
    fixtures=[int(value,16) for value in context['fixtures'].values()]
    memcpy=int(context['helpers']['memcpy'],16)
    if (len(set(values))!=6 or len(set(fixtures))!=len(fixtures) or set(values)&set(fixtures)
            or memcpy in set(values)|set(fixtures)):
        raise ValueError('Metadata roots, fixtures or memcpy alias')
    return set(values)


def call_sites(all_rows):
    return {hex(row['address']):dict(target=hex(row['direct_target']) if row['direct_target'] is not None else row['operands'])
        for rows in all_rows.values() for row in rows if row['call']}


def call_roles(context,all_rows):
    for role,text in context['functions'].items():
        origin=int(text,16);rows={row['address']-origin:row for row in all_rows[role] if row['call']}
        expected={offset:key for key,offsets in CALL_GROUPS[role].items() for offset in offsets}
        if len(expected)!=sum(map(len,CALL_GROUPS[role].values())) or set(rows)!=set(expected):raise ValueError('Metadata call role layout changed')
        for offset,key in expected.items():
            row=rows[offset]
            if key.startswith('qword ptr '):
                if row['direct_target'] is not None or row['operands']!=key or row['rip_references']:
                    raise ValueError('Metadata virtual destructor dispatch differs')
            else:
                target=context['functions'][key[5:]] if key.startswith('root:') else context['fixtures'][key]
                if row['direct_target']!=int(target,16):raise ValueError('Metadata direct callee role differs: '+key)


def typed_inputs(before,after,baseline,mapping,rows):
    utility=load('version-system-transfer-rules');common=load('update-native-archive-wire');result=[];seen={}
    for role,text in baseline['functions'].items():
        origin=int(text,16);refs={row['address']-origin:row['rip_references'] for row in rows[role] if row['rip_references']}
        if set(refs)!=set(LITERALS[role])|set(GLOBAL_RIPS[role]) or any(len(v)!=1 for v in refs.values()):
            raise ValueError('Metadata RIP role layout changed')
        for offset,name in GLOBAL_RIPS[role].items():
            if refs[offset]!=[int(baseline['globals'][name],16)]:raise ValueError('Metadata global input linkage differs')
        for offset,raw in LITERALS[role].items():
            old=refs[offset][0];new=mapping[old]
            if utility.image_bytes(before,old,len(raw))!=raw or utility.image_bytes(after,new,len(raw))!=raw:
                raise ValueError('Metadata exact compiled literal changed: '+role+'/'+str(offset))
            if new in seen and seen[new]!=raw:raise ValueError('Metadata literal roles alias incompatible data')
            seen[new]=raw
            result.append(dict(root=role,offset=offset,address=hex(new),encoding='ascii' if role=='writer' and offset not in (94,111,264) else 'utf16le',
                bytes=raw.hex(),scope='Exact compiled literal; diagnostic text never executed' if role=='writer' and offset in (66,111) else 'Exact compiled metadata key/format'))
    data_roles={'optional_manager':(8,'pe-zero-fill'),'log_level':(1,'pe-zero-fill'),'log_enabled':(1,b'\1'),
        'cookie':(8,bytes.fromhex('32a2df2d992b0000'))}
    old_intervals=[];new_intervals=[]
    for name,(size,expected) in data_roles.items():
        old=int(baseline['globals'][name],16);new=mapping[old]
        a,b=utility.data_input(before,old,size),utility.data_input(after,new,size)
        if a!=b or (isinstance(expected,bytes) and b!=dict(storage='file',bytes=expected.hex())) or (expected=='pe-zero-fill' and b['storage']!=expected):
            raise ValueError('Metadata typed global input changed: '+name)
        for intervals,start in ((old_intervals,old),(new_intervals,new)):
            if any(start<end and lo<start+size for lo,end in intervals):raise ValueError('Metadata global input roles overlap')
            intervals.append((start,start+size))
        common.add_link(mapping,old,new)
        result.append(dict(role=name,address=hex(new),size=size,input=b,scope='Synthetic initialized state; no real SDK or user identity read'))
    return result


def fixture_boundaries(before,after,baseline,context,mapping):
    utility=load('version-system-transfer-rules');roots(baseline);roots(context)
    result={}
    for role,text in context['fixtures'].items():
        old,new=int(baseline['fixtures'][role],16),int(text,16)
        if role in SYNTHETIC:
            if old!=SYNTHETIC[role] or new!=old:raise ValueError('Metadata synthetic destructor hook moved')
            result[role]=dict(address=text,kind='synthetic-hook',scope='Emulator control-block virtual destructor fixture');continue
        if role=='memset':result[role]=utility.import_thunk(before,after,old,new,'memset',mapping)
        elif role in LEAF_BYTES:
            raw=LEAF_BYTES[role]
            if utility.image_bytes(before,old,len(raw))!=raw or utility.image_bytes(after,new,len(raw))!=raw:
                raise ValueError('Metadata bounded fixture leaf changed: '+role)
            result[role]=dict(address=text,kind='bounded-fixture-leaf',size=len(raw),bytes_sha256=hashlib.sha256(raw).hexdigest(),
                scope='Exact non-unwind fixture body; replaced, not executed; virtual tail dispatch excluded' if role=='optional_resolve' else 'Exact non-unwind fixture body; replaced, not executed')
        else:
            utility.concrete(before,old);utility.concrete(after,new)
            result[role]=dict(address=text,kind='unwind-fixture',scope='Replaced fixture; body not executed')
    return result


def transfer(native,bindings,before,after,baseline,mapping):
    current=functional(baseline);roots(baseline);common=load('update-native-archive-wire');utility=load('version-system-transfer-rules')
    old_rows={};new_rows={}
    for role in FUNCTIONS:
        old=int(baseline['functions'][role],16)
        if old not in mapping:raise ValueError('Metadata root lacks caller constraint: '+role)
        target=mapping[old];utility.concrete(before,old);utility.concrete(after,target)
        a,b=bindings.rows(native,before,old),bindings.rows(native,after,target);common.pair_rows(native,a,b,mapping)
        old_rows[role],new_rows[role]=a,b
    if call_sites(old_rows)!=baseline['call_sites']:raise ValueError('Metadata baseline call sites differ')
    call_roles(baseline,old_rows);data=typed_inputs(before,after,baseline,mapping,old_rows)
    def mapped(value):
        old=int(value,16)
        if old not in mapping:raise ValueError('Metadata undeclared relocated address: '+value)
        return hex(mapping[old])
    current['functions']={key:mapped(value) for key,value in baseline['functions'].items()}
    current['fixtures']={key:(value if key in SYNTHETIC else mapped(value)) for key,value in baseline['fixtures'].items()}
    current['globals']={key:mapped(value) for key,value in baseline['globals'].items()}
    current['helpers']={'memcpy':mapped(baseline['helpers']['memcpy'])};current['call_sites']=call_sites(new_rows)
    boundaries=fixture_boundaries(before,after,baseline,current,mapping)
    memcpy=utility.import_thunk(before,after,int(baseline['helpers']['memcpy'],16),int(current['helpers']['memcpy'],16),'memcpy',mapping)
    return current,dict(roots=current['functions'],typed_inputs=data,fixtures=boundaries,memcpy=memcpy,
        collector_order=list(ORDER),field_map=FIELD_MAP,userinfo_bytes=0x250,userinfo_fields=list(range(0,0x250,16)),
        excluded_calls=[dict(root='writer',offset=offset,role=role,scope='Diagnostic branch disabled; fixture body not executed')
            for offset,role in ((78,'diagnostic_text'),(132,'diagnostic_log'))],
        mapping={hex(a):hex(b) for a,b in sorted(mapping.items())})
