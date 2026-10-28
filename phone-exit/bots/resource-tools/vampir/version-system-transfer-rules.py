"""Pure, typed relocation rules for Version NM, CPU and Windows helper families.

The caller owns source/export admission, semantic execution and publication.
Only complete reviewed roots execute; OS, storage and CRT fixture bodies do not.
"""
import copy
import hashlib
from importlib.util import spec_from_file_location, module_from_spec
from pathlib import Path
import re
import struct

HERE=Path(__file__).resolve().parent
TOOLS=('version-system-transfer-rules.py','update-native-archive-wire.py','update-native-contexts.py',
    'update-bindings.py','build-native-entry-code.py','extract-native-enums.py','build-object-zero-init-code.py')
METADATA={'schema','source','source_sha256','exports','family','layout','transfer_proof','release_id'}
FIELDS={
    'version-nm-device':{'wrapper','getter','cache','log_level','log_enabled','storage_arguments'},
    'version-cpu':{'functions','vendor','brand','space_slot'},
    'version-windows':{'function','guard','cache','tls_index','cookie','imports'}}
FIXTURES={
    'version-nm-device':{'resize','free','assign_span','stored_read','parse','new_guid','format_guid','stored_write'},
    'version-cpu':{'ascii','wide','free','move','shrink','format','space'},
    'version-windows':{'acquire','release','memset','format','wide_string','cookie_check'}}
CPU_FUNCTIONS=('formatter','first','second','trim','trim_end','trim_start')
NM_RIPS={10:('log_level',0),22:('log_enabled',0),31:('diagnostic_name',0),58:('empty',0),73:('diagnostic_format',0),
    80:('log_level',0),125:('cache',8),142:('cache',8),149:('cache',0),214:('storage2',0),225:('storage1',0),
    232:('storage0',0),326:('cache',0),347:('cache',0),354:('cache',0),361:('storage2',0),371:('storage1',0),
    378:('cache',8),384:('storage0',0),394:('cache',12),425:('cache',0),440:('cache',8),447:('cache',0)}
CPU_RIPS={
    'formatter':{91:('unknown',0),134:('unknown',0),270:('separator',0),291:('underscore',0),306:('separator',0),
        330:('empty',0),340:('format_three',0),406:('empty',0),416:('format_three',0),468:('empty',0),478:('format_two',0)},
    'first':{6:('vendor',0)},'second':{6:('brand',0)},'trim':{},
    'trim_end':{56:('space_slot',0)},'trim_start':{54:('space_slot',0)}}
WINDOWS_RIPS={9:('cookie',0),39:('tls_index',0),57:('guard',0),65:('cache',0),108:('guard',0),122:('guard',0),
    134:('guard',0),148:('system_info_slot',0),194:('version_slot',0),212:('bits',0),227:('format',0),
    267:('cache',0),294:('guard',0),313:('cache',0)}
CALL_ROLES={
    'version-nm-device':{'wrapper':{9:'root:getter'},'getter':{42:None,91:None,105:'free',179:'resize',196:'helper:memcpy',
        239:'stored_read',252:'parse',298:'new_guid',321:'format_guid',338:'free',400:'stored_write',432:'assign_span',
        474:'resize',491:'helper:memcpy',505:'free'}},
    'version-cpu':{'formatter':{25:'root:first',37:'root:trim',51:'free',60:'root:second',72:'root:trim',86:'free',
        102:'wide',115:'root:trim',129:'free',145:'wide',231:'free',281:None,321:None,381:'format',395:'free',
        457:'format',502:'format',516:'free',530:'free',544:'free'},'first':{16:'ascii'},'second':{16:'ascii'},
        'trim':{16:'root:trim_end',24:'root:trim_start'},'trim_end':{56:'iat:space_slot',141:'move',152:'shrink'},
        'trim_start':{54:'iat:space_slot',117:'move',128:'shrink'}},
    'version-windows':{'windows':{75:'wide_string',94:'cookie_check',115:'release',129:'acquire',
        148:'iat:GetNativeSystemInfo',170:'memset',194:'iat:GetVersionExW',289:'format',301:'release'}}}


def load(name):
    spec=spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=module_from_spec(spec);spec.loader.exec_module(module);return module


def tools():return {str(HERE/name):hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in TOOLS}


def address(value):
    if not isinstance(value,str) or not re.fullmatch('0x[0-9a-fA-F]+',value):raise ValueError('Version helper requires an explicit hex address')
    return int(value,16)


def functional(family,context):
    if family not in FIELDS:raise ValueError('Unsupported Version system family')
    required=FIELDS[family]|{'helpers','fixtures','call_sites','verify_whole_exports'}
    if set(context)-METADATA!=required or context['verify_whole_exports'] is not True:
        raise ValueError('Version helper fields or optional native scope differ')
    if set(context['helpers'])!={'memcpy'} or set(context['fixtures'])!=FIXTURES[family]:raise ValueError('Version helper fixture/helper roles differ')
    if not isinstance(context['call_sites'],dict) or not all(isinstance(k,str) and isinstance(v,str) for k,v in context['call_sites'].items()):
        raise ValueError('Version helper call-site declaration differs')
    if family=='version-cpu' and set(context['functions'])!=set(CPU_FUNCTIONS):raise ValueError('Version CPU function roles differ')
    if family=='version-nm-device' and (not isinstance(context['storage_arguments'],list) or len(context['storage_arguments'])!=3):
        raise ValueError('Version NM storage descriptor roles differ')
    if family=='version-windows':
        if set(context['imports'])!={'GetNativeSystemInfo','GetVersionExW'}:raise ValueError('Version Windows import roles differ')
        for name,fixture in (('GetNativeSystemInfo','system_info'),('GetVersionExW','version')):
            item=context['imports'][name]
            if set(item)!={'slot','dll','fixture'} or item['dll'].lower()!='kernel32.dll' or item['fixture']!=fixture:
                raise ValueError('Version Windows import binding differs')
    return {k:copy.deepcopy(context[k]) for k in required}


def root_roles(family,context):
    if family=='version-nm-device':return {k:address(context[k]) for k in ('wrapper','getter')}
    if family=='version-cpu':return {k:address(context['functions'][k]) for k in CPU_FUNCTIONS}
    if family=='version-windows':return {'windows':address(context['function'])}
    raise ValueError('Unsupported Version system family')


def roots(family,context):
    functional(family,context);values=list(root_roles(family,context).values())
    if len(values)!=len(set(values)):raise ValueError('Version helper executable roots alias')
    return set(values)


def image_bytes(image,at,size):
    rva=at-image.pe.base
    spans=[s for s in image.pe.sections if s['rva']<=rva and rva+size<=s['rva']+s['raw_size']]
    if len(spans)!=1:raise ValueError('Version helper data is not wholly file-backed')
    return load('update-native-contexts').image_bytes(image,at,size)


def data_input(image,at,size):
    if type(size) is not int or size<=0:raise ValueError('Invalid Version helper data width')
    try:return dict(storage='file',bytes=image_bytes(image,at,size).hex())
    except ValueError:
        rva=at-image.pe.base
        spans=[s for s in image.pe.sections if s['rva']+s['raw_size']<=rva and rva+size<=s['rva']+s['size']]
        if len(spans)!=1:raise ValueError('Version helper data is outside file and PE zero-fill')
        return dict(storage='pe-zero-fill',size=size,section=spans[0]['name'])


def concrete(image,at):
    part=image.containing(at)
    if part is None or image.roots[part][0]+image.pe.base!=at:raise ValueError('Version fixture is not a concrete unwind entry')


def named_import(image,slot,name,dll):
    found=load('build-object-zero-init-code').import_at(image.data,image,slot)
    if (found['name'],found['dll'].lower())!=(name,dll.lower()):raise ValueError('Version helper named import identity differs')
    return dict(slot=hex(slot),name=found['name'],dll=found['dll'].lower())


def import_thunk(before,after,old,new,name,mapping):
    common=load('update-native-archive-wire');items=[];slots=[]
    for image,at in ((before,old),(after,new)):
        raw=image_bytes(image,at,6)
        if raw[:2]!=b'\xff\x25':raise ValueError('Version CRT fixture is not an exact six-byte IAT thunk')
        slot=at+6+struct.unpack_from('<i',raw,2)[0];slots.append(slot)
        items.append(named_import(image,slot,name,'VCRUNTIME140.dll'))
    common.add_link(mapping,*slots)
    return dict(address=hex(new),kind='named-import-thunk',size=6,import_binding=items[1],scope='Replaced fixture; thunk and named IAT linkage only')


def call_sites(rows):
    return {hex(r['address']):hex(r['direct_target']) if r['direct_target'] is not None else r['operands'] for r in rows if r['call']}


def rip_roles(rows,origin,spec,known,mapping):
    refs={r['address']-origin:r['rip_references'] for r in rows if r['rip_references']}
    if set(refs)!=set(spec) or any(len(v)!=1 for v in refs.values()):raise ValueError('Version helper RIP role layout changed')
    for offset,(role,delta) in spec.items():
        old=refs[offset][0]-delta
        if role in known and known[role]!=old:raise ValueError('Version helper RIP role linkage differs: '+role)
        known[role]=old
        if mapping[old+delta]!=mapping.get(old,mapping[old+delta]-delta)+delta:raise ValueError('Version helper descriptor subfield relocation differs')
        load('update-native-archive-wire').add_link(mapping,old,mapping[old+delta]-delta)


def check_call_roles(family,context,roles,all_rows):
    for role,origin in roles.items():
        rows={r['address']-origin:r for r in all_rows[role] if r['call']};spec=CALL_ROLES[family][role]
        if set(rows)!=set(spec):raise ValueError('Version helper call role layout changed')
        for offset,key in spec.items():
            row=rows[offset]
            if key is None:
                if row['direct_target'] is None:raise ValueError('Version excluded direct-call boundary changed')
                continue
            if key.startswith('iat:'):
                name=key[4:];slot=context[name] if name=='space_slot' else context['imports'][name]['slot']
                if row['direct_target'] is not None or row['rip_references']!=[address(slot)]:raise ValueError('Version helper IAT call role differs')
                continue
            expected=roles[key[5:]] if key.startswith('root:') else address(context['helpers'][key[7:]]) if key.startswith('helper:') else address(context['fixtures'][key])
            if row['direct_target']!=expected:raise ValueError('Version helper callee role linkage differs: '+key)


def transfer(family,native,bindings,before,after,baseline,mapping):
    current=functional(family,baseline);expected_roots=roots(family,baseline);roles=root_roles(family,baseline)
    common=load('update-native-archive-wire');old_rows={};new_rows={}
    # Only the caller-proved entry root is seeded. Its exact call edges resolve descendants.
    for role,old in roles.items():
        if old not in mapping:raise ValueError('Version helper lacks caller-constrained root: '+role)
        target=mapping[old];concrete(before,old);concrete(after,target)
        a,b=bindings.rows(native,before,old),bindings.rows(native,after,target)
        common.pair_rows(native,a,b,mapping);old_rows[role]=a;new_rows[role]=b
    if {k:v for r in old_rows.values() for k,v in call_sites(r).items()}!=baseline['call_sites']:
        raise ValueError('Version helper baseline call sites differ')
    check_call_roles(family,baseline,roles,old_rows)
    def mapped(value):
        old=address(value)
        if old not in mapping:raise ValueError('Version helper has an undeclared relocated address: '+value)
        return hex(mapping[old])
    known={};specs={};literals={};ranges=[];typed=[];imports=[]
    if family=='version-nm-device':
        known={k:address(baseline[k]) for k in ('cache','log_level','log_enabled')}
        known.update({'storage'+str(i):address(v) for i,v in enumerate(baseline['storage_arguments'])})
        specs={'wrapper':{},'getter':NM_RIPS}
        literals={'diagnostic_name':b'class FString __cdecl Netmarble::Service::FDeviceInfo::GetNMDeviceKey(void)\0',
            'empty':b'\0\0','diagnostic_format':'%s\0'.encode('utf-16le')}
        ranges=[('cache',16,'pe-zero-fill'),('log_level',1,'pe-zero-fill'),('log_enabled',1,b'\1')]+[
            ('storage'+str(i),16,'pe-zero-fill') for i in range(3)]
        current.update({k:mapped(baseline[k]) for k in ('wrapper','getter','cache','log_level','log_enabled')})
        current['storage_arguments']=[mapped(v) for v in baseline['storage_arguments']]
    elif family=='version-cpu':
        known={k:address(baseline[k]) for k in ('vendor','brand','space_slot')};specs=CPU_RIPS
        literals={k:(v+'\0').encode('utf-16le') for k,v in dict(unknown='Unknown',separator='|',underscore='_',empty='',format_three='%s|%s|%s',format_two='%s|%s').items()}
        ranges=[('vendor',13,bytes(13)),('brand',64,bytes(64))]
        if address(baseline['fixtures']['space'])!=0x28006000:raise ValueError('Version CPU synthetic whitespace hook moved')
        current['functions']={k:mapped(v) for k,v in baseline['functions'].items()}
        current.update({k:mapped(baseline[k]) for k in ('vendor','brand','space_slot')})
    else:
        known={k:address(baseline[k]) for k in ('guard','cache','tls_index','cookie')};specs={'windows':WINDOWS_RIPS}
        known.update(system_info_slot=address(baseline['imports']['GetNativeSystemInfo']['slot']),version_slot=address(baseline['imports']['GetVersionExW']['slot']))
        literals={k:(v+'\0').encode('utf-16le') for k,v in dict(bits='64bit',format='%d.%d.%d.%d.%d.%s').items()}
        ranges=[('guard',4,'pe-zero-fill'),('cache',256,'pe-zero-fill'),('tls_index',4,'pe-zero-fill'),('cookie',8,bytes.fromhex('32a2df2d992b0000'))]
        current.update({k:mapped(baseline[k]) for k in ('function','guard','cache','tls_index','cookie')})
        current['imports']={k:{**v,'slot':mapped(v['slot'])} for k,v in baseline['imports'].items()}
    for role,rows in old_rows.items():rip_roles(rows,roles[role],specs[role],known,mapping)
    for role,raw in literals.items():ranges.append((role,len(raw),raw))
    old_intervals=[];new_intervals=[]
    for role,size,expected in ranges:
        old=known[role];new=mapping[old];a,b=data_input(before,old,size),data_input(after,new,size)
        if a!=b or (isinstance(expected,bytes) and b!=dict(storage='file',bytes=expected.hex())) or (expected=='pe-zero-fill' and b['storage']!=expected):
            raise ValueError('Version helper typed data changed: '+role)
        for intervals,start in ((old_intervals,old),(new_intervals,new)):
            if any(start<end and lo<start+size for lo,end in intervals):raise ValueError('Version helper data roles overlap')
            intervals.append((start,start+size))
        typed.append(dict(role=role,address=hex(new),size=size,input=b,scope='Synthetic initialized state' if role not in literals else 'Exact compiled literal'))
    if family=='version-cpu':
        for image,slot in ((before,known['space_slot']),(after,mapping[known['space_slot']])):
            item=named_import(image,slot,'iswspace','api-ms-win-crt-string-l1-1-0.dll')
        imports.append(item)
    elif family=='version-windows':
        for name in ('GetNativeSystemInfo','GetVersionExW'):
            for image,slot in ((before,address(baseline['imports'][name]['slot'])),(after,address(current['imports'][name]['slot']))):
                item=named_import(image,slot,name,'KERNEL32.dll')
            imports.append(item)
    current['fixtures']={k:(v if family=='version-cpu' and k=='space' else mapped(v)) for k,v in baseline['fixtures'].items()}
    current['helpers']={'memcpy':mapped(baseline['helpers']['memcpy'])}
    current['call_sites']={k:v for rows in new_rows.values() for k,v in call_sites(rows).items()}
    targets={address(v) for v in current['fixtures'].values()};new_roots={mapping[v] for v in expected_roots}
    if len(targets)!=len(current['fixtures']) or targets&new_roots or len(new_roots)!=len(expected_roots):raise ValueError('Version helper fixtures/roots alias')
    boundaries={}
    for key,value in current['fixtures'].items():
        old,new=address(baseline['fixtures'][key]),address(value)
        if family=='version-cpu' and key=='space':
            boundaries[key]=dict(address=value,kind='synthetic-hook',scope='Emulator-only ASCII whitespace classifier');continue
        if (family,key) in (('version-cpu','move'),('version-windows','memset')):
            boundaries[key]=import_thunk(before,after,old,new,'memmove' if key=='move' else 'memset',mapping)
        else:
            concrete(before,old);concrete(after,new)
            boundaries[key]=dict(address=value,kind='unwind-fixture',scope='Replaced fixture; body not executed')
    memcpy=import_thunk(before,after,address(baseline['helpers']['memcpy']),address(current['helpers']['memcpy']),'memcpy',mapping)
    exclusions=[]
    excluded={'version-nm-device':{'getter':(42,91)},'version-cpu':{'formatter':(281,321)}}.get(family,{})
    for role,offsets in excluded.items():
        rows={r['address']-roles[role]:r for r in old_rows[role]}
        for offset in offsets:
            old=rows[offset]['direct_target']
            if old is None:raise ValueError('Version excluded direct-call boundary changed')
            concrete(before,old);concrete(after,mapping[old])
            exclusions.append(dict(root=role,offset=offset,address=hex(mapping[old]),scope='Static linkage only; diagnostics disabled' if family=='version-nm-device' else 'Static linkage only; compiled Unknown selects the two-part CPU branch'))
    return current,dict(roots={k:hex(mapping[v]) for k,v in roles.items()},typed_inputs=typed,imports=imports,fixtures=boundaries,
        memcpy=memcpy,excluded_calls=exclusions,mapping={hex(a):hex(b) for a,b in sorted(mapping.items())})
