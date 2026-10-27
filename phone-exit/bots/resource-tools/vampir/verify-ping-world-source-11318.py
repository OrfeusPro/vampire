"""Revalidate fixed current Ping/world exports, whole ranges and static bindings."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
SHA='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify(context,root):
    root=Path(root);source=root/'client-code-snapshots'/SHA/'ProjectRED-Win64-Shipping.exe'
    if context['source_sha256']!=SHA or Path(context['source']).resolve()!=source.resolve():raise ValueError('Ping/world context source differs')
    raw=source.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SHA:raise ValueError('Ping/world source SHA changed')
    native=load('build-native-entry-code');image=native.Image(raw)
    functions={int(at,16) for at in context['functions'].values()};found=set();evidence=[]
    expected_roots={int(at,16) for at in ('14561c000 1456baed0 1456db7f0 1456e8660 1456f04a0 '
        '145822390 1458224d0 14584f500 14584f7b0 14584f8d0 145dafea0 145db3050 '
        '145db3580 1467cf7f0 14679c920').split()}
    if functions!=expected_roots:
        raise ValueError('Ping/world fixed root set changed')
    whole=load('audit-launcher-shape-11318')
    for run,expected in context['exports'].items():
        path=root/'ghidra/request-exports'/SHA/run/'details.json'
        if digest(path)!=expected:raise ValueError('Ping/world export SHA changed')
        document=json.loads(path.read_bytes())
        if document['new_source_sha256']!=SHA:raise ValueError('Ping/world export source differs')
        evidence.append(dict(path=str(path),sha256=expected))
        for f in document['functions']:
            at=int(f['address'],16)
            if at not in functions:continue
            if at in found:raise ValueError('Duplicate Ping/world export root')
            whole.normalize_function(native,image,f);found.add(at)
    if found!=functions:raise ValueError('Ping/world export root absent')
    for at,encoded in dict(context['leaves'],**context['blocks']).items():
        at=int(at,16);payload=bytes.fromhex(encoded);off=image.offset(at-image.pe.base)
        if raw[off:off+len(payload)]!=payload:raise ValueError('Ping/world static source bytes changed')
    ping=context['ping']
    expected_ping=dict(constructor='0x1456d7c70',getter='0x1456e5080',reader='0x1456db7f0',handler='0x14679c920',
        receiver='0x1467cf7f0',packet_table='0x149928290',handler_table='0x149dc7fa8',wrapper_getter='0x144ab0f40',
        config_getter='0x145595140',recovery='0x144ab13f0')
    if any(ping.get(key)!=value for key,value in expected_ping.items()):raise ValueError('Ping source-bound role differs')
    table=int(ping['packet_table'],16);handler_table=int(ping['handler_table'],16)
    def data(at,size):
        off=image.offset(at-image.pe.base);return raw[off:off+size]
    for base,slot,key in ((table,0x20,'reader'),(table,0x28,'getter'),(handler_table,0x10,'handler')):
        if struct.unpack('<Q',data(base+slot,8))[0]!=int(ping[key],16):raise ValueError('Ping static table link changed')
    if data(table+0x50,14)!=b'PktPingResult\0' or data(int(ping['getter'],16),6)!=b'\xb8\x11\0\0\0\xc3':
        raise ValueError('Ping packet name/ID changed')
    get=int(context['mapping']['0x1445cd3c0'],16);leaf=data(get,8)
    if (get!=0x1445cd6c0 or leaf[:3]!=b'\x48\x8b\x05' or leaf[-1:]!=b'\xc3'
            or get+7+struct.unpack_from('<i',leaf,3)[0]!=int(ping['clock_global'],16)):
        raise ValueError('Ping clock singleton role differs')
    registration=ping['registration'];at=int(registration['address'],16)
    if (at!=0x1467b53fc or registration['owner']!='0x1467b5130' or len(bytes.fromhex(registration['bytes']))!=75
            or data(at,75)!=bytes.fromhex(registration['bytes'])):
        raise ValueError('Ping registration binding differs')
    return dict(source_sha256=SHA,evidence=evidence,function_count=len(found),network_used=False,
                profile_activated=False,limits=['Whole native ranges and pinned static bindings only; execution and fixtures are reported separately.'])
