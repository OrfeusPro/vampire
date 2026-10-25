"""Build a small runtime name registry from pinned current native EStat descriptors."""
import argparse
import hashlib
import json
from pathlib import Path
import re

HERE=Path(__file__).resolve().parent
SOURCE_SHA='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
ENUM_SHA='6e78d5ed9523d64e3e771da24da6b9fd2f95fd78c8d308076717918d369d205a'


def build(source,output):
    raw=source.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=ENUM_SHA:raise ValueError('Pinned enum descriptor report required')
    data=json.loads(raw)
    if data['source_sha256']!=SOURCE_SHA:raise ValueError('Stat descriptor source differs')
    names={}
    for row in data['enums']['EStat']:
        name=row['name']
        if not isinstance(name,str) or not re.fullmatch('EStat::[A-Za-z_][A-Za-z_0-9]*',name):raise ValueError('Invalid native enum name')
        value=row['value']
        if type(value) is not int or not -2**31<=value<2**31 or value in names:raise ValueError('Invalid or duplicate stat descriptor')
        names[value]=name.removeprefix('EStat::')
    if len(names)!=208 or [names[i] for i in (3,4,5,9,10)]!=['Level','Hp','MaxHp','Mp','MaxMp']:
        raise ValueError('Current stat contract differs')
    lines=['"""Generated native EStat names; units and display formatting are not inferred."""',
        'from types import MappingProxyType','',f'SOURCE_SHA256={SOURCE_SHA!r}',f'ENUM_REPORT_SHA256={ENUM_SHA!r}',
        'STAT_NAMES=MappingProxyType({']
    lines.extend(f'    {key}: {value!r},' for key,value in sorted(names.items()))
    lines.append('})')
    output.write_text('\n'.join(lines)+'\n',encoding='utf-8')
    return dict(output=str(output),names=len(names),sha256=hashlib.sha256(output.read_bytes()).hexdigest())


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--output',type=Path,default=HERE.parents[1]/'vampir-shared/vampir_core/stat_names.py')
    args=parser.parse_args();print(json.dumps(build(args.source,args.output)))
