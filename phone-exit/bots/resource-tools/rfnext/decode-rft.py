"""Bounded native RFT decoder. Reject unknown field types and trailing bytes."""
import json,struct,hashlib,sys,os,re
from pathlib import Path
ROOT=Path(os.environ.get('PHONEEXIT_RF_RESOURCES',r'F:\PhoneExit Resources\RF Online Next'))/'data-study/rft'
def decode(file):
 b=Path(file).read_bytes()
 if b[:7]!=b'RFT\x1a\0\0\0':raise ValueError('Unexpected RFT version')
 def cstring(p):
  e=b.index(0,p)
  if e-p>65536:raise ValueError('Large string')
  return b[p:e].decode('utf-8'),e+1
 name,p=cstring(23);p+=8
 count,rows,declared,reserved=struct.unpack_from('<HIII',b,p);p+=14
 if count>1024 or rows>1000000:raise ValueError('Unbounded table')
 fields=[]
 for i in range(count):
  h=b[p:p+12];p+=12;strings=[]
  for k in range(4):s,p=cstring(p);strings.append(s)
  fields.append(dict(type=h[0],enum_storage=struct.unpack_from('<H',h,10)[0],flags=h.hex(),name=strings[0],enum=strings[1],meta=strings[2],description=strings[3]))
 start=p;records=[]
 formats={4:'<B',5:'<B',6:'<b',7:'<h',8:'<B',9:'<I',10:'<i',11:'<I',13:'<f',20:'<ddd'}
 for i in range(rows):
  row={};offset=p
  for f in fields:
   t=f['type'];array=bytes.fromhex(f['flags'])[5]==1
   if array:
    length=struct.unpack_from('<H',b,p)[0];p+=2
    storage=f['enum_storage'] if t==3 else t
    if length>4096 or storage not in formats:raise ValueError('Unsupported or unbounded array '+f['name'])
    fmt=formats[storage];value=[]
    for _ in range(length):
     parts=struct.unpack_from(fmt,b,p);p+=struct.calcsize(fmt);value.append(list(parts) if len(parts)>1 else parts[0])
    row[f['name']]=value;continue
   if t in (15,16,22):value,p=cstring(p)
   elif t==3:
    storage=f['enum_storage']
    if storage not in formats:raise ValueError('Unknown enum storage '+str(storage))
    fmt='<I' if storage==4 else formats[storage];value=struct.unpack_from(fmt,b,p)[0];p+=struct.calcsize(fmt)
   elif t in formats:
    fmt=formats[t];values=struct.unpack_from(fmt,b,p);p+=struct.calcsize(fmt);value=list(values) if len(values)>1 else values[0]
   else:raise ValueError('Unsupported type '+str(t)+' '+f['name'])
   row[f['name']]=value
  records.append(dict(offset=offset,values=row))
 if p!=len(b):raise ValueError('Unconsumed bytes: '+str(len(b)-p))
 return dict(name=name,sha256=hashlib.sha256(b).hexdigest(),source=str(file),data_offset=start,declared_size=declared,fields=fields,records=records)
if __name__=='__main__':
 if sys.argv[1:]==['--ru']:
  catalog=json.loads((ROOT/'catalog.json').read_text('utf-8'));variants=[r for r in catalog if r['name']=='RF_StringTable'];rank=max(r['patch_rank'] for r in variants);found=[]
  for r in variants:
   if r['patch_rank']!=rank:continue
   out=decode(r['file']);sample=next((x['values']['KO_KR'] for x in out['records'] if x['values']['StringID']=='Map_Region_55001'),'')
   sample=re.sub(r'\\u([0-9a-fA-F]{4})',lambda m:chr(int(m[1],16)),sample)
   if any('\u0400'<=c<='\u04ff' for c in sample):found.append((r,out))
  if len(found)!=1:raise ValueError('Russian language selection is ambiguous')
  r,out=found[0];out['archive_provenance']={k:r[k] for k in ('pak','pak_bytes','entry','pak_offset','sha256','patch_rank')};target=ROOT/'decoded';target.mkdir(exist_ok=True);(target/'RF_StringTable_RU.json').write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf-8');print('Russian localization selected by content:',r['entry'],'patch rank',rank);sys.exit(0)
 latest=json.loads((ROOT/'latest.json').read_text('utf-8'))
 for name in sys.argv[1:] or ['RF_MapInfoTable']:
  r=next(r for r in latest if r['name']==name)
  try:
   out=decode(r['file']);out['archive_provenance']={k:r[k] for k in ('pak','pak_bytes','entry','pak_offset','patch_rank')}
   target=ROOT/'decoded';target.mkdir(exist_ok=True);(target/(name+'.json')).write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf-8')
   print(name,len(out['records']),'rows fully consumed');print(json.dumps(out['records'][:2]))
  except Exception as e:print(name,'FAILED',str(e));raise
