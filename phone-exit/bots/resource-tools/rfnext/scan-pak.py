import struct,json,ctypes,hashlib,re,time
from pathlib import Path
import os
ROOT=Path(os.environ.get('PHONEEXIT_RF_RESOURCES', r'F:\PhoneExit Resources\RF Online Next'))
DLL=ctypes.CDLL(str(ROOT/'tools/oodle-data-shared.dll'));DECOMP=DLL.OodleLZ_Decompress;DECOMP.restype=ctypes.c_ssize_t;DECOMP.argtypes=[ctypes.c_void_p,ctypes.c_ssize_t,ctypes.c_void_p,ctypes.c_ssize_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_void_p,ctypes.c_ssize_t,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_ssize_t,ctypes.c_int]
def header(f,pos,limit):
 f.seek(pos);h=f.read(52)
 if len(h)<52:return None
 off,size,usize,method=struct.unpack_from('<qqqI',h)
 if off!=0 or size<=0 or usize<=0 or size>limit-pos or usize>1024**3 or method>1:return None
 blocks=[]
 if method:
  count=struct.unpack_from('<i',h,48)[0]
  if count<1 or count>32768:return None
  data=f.read(count*16+1)
  # First four bytes of the first block were already read in h[48:52]? h includes count only.
  blocks=[struct.unpack_from('<qq',data,i*16) for i in range(count)]
  flags=data[-1];bs=struct.unpack('<I',f.read(4))[0];hs=52+count*16+5
 else:
  flags=h[48];f.seek(pos+49);bs=struct.unpack('<I',f.read(4))[0];hs=53
 if flags not in (0,1):return None
 if method and (bs<1 or any(a<hs or b<a or pos+b>limit for a,b in blocks)):return None
 end=pos+blocks[-1][1] if method else pos+hs+size
 if flags:end=(end+15)//16*16
 if end<=pos or end>limit:return None
 return dict(pos=pos,size=size,usize=usize,method=method,blocks=blocks,encrypted=bool(flags),blocksize=bs,hs=hs,end=end)
def decode(f,h):
 if h['encrypted']:return None
 if not h['method']:
  f.seek(h['pos']+h['hs']);return f.read(h['size'])
 out=[];written=0
 for a,b in h['blocks']:
  f.seek(h['pos']+a);data=f.read(b-a);n=min(h['blocksize'],h['usize']-written);buf=ctypes.create_string_buffer(n+64);src=ctypes.create_string_buffer(data);actual=DECOMP(src,len(data),buf,n,1,0,0,None,0,None,None,None,0,3)
  if actual!=n:raise ValueError('oodle_size_mismatch')
  out.append(buf.raw[:n]);written+=n
 return b''.join(out)
def scan(path,outdir):
 outdir.mkdir(exist_ok=True,parents=True);records=[]
 with path.open('rb') as f:
  f.seek(-512,2);tail=f.read();i=tail.rfind(struct.pack('<I',0x5a6f12e1));limit=struct.unpack_from('<q',tail,i+8)[0];pos=0
  while pos<limit:
   h=header(f,pos,limit)
   if not h:
    candidates=sorted({((pos+a-1)//a)*a for a in (16,128,512,2048,4096,65536)})
    found=next(((candidate,header(f,candidate,limit)) for candidate in candidates if candidate>pos and header(f,candidate,limit)),None)
    if not found:break
    pos,h=found
   row={'entry':len(records),'offset':pos,'bytes':h['size'],'uncompressed':h['usize'],'encrypted':h['encrypted']};records.append(row)
   if h['usize']<=32*1024*1024 and not h['encrypted']:
    b=decode(f,h)
    if b:
     row['uasset']=b.startswith(b'\xc1\x83\x2a\x9e')
     if row['uasset']:
      strings=[s.decode('ascii') for s in re.findall(rb'[ -~]{4,}',b)]
      paths=[s for s in strings if s.startswith(('/Game/','/Engine/'))];row['paths']=paths;row['texture']='Texture2D' in strings
      if row['texture'] or any(re.search(r'(?i)(map|mini.?map|atlas)',s) for s in paths):
       row['saved']=str(outdir/f"{row['entry']:06d}.uasset");Path(row['saved']).write_bytes(b)
     elif b'PF_' in b:
      row['pixel_formats']=[s.decode('ascii') for s in re.findall(rb'PF_[A-Za-z0-9_]+',b)];row['saved']=str(outdir/f"{row['entry']:06d}.uexp");Path(row['saved']).write_bytes(b)

   pos=h['end']
 records.append({'scan_end':pos,'index_offset':limit,'complete_linear_scan':pos==limit})
 (outdir/'entries.json').write_text(json.dumps(records,ensure_ascii=False,indent=2),encoding='utf-8');print(path.name,'entries',len(records)-1,'textures',sum(r.get('texture',False) for r in records),'PF exports',sum('pixel_formats' in r for r in records),'end',pos,'index',limit,flush=True)
 return records
if __name__=='__main__':
 import sys
 scan(Path(sys.argv[1]),ROOT/'pak-extracted'/Path(sys.argv[1]).stem)
