"""Current projection math and two exact map-table records; no game IO."""
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
HERE=Path(__file__).resolve().parent
SHA='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
EXPORT='ghidra/request-exports/'+SHA+'/run-5e7bbc8a0f43/details.json'
INDEX='release-snapshots/c44b60d512a5b6a07a3ca7f6242eb23a385d36c87c67a7490fb2bad3c150b4db/record-indexes/faad77301f66215958cca4d9a083ca61f09f8f54650307dab1580470dc47f913/manifest.json'
ANCHORS={
0x145ac16b1:'MOVSS dword ptr [RBX + 0x20],XMM0',0x145ac1715:'MOVSS dword ptr [RBX + 0x24],XMM0',0x145ac1752:'MOVSS dword ptr [RBX + 0x28],XMM0',
0x1464ed309:'MOVSD qword ptr [RBX + 0xb10],XMM0',0x1464ed323:'MOVSD qword ptr [RBX + 0xb18],XMM0',0x1464ed33d:'MOVSD qword ptr [RBX + 0xb00],XMM0',0x1464ed359:'MOVSD qword ptr [RBX + 0xb08],XMM0',
0x1464ed413:'DIVSD XMM0,qword ptr [RBX + 0xb00]',0x1464ed41b:'MOVSD qword ptr [RBX + 0xb20],XMM0',0x1464ed423:'DIVSD XMM6,qword ptr [RBX + 0xb08]',0x1464ed42b:'MOVSD qword ptr [RBX + 0xb28],XMM6',
0x1464fcf07:'SUBSD XMM8,XMM6',0x1464fcf0f:'SUBSD XMM9,XMM7',0x1464fcf1b:'MULSD XMM8,qword ptr [RAX + 0xb28]',0x1464fcf24:'MULSD XMM9,qword ptr [RAX + 0xb20]'}
TABLES={'World':'c782ba8bd2c11a82382082da8a0e5487f4479d8605d795455cfc6e987f862c8c','Map':'a17dcb5015fa7e1fca8b052bd59d6d65bd077fcf40901719c70bb06e0749b7b4'}
def load(name,path=None):
 spec=importlib.util.spec_from_file_location(name.replace('-','_'),path or HERE/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def run():
 native,audit=load('build-native-entry-code'),load('audit-client-release');root=native.ROOT
 raw=(root/'client-code-snapshots'/SHA/'ProjectRED-Win64-Shipping.exe').read_bytes()
 if hashlib.sha256(raw).hexdigest()!=SHA:raise ValueError('Projection EXE changed')
 image=native.Image(raw);export=root/EXPORT
 if audit.sha256(export)!='6ca99ed560450f269f2e0f35c5d07d0d92f56a8e4022f3749d008419e36b3ea0':raise ValueError('Projection export changed')
 details=json.loads(export.read_text('utf-8'))
 if details['new_source_sha256']!=SHA:raise ValueError('Projection export source differs')
 rows={int(r['address'],16):r for f in details['functions'] for r in f['instructions']}
 for at,text in ANCHORS.items():
  row=rows[at];value=bytes.fromhex(row['bytes']);off=image.offset(at-image.pe.base)
  if row['text']!=text or raw[off:off+len(value)]!=value:raise ValueError('Projection instruction changed')
 literals=[]
 for at,target,text in ((0x145ac1693,0x1499dd6f0,'GroundDistance'),(0x145ac16f7,0x1490ed900,'CenterX'),(0x145ac1734,0x1490ed908,'CenterY')):
  row=rows[at];value=bytes.fromhex(row['bytes']);off=image.offset(at-image.pe.base);target_off=image.offset(target-image.pe.base)
  if raw[off:off+len(value)]!=value or at+7+struct.unpack_from('<i',value,3)[0]!=target or raw[target_off:target_off+len(text)+1]!=text.encode()+b'\0':raise ValueError('Projection field literal changed')
  literals.append(dict(address=hex(at),target=hex(target),text=text))
 index_path=root/INDEX
 if audit.sha256(index_path)!=index_path.parent.name:raise ValueError('Projection record index changed')
 index=json.loads(index_path.read_text('utf-8'));archive=Path(index['source']['path']);before=archive.stat()
 if audit.sha256(archive)!=index['source']['sha256'] or index['source']['sha256']!='15cf4f880170e87fc5fdea661cf9ba3d54a4f66c607844f5ab1047ed87f1e6a4':raise ValueError('Installed map archive changed')
 reader_path=HERE.parent/'rfnext/scan-pak.py';reader=load('projection_record_reader',reader_path)
 if audit.sha256(reader_path)!=index['dependencies']['reader_sha256'] or audit.sha256(reader.ROOT/'tools/oodle-data-shared.dll')!=index['dependencies']['oodle_sha256']:raise ValueError('Projection decoder changed')
 tables={};proof={}
 with archive.open('rb') as stream:
  for name,sha in TABLES.items():
   matches=[e for e in index['entries'] if e.get('decoded_sha256')==sha]
   if len(matches)!=1:raise ValueError('Map table must have unique exact content match')
   entry=matches[0];header=reader.header(stream,entry['offset'],index['index_offset'])
   if not header or header['end']!=entry['end']:raise ValueError('Map table record header differs')
   body=reader.decode(stream,header)
   if hashlib.sha256(body).hexdigest()!=sha:raise ValueError('Current map table bytes differ')
   tables[name]=list(csv.DictReader(io.StringIO(body.decode('utf-8-sig'))));proof[name]=dict(sha256=sha,entry=entry['entry'],offset=entry['offset'],rows=len(tables[name]))
 after=archive.stat()
 if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):raise ValueError('Archive changed during audit')
 maps={r['Id']:r for r in tables['Map']};world_rows={r['Id']:r for r in tables['World']}
 if len(maps)!=len(tables['Map']) or len(world_rows)!=len(tables['World']):raise ValueError('Duplicate map/world IDs')
 for key in ('10','11'):
  row=maps[key]
  if (row['MapResource'],row['GroundDistance'],row['CenterX'],row['CenterY'])!=('Field/Nocturne','615000','0','0'):raise ValueError('Nocturne parameters changed')
 projection_path=root/'maps/atlas/projection.json';projection=json.loads(projection_path.read_text('utf-8'))
 if (projection['map_ids'],projection['size'],projection['center'],projection['ground_distance'])!=(['10','11'],[10240,10240],[0,0],615000):raise ValueError('Atlas projection parameters differ')
 for old in projection['map_records']:
  if maps[old['Id']]!={k:v for k,v in old.items() if k!='provenance'}:raise ValueError('Atlas map record differs')
 report=dict(source_sha256=SHA,tool_sha256=audit.sha256(Path(__file__)),native_evidence=dict(path=str(export),sha256=audit.sha256(export)),anchors=[rows[a] for a in ANCHORS],literals=literals,
  record_index=dict(path=str(index_path),sha256=audit.sha256(index_path)),installed_archive=dict(path=str(archive),sha256=index['source']['sha256']),tables=proof,
  atlas_projection_sha256=audit.sha256(projection_path),map_ids=projection['map_ids'],size=projection['size'],center=projection['center'],ground_distance=projection['ground_distance'],
  worlds={r['Id']:r['MapId'] for r in tables['World'] if r['MapId'] in ('10','11')},
  limits=['Current static projection fields/math and two exact current table bodies; not full native widget execution.','Reuses existing atlas geometry; texture freshness, engine correction, pathing and live movement remain separate.','Only explicit Map10/11 worlds; no game IO or credentials.'])
 return audit.save_snapshot(root/'code-clues/map-projection-11316',report),report
if __name__=='__main__':
 p,r=run();print(json.dumps(dict(manifest=str(p),worlds=len(r['worlds']),world10012=r['worlds'].get('10012'))))
