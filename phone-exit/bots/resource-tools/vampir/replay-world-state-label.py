"""Bind real World CSV LevelPath to native record/field/lookup/getter code."""
import csv
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('world_label_base',HERE/'replay-selection-state-lookup.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
native,x=base.native,base.x
CTOR,COPY,TABLE,GETTER=0x145c5c780,0x145c5d5a0,0x1499d28a8,0x141482e60
FIELD_BEGIN,FIELD_END=0x145c628bd,0x145c62906


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        self.world_fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in
            (CTOR,0x145c62130,0x145c5d390,0x145c5cca0)})
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.world_fragments)
        self.ranges.append((GETTER,GETTER+5))
        self.world_hooks={COPY}
        refs=[a for f in self.world_fragments for r in f['instructions'] for a in r['rip_references']]
        pages={p for begin,end in self.ranges for p in range(begin & ~4095,(end+4095) & ~4095,4096)}
        pages.update(a & ~4095 for a in (*refs,COPY,TABLE))
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=self.image.offset(page-self.image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,self.raw[off:off+4096])
        self.templates=[]

    def hook(self,uc,address,size,user):
        if address==COPY:
            a,b=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX)]
            data=bytes(uc.mem_read(b,0x140))
            if int.from_bytes(data[:8],'little')!=TABLE:raise ValueError('World record template vptr')
            # Bounded empty-template copy fixture. No populated FString copies.
            if any(data[o:o+16]!=bytes(16) for o in (0x18,0x28,0x38,0x48)):
                raise ValueError('World empty-template strings changed')
            uc.mem_write(a,data);self.templates.append(dict(vtable=TABLE,bytes_sha256=hashlib.sha256(data).hexdigest()))
            self.finish(a);return
        super().hook(uc,address,size,user)

    def execute_table(self,rows):
        self.heap=self.scratch+0x10000;self.events=[];self.templates=[]
        self.registry=self.ctx+0x1000
        self.uc.mem_write(self.ctx,bytes(0x10000))
        self.uc.mem_write(self.scratch+0x6000,bytes(0x1000))
        nodes=self.scratch+0x6000
        for index,row in enumerate(rows):
            node=nodes+index*0x150
            key,pair=self.scratch+0x1000,self.scratch+0x1100
            self.uc.mem_write(key,struct.pack('<I',int(row['Id'])))
            self.uc.mem_write(pair,struct.pack('<Q',key))
            self.run(CTOR,pair,node)
            self.uc.mem_write(node+0x148,struct.pack('<i',index+1 if index+1<len(rows) else -1))
            record=node+8
            # Actual CSV field storage instructions; preceding CSV/UTF conversion
            # supplies this temporary FString as an explicit source-data fixture.
            rbp=self.scratch+0x20000
            self.fwrite(rbp-0x30,row['LevelPath'])
            self.uc.reg_write(x.UC_X86_REG_RBP,rbp)
            self.uc.reg_write(x.UC_X86_REG_RBX,record)
            self.uc.reg_write(x.UC_X86_REG_RSP,self.scratch+0x30000)
            self.uc.emu_start(FIELD_BEGIN,FIELD_END,count=10000)
            if self.uc.reg_read(x.UC_X86_REG_RIP)!=FIELD_END:raise ValueError('World LevelPath assignment budget')
            if self.fread(record+0x48)!=row['LevelPath']:raise ValueError('World LevelPath field assignment')
        self.uc.mem_write(self.registry+0x18,struct.pack('<Q',nodes))
        self.uc.mem_write(self.registry+0x20,struct.pack('<I',len(rows)))
        self.uc.mem_write(self.registry+0x50,struct.pack('<i',0 if rows else -1))
        self.uc.mem_write(self.registry+0x60,struct.pack('<I',1))
        cases=[]
        for query in (1,2,3):
            output=self.scratch+0x4000
            self.uc.reg_write(x.UC_X86_REG_R8,query)
            self.run(base.LABEL,0,output)
            cases.append(dict(key=query,label=self.fread(output)))
        return dict(templates=self.templates.copy(),cases=cases)


def build():
    upstream=native.ROOT/'code-clues/selection-state-lookup-replay.json'
    prior=json.loads(upstream.read_text('utf-8'));em=Emulator()
    if prior['sha256']!=em.bindings['sha256']:raise ValueError('World state source mismatch')
    tables=[]
    for filename,indexname in (('pakchunk1-Windows-1568.csv','index-pakchunk1-Windows.json'),('ProjectRED-Windows-6200.csv','index.json')):
        folder=native.ROOT/'table-study';indexpath=folder/indexname
        index=json.loads(indexpath.read_text('utf-8'));record=next(r for r in index['tables'] if r['file']==filename)
        path=folder/filename;raw=path.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=record['sha256']:raise ValueError('World CSV no longer matches extraction index')
        if filename.startswith('pakchunk1-'):
            # The historical CSV survived unchanged, but the archive was updated.
            # Use the existing audited release snapshot, never its old offset.
            snapshot='430a1b516df976ee6b1accfc93c7386f9ac95c66480ce0cf5c56888acfd03ea8'
            candidates=list((native.ROOT/'release-snapshots').glob('*/record-indexes/*/*/table-snapshots/'+snapshot+'/manifest.json'))
            if len(candidates)!=1:raise ValueError('Pinned current table snapshot missing/ambiguous')
            indexpath=candidates[0]
            if hashlib.sha256(indexpath.read_bytes()).hexdigest()!=snapshot:raise ValueError('Current table snapshot hash mismatch')
            current=json.loads(indexpath.read_text('utf-8'))
            matches=[r for r in current['tables'] if r['sha256']==record['sha256'] and filename in r['identical_previous_files']]
            if len(matches)!=1:raise ValueError('World table requires exact current content match')
            record=dict(matches[0],source=current['source']);path=Path(record['file'])
            if path.read_bytes()!=raw:raise ValueError('Current World CSV byte parity mismatch')
        source=record['source'];archive=Path(source['path'])
        before=archive.stat()
        with archive.open('rb') as stream:
            head=stream.read(65536);stream.seek(max(0,before.st_size-65536));tail=stream.read()
        if before.st_size!=source['size'] or hashlib.sha256(head+tail).hexdigest()!=source['sample_sha256']:
            raise ValueError('World archive changed; refresh audited release tables')
        with archive.open('rb') as stream:archive_sha256=hashlib.file_digest(stream,'sha256').hexdigest()
        if source.get('sha256') and archive_sha256!=source['sha256']:raise ValueError('Current World archive full SHA mismatch')
        with path.open(encoding='utf-8-sig',newline='') as f:
            reader=csv.DictReader(f);header=reader.fieldnames;selected=[r for r in reader if r['Id'] in ('1','2')]
        if header[3]!='LevelPath' or [r['Id'] for r in selected]!=['1','2']:raise ValueError('World row/header identity changed')
        tables.append(dict(index=str(indexpath),index_sha256=hashlib.sha256(indexpath.read_bytes()).hexdigest(),
            current_archive_sha256=archive_sha256,current_archive_matches_extraction=True,
            extraction=record,header=header,rows=selected,execution=em.execute_table(selected)))
    tableoff=em.image.offset(TABLE-em.image.pe.base);table=em.raw[tableoff:tableoff+0x70]
    if struct.unpack_from('<Q',table,0x20)[0]!=GETTER:raise ValueError('World label getter slot changed')
    getteroff=em.image.offset(GETTER-em.image.pe.base);getter=em.raw[getteroff:getteroff+5]
    if getter!=bytes.fromhex('488d4148c3'):raise ValueError('World getter no longer returns FString48')
    rows={r['address']:r for f in em.world_fragments for r in f['instructions']}
    column=rows[0x145c6230f]
    if column['rip_references']!=[0x1499d2c10]:raise ValueError('World LevelPath literal reference changed')
    literaloff=em.image.offset(0x1499d2c10-em.image.pe.base)
    literal=em.raw[literaloff:literaloff+10]
    if literal!=b'LevelPath\0':raise ValueError('World native column name changed')
    if rows[0x145c628c1]['operands']!='rdi, [rbx + 0x48]' or rows[0x145c6290c]['operands']!='qword ptr [rax + 0x68]':
        raise ValueError('World LevelPath native field boundary changed')
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),upstream_sha256=hashlib.sha256(upstream.read_bytes()).hexdigest(),
        fragments=em.world_fragments,table=dict(address=TABLE,file_offset=tableoff,bytes=table.hex()),
        getter=dict(address=GETTER,file_offset=getteroff,bytes=getter.hex()),
        column_literal=dict(address=0x1499d2c10,file_offset=literaloff,bytes=literal.hex(),reference=column),tables=tables,
        native_execution=True,source_row2_label_verified=True,live_registry_population_verified=False,network_ready=False,
        limitations=['Actual World record constructor, LevelPath storage block, hash/accessor/label caller/virtual20 getter execute.',
            'Empty record-copy, FString temp/resize/copy and registry getter/storage allocation are fixtures; full CSV parser/insertion not executed.',
            'Real indexed CSV rows from base and patch are inputs; runtime mount priority/actual registry population not proved.',
            'Field assignment block starts after UTF-8 conversion, ends before field hook; source parser fragments retained.',
            'Source row2 label known, but world-load lifecycle/slot90 call/network/response102/session/game/Android unverified.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/world-state-label-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),tables=len(report['tables']))))
