"""Verify recipe ID -> material GroupId and CostType=Item parameter lookup in client UI."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent


def main():
    spec=importlib.util.spec_from_file_location('craft_native',HERE/'build-native-entry-code.py')
    n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
    source=json.loads((n.ROOT/'code-clues/native-enums.json').read_text('utf-8'))
    d=Path(source['source']).read_bytes()
    if hashlib.sha256(d).hexdigest()!=source['sha256'] or n.capstone.__version__!='5.0.6':
        raise ValueError('Changed client or decoder')
    costs={r['value']:r for r in source['enums']['ECostType']}
    if costs[1]['name']!='ECostType::Asset' or costs[2]['name']!='ECostType::Item':
        raise ValueError('Changed cost type names')
    im=n.Image(d)
    addresses=[0x145a68ca0,0x145a69980,0x145a5e510,0x145a56690,0x145a56750,0x145a565d0,
               0x145a5e490,0x145dd6920,0x146335060,0x14634b4e0]
    fragments=n.decode_ranges(im,{im.roots[im.containing(a)] for a in addresses})
    rows={r['address']:r for f in fragments for r in f['instructions']};anchors=[];blobs=[]
    def check(a,m,o):
        r=rows[a]
        if (r['mnemonic'],r['operands'])!=(m,o):raise ValueError('Changed craft anchor '+hex(a))
        anchors.append(r)
    def blob(a,b,role):
        off=im.offset(a-im.pe.base)
        if d[off:off+len(b)]!=b:raise ValueError('Changed craft data '+role)
        blobs.append(dict(address=a,file_offset=off,bytes=b.hex(),role=role))
    def literal(a,text):
        r=rows[a]
        if r['mnemonic']!='lea':raise ValueError('Expected literal LEA')
        blob(r['rip_references'][0],(text+'\0').encode('utf-16le' if text.startswith('Craft/') else 'ascii'),text);anchors.append(r)
    for a,text in [(0x145a69a51,'ItemCraftMaterial.csv'),(0x145a69aea,'FRdItemCraftMaterialInfoManagerTemplate::Load'),
                   (0x145a69b51,'GroupId'),(0x145a69b6c,'CostType'),(0x145a69b7a,'UsingGroupId'),
                   (0x145a69b88,'CostParam'),(0x145a69b96,'CostValue'),(0x145a69ba4,'CostEnchantLevel'),(0x145a68d67,'ItemCraft.csv'),
                   (0x14634b6ab,'Craft/WBP_ItemCraftMaterialT')]:literal(a,text)
    for a,m,o in [
        (0x145a699ea,'lea','r12, [rbx + 0x60]'),
        (0x145a69db8,'movzx','edx, word ptr [rbp + 0x192]'),(0x145a69dc3,'call','0x1445ef9f0'),
        (0x145a69dce,'mov','dword ptr [rsi + 0xc], eax'),
        (0x145a69dd4,'movzx','edx, word ptr [rbp + 0x194]'),(0x145a69ddf,'call','0x1445efb80'),
        (0x145a69de4,'mov','byte ptr [rsi + 0x10], al'),
        (0x145a69fbb,'lea','rbx, [rsi + 0x18]'),(0x145a6a033,'movzx','edx, word ptr [rbp + 0x19a]'),
        (0x145a6a043,'mov','dword ptr [rsi + 0x28], eax'),(0x145a6a05f,'mov','byte ptr [rsi + 0x2c], al'),
        (0x145a6a3df,'mov','r8d, dword ptr [rdi + 0x14]'),(0x145a6a3e3,'mov','dword ptr [rsp + 0x40], r8d'),
        (0x145a6a42a,'cmp','dword ptr [rcx], r8d'),(0x145a6a460,'call','0x1421e0010'),
        (0x145a6a474,'lea','rbx, [rcx + 8]'),(0x145a6a478,'lea','rsi, [rdi + 8]'),
        (0x145a6a49d,'mov','qword ptr [rax + rdi*8], rsi'),
        (0x145a5e539,'lea','rax, [rip + 0x56f3b50]'),
        (0x145a566aa,'call','0x145a5e510'),(0x145a566af,'mov','r9d, dword ptr [rbx]'),
        (0x145a566e8,'mov','rdx, qword ptr [r8 + 0x68]'),(0x145a566f7,'cmp','dword ptr [rcx + rdx], r9d'),
        (0x145a56722,'lea','rax, [rax + 8]'),(0x145a5672f,'mov','qword ptr [rdi], rax'),
        (0x145a565e1,'call','0x145a5e490'),(0x145a565eb,'call','0x145a5dc20'),
        (0x145a5e4b9,'lea','rax, [rip + 0x56f3b10]'),
        (0x145dd6959,'mov','edx, ecx'),(0x145dd695b,'mov','dword ptr [rbp - 0x71], ecx'),
        (0x145dd6962,'call','0x145a565d0'),(0x145dd696b,'call','0x141482990'),
        (0x145dd6973,'je','0x145dd6c38'),(0x145dd6a0d,'lea','rdx, [rbp - 0x71]'),
        (0x145dd6a15,'call','0x145a56690'),(0x145dd6a30,'call','0x1414fa960'),
        (0x145dd6a35,'mov','r15, qword ptr [rax]'),(0x145dd6a3c,'lea','r12, [r15 + rax*8]'),
        (0x145a56761,'call','0x145a5e510'),(0x145a56769,'mov','r9, rax'),
        (0x146335104,'call','0x145a56750'),(0x14633513f,'call','0x141482990'),
        (0x146335144,'movzx','ecx, byte ptr [rax + 0x10]'),(0x146335148,'sub','ecx, 1'),
        (0x14633514b,'je','0x146335a40'),(0x146335151,'cmp','ecx, 1'),(0x146335154,'jne','0x146335a13'),
        (0x146335171,'mov','rcx, qword ptr [rax + 0x18]'),
        (0x14633517a,'call','qword ptr [rip + 0x2610a30]'),(0x146335180,'mov','edx, eax'),
        (0x14633518c,'call','0x145a80590'),(0x146335195,'call','0x141482990'),
        (0x1463351c7,'call','0x146370b50'),(0x1463351e0,'movsx','edx, byte ptr [rax + 0x2c]')]:check(a,m,o)
    for a,p,role in [(0x14b152098,0x1499834d0,'material manager secondary vtable'),
                     (0x149983508,0x145a69980,'material loader slot'),
                     (0x14b151fd8,0x1499825e0,'recipe manager secondary vtable'),
                     (0x149982618,0x145a68ca0,'recipe loader slot')]:blob(a,struct.pack('<Q',p),role)
    blob(0x1414fa960,bytes.fromhex('488b01c3'),'group handle pointer getter')
    blob(0x141482990,bytes.fromhex('488b4108c3'),'record handle pointer getter')
    off=im.offset(0x145a5dc20-im.pe.base);leaf=d[off:off+0x6c]
    if hashlib.sha256(leaf).hexdigest()!='4809ded6e5801dffc1a70d3de13ef885f496096f537c7da257008d78e254d3d2':
        raise ValueError('Changed exact recipe ID lookup leaf')
    blob(0x145a5dc20,leaf,'full recipe ID lookup through final branch and ret')
    book_path=n.ROOT/'code-clues/item-skill-binding.json';book=json.loads(book_path.read_text('utf-8'))
    if book['sha256']!=source['sha256']:raise ValueError('Changed Item table proof')
    for row in book['anchors']+book['data_anchors']:
        off=row['file_offset'];b=bytes.fromhex(row['bytes'])
        if d[off:off+len(b)]!=b:raise ValueError('Changed Item lookup dependency')
    spec=importlib.util.spec_from_file_location('craft_import',HERE/'build-object-zero-init-code.py')
    imports=importlib.util.module_from_spec(spec);spec.loader.exec_module(imports)
    conversion=imports.import_at(d,im,0x148945bb0)
    if conversion['name']!='_wtoi':raise ValueError('Changed material ID conversion')
    report=dict(source=source['source'],sha256=source['sha256'],anchors=anchors,data_anchors=blobs,fragments=fragments,
        conversion_import=conversion,item_lookup_dependency=dict(file='code-clues/item-skill-binding.json',sha256=hashlib.sha256(book_path.read_bytes()).hexdigest()),
        relation='ItemCraft.Id = ItemCraftMaterial.GroupId; CostType=2 Item: complete positive CostParam -> Item.Id',
        relation_verified=True,item_target_verified=True,runtime_cost_enforcement_verified=False,cost_types=costs,
        limitations=['All material rows retained; UsingGroupId combination and server availability unverified.',
                     'Raw CostValue and CostEnchantLevel retained; no multiplication, summation or inferred defaults.',
                     'Only complete positive int32 item IDs accepted; other cost types retained as raw.'])
    path=n.ROOT/'code-clues/craft-material-binding.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(anchors=len(anchors),data_anchors=len(blobs),sha256=hashlib.sha256(path.read_bytes()).hexdigest())))


if __name__=='__main__':main()
