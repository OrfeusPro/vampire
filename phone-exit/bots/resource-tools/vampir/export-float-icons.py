"""Decode missing item icon PF_FloatRGBA pixels without changing original catalogs.

Keep both direct and linear-to-sRGB previews: Android color conversion unverified.
"""
import collections
import csv
import hashlib
import io
import json
import os
import re
import struct
from pathlib import Path

import numpy as np
from PIL import Image

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))


def decode(data):
    pos = data.find(b'PF_FloatRGBA\0')
    if pos < 16:
        raise ValueError('No FloatRGBA header')
    w,h,slices = struct.unpack_from('<iii', data, pos-16)
    if not 1 <= w <= 2048 or not 1 <= h <= 2048 or slices != 1:
        raise ValueError('Unexpected float icon dimensions')
    count = w*h*8
    end = data.find(struct.pack('<iii',w,h,1),pos+16+count)
    start = end-count
    if end < 0 or start < pos+16:
        raise ValueError('Missing complete first mip')
    raw = data[start:end]
    values = np.frombuffer(raw,dtype='<f2').reshape(h,w,4).astype(np.float32)
    if not np.isfinite(values).all() or values.min() < 0 or values.max() > 1:
        raise ValueError('HDR/out-of-range icon requires separate rendering research')
    direct = np.round(values*255).astype(np.uint8)
    rgb = values[:,:,:3]
    converted = np.where(rgb <= .0031308,12.92*rgb,1.055*np.power(rgb,1/2.4)-.055)
    srgb = direct.copy()
    srgb[:,:,:3] = np.round(np.clip(converted,0,1)*255).astype(np.uint8)
    return direct,srgb,dict(width=w,height=h,mip_offset=start,encoded_pixel_sha256=hashlib.sha256(raw).hexdigest())


def main():
    ts=json.loads((ROOT/'table-study/index-pakchunk1-Windows.json').read_text('utf-8'))['tables']
    meta=next(t for t in ts if t['entry']==194)
    data=(ROOT/'table-study'/meta['file']).read_bytes()
    if hashlib.sha256(data).hexdigest()!=meta['sha256']:
        raise ValueError('Item CSV changed')
    items=list(csv.DictReader(io.StringIO(data.decode('utf-8-sig'),newline='')))
    existing=json.loads((ROOT/'archive-image-latest.json').read_text('utf-8'))
    present={r['asset_path'].rsplit('/',1)[-1] for r in existing}
    wanted={r['Img'] for r in items if r['Img'] and r['Img'] not in present}
    out=ROOT/'item-icons-float';out.mkdir(exist_ok=True)
    records=[];errors=[]
    for folder in sorted((ROOT/'pak-extracted').iterdir()):
        index=folder/'entries.json'
        if not index.is_file():continue
        entries=json.loads(index.read_text('utf-8'))
        for i,owner in enumerate(entries[:-1]):
            if not owner.get('uasset') or not owner.get('paths'):continue
            paths=[p for p in owner['paths'] if p.rsplit('/',1)[-1] in wanted]
            row=entries[i+1]
            if not paths or 'PF_FloatRGBA' not in row.get('pixel_formats',[]):continue
            path=collections.Counter(paths).most_common(1)[0][0]
            try:
                original=Path(row['saved']).read_bytes();direct,srgb,details=decode(original)
                stem=hashlib.sha256((path+folder.name).encode()).hexdigest()[:16]
                png=out/(stem+'.png');rawpng=out/(stem+'-direct.png')
                Image.fromarray(srgb).save(png);Image.fromarray(direct).save(rawpng)
                match=re.search(r'_s(\d+)-Windows',folder.name)
                records.append(dict(asset_path=path,file=png.relative_to(ROOT).as_posix(),
                    direct_file=rawpng.relative_to(ROOT).as_posix(),sha256=hashlib.sha256(png.read_bytes()).hexdigest(),
                    source=folder.name+'.pak',entry=row['entry'],offset=row['offset'],uasset_entry=owner['entry'],
                    uexp_sha256=hashlib.sha256(original).hexdigest(),
                    uasset_sha256=hashlib.sha256(Path(owner['saved']).read_bytes()).hexdigest(),
                    format='PF_FloatRGBA',patch=int(match[1]) if match else 0,**details,
                    rendering='RGBA16F: linear-to-sRGB preview; direct preview also retained',color_verified=False))
            except ValueError as error:errors.append(dict(asset_path=path,source=folder.name,error=str(error)))
    report=dict(images=records,errors=errors,item_source=meta,
        limitation='Byte decoding verified; Unreal/Android color-space setting not recovered. Preview is not evidence of in-game color match.')
    (out/'index.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(dict(images=len(records),unique_assets=len({r['asset_path'] for r in records}),errors=len(errors)),ensure_ascii=False))


if __name__=='__main__':main()
