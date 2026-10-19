"""Download official pinned offline-analysis tools; no system Java/PATH changes."""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import urllib.request
import zipfile

HERE=Path(__file__).resolve().parent
ROOT=Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES','F:/PhoneExit Resources/Vampir'))


def install(name,entry):
    root=ROOT/'tools/ghidra';root.mkdir(parents=True,exist_ok=True)
    archive=root/(name+'-'+entry['version'].replace('+','_')+'.zip')
    if not archive.exists():
        part=archive.with_suffix('.part')
        with urllib.request.urlopen(entry['url'],timeout=90) as response,part.open('wb') as out:
            while data:=response.read(1024*1024):out.write(data)
        with part.open('rb') as source:digest=hashlib.file_digest(source,'sha256').hexdigest()
        if digest!=entry['sha256']:
            raise ValueError('Downloaded '+name+' hash mismatch; partial file preserved')
        part.replace(archive)
    with archive.open('rb') as source:digest=hashlib.file_digest(source,'sha256').hexdigest()
    if digest!=entry['sha256']:raise ValueError('Cached '+name+' hash mismatch')
    target=root/entry['directory']
    marker=target/'.phoneexit-verified.json'
    if not marker.exists():
        with zipfile.ZipFile(archive) as z:
            for member in z.infolist():
                resolved=(root/member.filename).resolve()
                if not resolved.is_relative_to(target.resolve()):raise ValueError('Archive path escapes pinned tool directory')
            z.extractall(root)
        marker.write_text(json.dumps(entry,indent=2)+'\n',encoding='utf-8')
    elif json.loads(marker.read_text('utf-8'))!=entry:raise ValueError('Tool installation marker mismatch')
    print(json.dumps(dict(tool=name,path=str(target),sha256=digest)),flush=True)


if __name__=='__main__':
    lock=json.loads((HERE/'ghidra-tools.lock.json').read_text('utf-8'))
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures=[pool.submit(install,name,lock[name]) for name in ('ghidra','jdk')]
        for future in futures:future.result()
