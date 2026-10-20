"""Install only pinned WebView2 host DLLs outside Git; no runtime/system changes."""
import hashlib
import io
import json
from pathlib import Path
import urllib.request
import zipfile

HERE = Path(__file__).resolve().parent


def install():
    lock = json.loads((HERE / 'webview2.lock.json').read_text('utf-8'))
    target = Path('F:/PhoneExit Resources/Vampir/tools/webview2') / lock['version']
    target.mkdir(parents=True, exist_ok=True)
    if all((target / name).is_file() and hashlib.sha256((target / name).read_bytes()).hexdigest() == digest
           for name, digest in lock['files'].items()):
        return target
    with urllib.request.urlopen(lock['url'], timeout=30) as response:
        data = response.read(20000000)
    if len(data) >= 20000000 or hashlib.sha256(data).hexdigest() != lock['sha256']:
        raise ValueError('WebView2 package hash differs')
    with zipfile.ZipFile(io.BytesIO(data)) as package:
        for name, digest in lock['files'].items():
            source = ('runtimes/win-x64/native/' if name == 'WebView2Loader.dll' else 'lib/net462/') + name
            content = package.read(source)
            if hashlib.sha256(content).hexdigest() != digest: raise ValueError('WebView2 DLL differs')
            (target / name).write_bytes(content)
    return target


if __name__ == '__main__': print(json.dumps(dict(directory=str(install()))))
