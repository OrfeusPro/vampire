"""One disposable, time-limited analysis invocation. Never owns a game socket."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import uuid


def main():
    # New helpers/decoders must not inherit stale same-second .pyc files.
    sys.dont_write_bytecode=True
    sys.pycache_prefix=os.path.join(tempfile.gettempdir(),'phone-exit-observer',uuid.uuid4().hex)
    sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'vampir-shared'))
    path=Path(sys.argv[1]).resolve()
    source=path.read_bytes()
    if len(source)>1048576:raise ValueError('Handler source limit')
    revision=hashlib.sha256(source).hexdigest()
    payload=json.loads(sys.stdin.buffer.read(524289))
    # Redirect handler prints so the output protocol is bounded and independent.
    try:
        with open(os.devnull,'w') as sink,contextlib.redirect_stdout(sink),contextlib.redirect_stderr(sink):
            namespace={'__file__':str(path),'__name__':'live_observer'}
            sys.path.insert(0,str(path.parent))
            exec(compile(source,str(path),'exec'),namespace)
            values=namespace['analyze'](payload)
        if type(values) is not dict:raise ValueError('Handler must return a dictionary')
        result=dict(revision=revision,values=values,error=None)
        encoded=json.dumps(result,ensure_ascii=True,allow_nan=False)
        if len(encoded.encode())>16384:raise ValueError('Handler result limit')
    except Exception as error:
        result=dict(revision=revision,values={},error=type(error).__name__[:64])
        encoded=json.dumps(result)
    sys.stdout.write(encoded)


if __name__=='__main__':main()
