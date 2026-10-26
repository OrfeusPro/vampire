"""Explicit Windows breakaway launch with bounded anonymous-pipe handoff."""
import json
import os
from queue import Queue
import subprocess
from threading import Thread

MAX_INPUT=1048576
MAX_READY=65536


def launch_detached(command,payload,*,cwd=None,timeout=15):
    if os.name!='nt':raise OSError('Windows breakaway launch required')
    if type(payload) is not dict:raise ValueError('Explicit worker payload required')
    data=json.dumps(payload,ensure_ascii=False,allow_nan=False,separators=(',',':')).encode('utf-8')
    if len(data)>MAX_INPUT:raise ValueError('Worker input limit exceeded')
    # A plain detached console can still belong to the caller's kill-on-close
    # job. BREAKAWAY must succeed; there is deliberately no weaker fallback.
    flags=subprocess.DETACHED_PROCESS|subprocess.CREATE_NEW_PROCESS_GROUP|subprocess.CREATE_BREAKAWAY_FROM_JOB
    process=subprocess.Popen(command,cwd=cwd,creationflags=flags,
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    output=Queue(maxsize=1)
    def read_ready():
        try:output.put(process.stdout.readline(MAX_READY+1))
        except OSError:output.put(b'')
    reader=Thread(target=read_ready,name='detached-ready',daemon=True)
    reader.start()
    write_errors=[]
    def deliver(frame):
        try:process.stdin.write(frame)
        except OSError:write_errors.append(True)
        finally:
            try:process.stdin.close()
            except OSError:pass
    writer=Thread(target=deliver,args=(data,),name='detached-input',daemon=True)
    writer.start()
    try:
        writer.join(timeout)
        if writer.is_alive():raise TimeoutError('Worker input timed out')
        if write_errors:raise RuntimeError('Worker input failed')
        data=None
        reader.join(timeout)
        if reader.is_alive():raise TimeoutError('Worker readiness timed out')
        line=output.get_nowait()
        if not line.endswith(b'\n') or len(line)>MAX_READY:raise RuntimeError('Invalid worker readiness')
        try:ready=json.loads(line)
        except (ValueError,UnicodeError):raise RuntimeError('Invalid worker readiness') from None
        if type(ready) is not dict or ready.get('status')!='ready' or ready.get('pid')!=process.pid:
            raise RuntimeError('Worker startup failed')
        if process.poll() is not None:raise RuntimeError('Worker exited during startup')
        return ready
    except BaseException:
        if process.poll() is None:
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
        raise
    finally:
        data=None
        if process.stdin and not process.stdin.closed:process.stdin.close()
        process.stdout.close()


def receive_handoff(stream):
    data=stream.read(MAX_INPUT+1)
    if len(data)>MAX_INPUT:raise ValueError('Worker input limit exceeded')
    value=json.loads(data.decode('utf-8'))
    if type(value) is not dict:raise ValueError('Invalid worker handoff')
    return value


def ready_channel():
    """Keep one startup pipe, then silence stdout before any worker diagnostics."""
    duplicate=os.dup(1)
    with open(os.devnull,'wb') as sink:os.dup2(sink.fileno(),1)
    def send(value):
        nonlocal duplicate
        if duplicate is None:raise RuntimeError('Readiness was already sent')
        frame=json.dumps(value,ensure_ascii=False,allow_nan=False,separators=(',',':')).encode('utf-8')+b'\n'
        try:
            if len(frame)>MAX_READY:raise ValueError('Worker readiness limit exceeded')
            with os.fdopen(duplicate,'wb',buffering=0) as pipe:
                duplicate=None
                at=0
                while at<len(frame):
                    written=pipe.write(frame[at:])
                    if not written:raise OSError('Readiness pipe closed')
                    at+=written
        finally:
            if duplicate is not None:os.close(duplicate);duplicate=None
    return send
