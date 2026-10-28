"""User-started Windows update owner. No game IO, login or automatic Windows start."""
import argparse
from contextlib import contextmanager
from contextlib import redirect_stdout
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import secrets
import re
import subprocess
import sys
import time
from types import SimpleNamespace

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parents[1]/'vampir-shared'))
POLL_SECONDS=15
QUIET_SECONDS=120
MAX_EVENT_LOG=2*1024*1024
EVENT_TAIL=64*1024
RETAIN_RUNS=20


class EventLog:
    """Bounded updater stdout only; never receives game traffic or credentials."""
    def __init__(self,path,limit=MAX_EVENT_LOG):
        self.path=Path(path);self.limit=limit
    def write(self,text):
        data=text.encode('utf-8',errors='replace')
        self.path.parent.mkdir(parents=True,exist_ok=True)
        with self.path.open('a+b') as stream:
            stream.seek(0,2)
            if stream.tell()+len(data)>self.limit:
                keep=max(0,self.limit-len(data))
                if keep:
                    stream.seek(max(0,stream.tell()-keep));old=stream.read(keep)
                    # A rotation may discard the first incomplete JSON line.
                    old=old.split(b'\n',1)[-1] if b'\n' in old else b''
                else:old=b''
                stream.seek(0);stream.truncate();stream.write(old)
            stream.write(data[-self.limit:])
        return len(text)
    def flush(self):pass


def last_phase(folder,state):
    filename=state.get('event_log')
    if not filename:return None
    path=Path(filename).resolve()
    if path.parent!=folder.resolve() or not path.name.startswith('result-') or path.suffixes[-2:]!=['.events','.jsonl']:
        raise ValueError('Watcher event log outside owner directory')
    if not path.is_file():return None
    with path.open('rb') as stream:
        stream.seek(max(0,path.stat().st_size-EVENT_TAIL));raw=stream.read(EVENT_TAIL)
    for line in reversed(raw.decode('utf-8',errors='replace').splitlines()):
        if len(line)>16384:continue
        try:value=json.loads(line)
        except ValueError:continue
        if isinstance(value,dict) and value.get('event'):
            return {key:value[key] for key in ('event','stage','state','seconds') if key in value}
    return None


def retain_results(folder,current):
    # Only this wrapper's fixed result basename is eligible for cleanup.
    results=sorted((p for p in folder.glob('result-*.json') if re.fullmatch(r'result-[0-9a-f]{24}\.json',p.name)),
        key=lambda p:p.stat().st_mtime_ns,reverse=True)
    keep={Path(current).resolve(),*(p.resolve() for p in results[:RETAIN_RUNS-1])}
    for path in results:
        if path.resolve() in keep:continue
        path.with_suffix('.events.jsonl').unlink(missing_ok=True)
        path.unlink()


def load_index():
    import importlib.util
    spec=importlib.util.spec_from_file_location('update_watch_index',HERE/'knowledge-index.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module.api()


def process_creation(pid):
    """PID reuse cannot authorize ownership of an unrelated process."""
    if os.name!='nt':
        try:return Path('/proc') .joinpath(str(pid),'stat').read_text().rsplit(')',1)[1].split()[19]
        except (OSError,IndexError):return None
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
    kernel.OpenProcess.restype=wintypes.HANDLE
    kernel.GetProcessTimes.argtypes=[wintypes.HANDLE,*([ctypes.POINTER(wintypes.FILETIME)]*4)]
    kernel.GetProcessTimes.restype=wintypes.BOOL
    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    handle=kernel.OpenProcess(0x1000,False,pid)
    if not handle:return None
    try:
        values=[wintypes.FILETIME() for _ in range(4)]
        if not kernel.GetProcessTimes(handle,*[ctypes.byref(v) for v in values]):return None
        return str((values[0].dwHighDateTime<<32)|values[0].dwLowDateTime)
    finally:kernel.CloseHandle(handle)


def alive(owner):
    return (isinstance(owner,dict) and type(owner.get('pid')) is int and owner.get('creation_time') is not None
        and process_creation(owner['pid'])==owner['creation_time'])


def folder_for(args):
    # Current user's LocalAppData has the user's ACL. The install hash isolates
    # independent installations; no credentials or game traffic are stored here.
    base=Path(os.environ.get('LOCALAPPDATA',str(Path.home()/'.local/share')))/'PhoneExit/Vampir/update-watch'
    return base/hashlib.sha256(str(Path(args.install).resolve()).casefold().encode()).hexdigest()[:24]


def read_state(index,folder):
    path=folder/'state.json'
    if not path.is_file():return dict(state='not_started',owner=None)
    value=index.read_json(path)
    if value.get('schema')!=1:raise ValueError('Invalid update watcher state')
    return value


def save_state(index,folder,state):
    index.extension('research-workflow').atomic(folder/'state.json',
        index.extension('update-auto').canonical(dict(schema=1,**state)))


@contextmanager
def owner_lock(folder):
    folder.mkdir(parents=True,exist_ok=True)
    with (folder/'owner.lock').open('a+b',buffering=0) as stream:
        if os.fstat(stream.fileno()).st_size==0:stream.write(b'0')
        stream.seek(0)
        try:
            if os.name=='nt':
                import msvcrt
                msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError:raise ValueError('Наблюдатель этой установки уже запущен') from None
        try:yield
        finally:
            stream.seek(0)
            if os.name=='nt':msvcrt.locking(stream.fileno(),msvcrt.LK_UNLCK,1)
            else:fcntl.flock(stream.fileno(),fcntl.LOCK_UN)


def definition_hint(index,knowledge):
    return index.extension('update-auto').fingerprint(index.extension('update-auto').definition_inputs(index,knowledge))


class Trigger:
    """Stability/attempt policy independent of the process launcher."""
    def __init__(self,quiet=QUIET_SECONDS):
        self.quiet=quiet;self.observed=None;self.changed_at=None;self.attempted=None;self.retry=False

    def request_retry(self):self.retry=True

    def observe(self,identity,definitions,now):
        key=(identity,definitions)
        if identity!=self.observed:self.observed=identity;self.changed_at=now
        if now-self.changed_at<self.quiet:return 'waiting_for_install'
        if self.retry or key!=self.attempted:
            self.attempted=key;self.retry=False;return 'run'
        return 'unchanged'


def queued_commands(index,folder,token):
    commands=[]
    paths=sorted(p for p in folder.glob('command-*.json') if re.fullmatch(r'command-[0-9a-f]{24}\.json',p.name))
    if len(paths)>128:raise ValueError('Watcher command budget exceeded')
    for path in paths:
        try:
            value=index.read_json(path)
            if value.get('start_token')==token and value.get('action') in ('stop','retry'):commands.append(value['action'])
        finally:path.unlink(missing_ok=True)
    return commands


def child_command(args,result):
    return [sys.executable,'-X','utf8',str(Path(__file__).resolve()),'--update-worker',
        '--root',str(args.root),'--knowledge',str(args.knowledge),'--install',str(args.install),
        '--result',str(result)]


def watch(index,args,*,ready=None,stop_after=None,clock=time.monotonic,sleep=time.sleep,launcher=subprocess.Popen):
    folder=folder_for(args)
    with owner_lock(folder):
        previous=read_state(index,folder)
        child_owner=previous.get('child')
        if alive(child_owner):raise ValueError('Прежний update worker ещё жив; новый не запускается')
        token=secrets.token_hex(32)
        owner=dict(pid=os.getpid(),creation_time=process_creation(os.getpid()),start_token=token)
        if owner['creation_time'] is None:raise ValueError('Cannot establish watcher process identity')
        state=dict(state='watching',owner=owner,child=None,poll_seconds=POLL_SECONDS,quiet_seconds=QUIET_SECONDS,
            install=str(args.install.resolve()),root=str(args.root.resolve()),last_result=previous.get('last_result'),
            event_log=previous.get('event_log'),
            attempted_identity=previous.get('attempted_identity'),attempted_definitions=previous.get('attempted_definitions'),
            network_attempted=False,game_session_changed=False)
        save_state(index,folder,state)
        if ready:ready(dict(status='ready',pid=os.getpid(),creation_time=owner['creation_time'],state_file=str(folder/'state.json')))
        trigger=Trigger()
        if state['attempted_identity'] is not None:
            trigger.attempted=(state['attempted_identity'],state['attempted_definitions'])
        child=None;result_path=None;draining=False;started=clock()
        try:
            while True:
                for command in queued_commands(index,folder,token):
                    if command=='stop':draining=True
                    else:trigger.request_retry()
                if stop_after is not None and clock()-started>=stop_after:draining=True
                if child is not None:
                    if child.poll() is None:
                        state['state']='draining' if draining else 'updating'
                    else:
                        if result_path.is_file():
                            state['last_result']=index.read_json(result_path)
                        else:state['last_result']=dict(state='failed',reason='update_worker_no_result',returncode=child.returncode)
                        state['child']=None;child=None
                        state['state']='needs_review' if state['last_result'].get('state') not in ('prepared_offline','planned') else 'watching'
                if draining and child is None:break
                if not draining and child is None:
                    try:
                        auto=index.extension('update-auto')
                        # A baseline supplies extra Engine archive directories.
                        _,baseline=auto.select_baseline(index,args)
                        roots={Path(row['path']).parent for row in baseline['files']}
                        hint=auto.fingerprint(auto.inventory(index,args.install,roots))
                        definitions=definition_hint(index,args.knowledge)
                        decision=trigger.observe(hint,definitions,clock())
                        if decision=='run':
                            # A failed/needs_review run is not retried with the
                            # same inputs. Only a new identity/definition/retry.
                            result_path=folder/('result-'+secrets.token_hex(12)+'.json')
                            retain_results(folder,result_path)
                            child=launcher(child_command(args,result_path),cwd=str(HERE.parents[3]),
                                stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                                creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                            creation=process_creation(child.pid)
                            if creation is None:
                                child.wait(timeout=5)
                                raise ValueError('Update worker identity unavailable')
                            state.update(state='updating',child=dict(pid=child.pid,creation_time=creation,start_token=secrets.token_hex(32)),
                                attempted_identity=hint,attempted_definitions=definitions,
                                event_log=str(result_path.with_suffix('.events.jsonl')))
                        elif decision=='waiting_for_install':state['state']=decision
                    except (OSError,ValueError) as error:
                        trigger.observed=None
                        state.update(state='waiting_for_install',reason=str(error)[:512])
                save_state(index,folder,state)
                sleep(POLL_SECONDS)
        finally:
            # Stop drains the owned update, including its Ghidra descendants.
            # There is no game-owner shutdown and no blind stale-lock deletion.
            if child is not None and child.poll() is None:
                state['state']='draining';save_state(index,folder,state)
                child.wait()
            state.update(state='stopped',child=None)
            save_state(index,folder,state)
        return state


def control(index,args):
    folder=folder_for(args);state=read_state(index,folder)
    running=alive(state.get('owner'))
    if args.action=='status':
        public={**state}
        for name in ('owner','child'):
            if public.get(name):public[name]={k:v for k,v in public[name].items() if k!='start_token'}
        return dict(public,owner_alive=running,child_alive=alive(state.get('child')),current_phase=last_phase(folder,state))
    if args.action in ('stop','retry'):
        if not running:return dict(state='not_running',action=args.action,game_session_changed=False)
        folder.mkdir(parents=True,exist_ok=True)
        path=folder/('command-'+secrets.token_hex(12)+'.json')
        index.extension('research-workflow').atomic(path,index.extension('update-auto').canonical(
            dict(action=args.action,start_token=state['owner']['start_token'])))
        return dict(state='stop_requested' if args.action=='stop' else 'retry_requested',
            draining=bool(state.get('child')),game_session_changed=False)
    if running:return dict(state='already_running',owner={k:v for k,v in state['owner'].items() if k!='start_token'},game_session_changed=False)
    from vampir_core.scheduled_worker import launch_scheduled
    ready=launch_scheduled([sys.executable,'-X','utf8',str(Path(__file__).resolve()),'--watch-worker'],
        dict(root=str(args.root.resolve()),knowledge=str(args.knowledge.resolve()),install=str(args.install.resolve())),
        cwd=str(HERE.parents[3]),unlimited=True)
    return dict(ready,game_session_changed=False,windows_autostart=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    modes=parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--watch-worker',action='store_true');modes.add_argument('--update-worker',action='store_true')
    parser.add_argument('--root',type=Path);parser.add_argument('--knowledge',type=Path)
    parser.add_argument('--install',type=Path);parser.add_argument('--result',type=Path)
    args=parser.parse_args();index=load_index()
    if args.watch_worker:
        from vampir_core.detached_worker import receive_handoff,ready_channel
        ready=ready_channel();payload=receive_handoff(sys.stdin.buffer)
        if set(payload)!={'root','knowledge','install'}:raise ValueError('Invalid watcher handoff')
        options=SimpleNamespace(**{name:Path(value) for name,value in payload.items()})
        try:watch(index,options,ready=ready)
        except Exception as error:
            try:ready(dict(status='failed',pid=os.getpid(),error_type=type(error).__name__))
            except RuntimeError:pass
            raise
    else:
        if any(getattr(args,name) is None for name in ('root','knowledge','install','result')):raise ValueError('Missing owned update arguments')
        args.auto=True;args.resume=None;args.baseline=None;args.plan_only=False;args.audit_only=False
        event_log=args.result.with_suffix('.events.jsonl')
        try:
            with redirect_stdout(EventLog(event_log)):
                print(json.dumps(dict(event='update_worker',state='starting')),flush=True)
                result=index.extension('update-auto').execute(index,args,args.root/'knowledge/search.sqlite3')
        except Exception as error:result=dict(state='failed',reason=str(error)[:2048],error_type=type(error).__name__)
        result['event_log']=str(event_log)
        index.extension('research-workflow').atomic(args.result,index.extension('update-auto').canonical(result))


if __name__=='__main__':main()
