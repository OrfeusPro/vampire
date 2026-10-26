"""One-shot interactive-user Windows task; anonymous handle handoff, no secrets on disk."""
import argparse
import ctypes
from ctypes import wintypes
import json
import io
import os
from pathlib import Path
import subprocess
import runpy
import sys
import uuid

if __package__ in (None,''):
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from vampir_core.detached_worker import receive_handoff,MAX_INPUT

TASK_SCRIPT=r'''
$ErrorActionPreference='Stop'
[Console]::InputEncoding=[System.Text.UTF8Encoding]::new($false)
$spec=[Console]::In.ReadToEnd() | ConvertFrom-Json
$service=New-Object -ComObject Schedule.Service
$service.Connect()
$folder=$service.GetFolder('\')
if ($spec.mode -eq 'cleanup') {
  try { $registered=$folder.GetTask($spec.name) }
  catch { if ($_.Exception.HResult -eq -2147024894) { exit 0 }; throw }
  if ($spec.stop) { $registered.Stop(0) }
  $folder.DeleteTask($spec.name,0)
} else {
  $task=$service.NewTask(0)
  $task.RegistrationInfo.Description='Phone Exit: одноразовый запуск владельца; без триггеров и сохранённых паролей.'
  $task.Principal.UserId=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $task.Principal.LogonType=3
  $task.Principal.RunLevel=0
  $task.Settings.Enabled=$true
  $task.Settings.Hidden=$true
  $task.Settings.ExecutionTimeLimit='PT24H'
  $task.Settings.DisallowStartIfOnBatteries=$false
  $task.Settings.StopIfGoingOnBatteries=$false
  $action=$task.Actions.Create(0)
  $action.Path=$spec.program
  $action.Arguments=$spec.arguments
  $registered=$folder.RegisterTaskDefinition($spec.name,$task,2,$null,$null,3)
  $running=$registered.Run($null)
  [Console]::Out.Write($running.InstanceGuid)
}
'''


def task_call(spec):
    shell=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
    try:
        result=subprocess.run([str(shell),'-NoProfile','-NonInteractive','-Command',TASK_SCRIPT],
            input=json.dumps(spec),text=True,encoding='utf-8',capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW,timeout=15)
    except subprocess.TimeoutExpired:raise TimeoutError('Windows task operation timed out') from None
    if result.returncode:raise RuntimeError('Windows task operation failed')
    return result.stdout.strip()


def duplicate_handoffs(parent,request,response):
    """Copy only explicit anonymous pipe handles from the live dispatcher."""
    import msvcrt
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
    kernel.OpenProcess.restype=wintypes.HANDLE
    kernel.GetCurrentProcess.restype=wintypes.HANDLE
    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    kernel.DuplicateHandle.argtypes=[wintypes.HANDLE,wintypes.HANDLE,wintypes.HANDLE,
        ctypes.POINTER(wintypes.HANDLE),wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
    kernel.DuplicateHandle.restype=wintypes.BOOL
    source=kernel.OpenProcess(0x40,False,parent) # PROCESS_DUP_HANDLE only
    if not source:raise OSError('Handoff dispatcher unavailable')
    descriptors=[]
    try:
        for value,mode in ((request,os.O_RDONLY),(response,os.O_WRONLY)):
            copied=wintypes.HANDLE()
            if not kernel.DuplicateHandle(source,value,kernel.GetCurrentProcess(),ctypes.byref(copied),0,False,2):
                raise OSError('Anonymous handoff handle unavailable')
            try:descriptors.append(msvcrt.open_osfhandle(copied.value,mode|os.O_BINARY))
            except BaseException:kernel.CloseHandle(copied);raise
        return descriptors
    except BaseException:
        for descriptor in descriptors:os.close(descriptor)
        raise
    finally:kernel.CloseHandle(source)


def broker(parent,request,response):
    read_fd,write_fd=duplicate_handoffs(parent,request,response)
    with os.fdopen(read_fd,'rb') as incoming:
        value=receive_handoff(incoming)
    if set(value)!={'command','payload','cwd'}:raise ValueError('Invalid scheduled handoff')
    command=value['command']
    validate_command(command)
    # Run in the scheduler process itself: Scheduler may forbid BREAKAWAY.
    # Spawning a child and exiting the task would retain task-job lifetime risk.
    sys.argv=command[3:]
    sys.path.insert(0,str(Path(sys.argv[0]).parent))
    if value['cwd']:os.chdir(value['cwd'])
    os.dup2(write_fd,1);os.close(write_fd)
    sys.stdout=open(1,'w',encoding='utf-8',closefd=False)
    sys.stderr=open(os.devnull,'w',encoding='utf-8')
    sys.stdin=io.TextIOWrapper(io.BytesIO(json.dumps(value['payload'],ensure_ascii=False).encode('utf-8')),encoding='utf-8')
    value=None
    runpy.run_path(sys.argv[0],run_name='__main__')


def validate_command(command):
    if not isinstance(command,list) or len(command)<4 or any(type(v) is not str for v in command):
        raise ValueError('Explicit Python script command required')
    if Path(command[0]).resolve()!=Path(sys.executable).with_name('python.exe').resolve() or command[1:3]!=['-X','utf8']:
        raise ValueError('Current Python UTF-8 script required')
    if not Path(command[3]).is_absolute() or not Path(command[3]).is_file():raise ValueError('Existing absolute script required')


def launch_scheduled(command,payload,*,cwd=None,timeout=30):
    """Task owns the worker ancestry; definition is deleted after handoff.

    No trigger, elevation, stored user password, credential file or auto-retry.
    The worker runs in the Scheduler process, outside the dispatcher ancestry.
    """
    if os.name!='nt':raise OSError('Windows interactive task required')
    if type(payload) is not dict:raise ValueError('Explicit worker payload required')
    if not isinstance(timeout,(int,float)) or not 0<timeout<=60:raise ValueError('Bounded handoff timeout required')
    validate_command(command)
    import msvcrt
    from queue import Queue
    from threading import Thread
    from vampir_core.detached_worker import MAX_READY
    frame=json.dumps(dict(command=command,payload=payload,cwd=str(cwd) if cwd else None),
        ensure_ascii=False,allow_nan=False,separators=(',',':')).encode('utf-8')
    if len(frame)>MAX_INPUT:raise ValueError('Scheduled handoff limit exceeded')
    pythonw=Path(sys.executable).with_name('pythonw.exe')
    if not pythonw.is_file():raise RuntimeError('Windowless Python worker unavailable')
    request_read,request_write=os.pipe();response_read,response_write=os.pipe()
    name='PhoneExit-OneShot-'+uuid.uuid4().hex
    # Arguments contain only PID and handle numbers. Passwords and game options
    # stay in anonymous pipes; handles are not inheritable or published endpoints.
    arguments=subprocess.list2cmdline([str(Path(__file__).resolve()),'--broker',str(os.getpid()),
        str(msvcrt.get_osfhandle(request_read)),str(msvcrt.get_osfhandle(response_write))])
    result=Queue(maxsize=1)
    def handoff():
        try:
            with os.fdopen(request_write,'wb') as outgoing:outgoing.write(frame)
            with os.fdopen(response_read,'rb') as incoming:line=incoming.readline(MAX_READY+1)
            if len(line)>MAX_READY or not line.endswith(b'\n'):raise RuntimeError('Scheduled readiness invalid')
            ready=json.loads(line)
            if type(ready) is not dict:raise RuntimeError('Scheduled worker startup failed')
            result.put(ready)
        except BaseException:result.put(None)
    thread=Thread(target=handoff,name='scheduled-handoff',daemon=True)
    attempted=False;started=False;ready_ok=False
    try:
        attempted=True
        task_call(dict(mode='create',name=name,program=str(pythonw),arguments=arguments))
        thread.start();started=True;thread.join(timeout)
        if thread.is_alive():raise TimeoutError('Scheduled handoff timed out')
        ready=result.get_nowait()
        if ready is None:raise RuntimeError('Scheduled worker handoff failed')
        if ready.get('status')!='ready' or type(ready.get('pid')) is not int or ready['pid']<1:
            raise RuntimeError('Scheduled worker startup failed: '+str(ready.get('error_type'))+' / '+str(ready.get('winerror')))
        ready['launcher']='windows_interactive_task'
        ready_ok=True
        return ready
    finally:
        os.close(request_read);os.close(response_write)
        if not started:os.close(request_write);os.close(response_read)
        if attempted:task_call(dict(mode='cleanup',name=name,stop=not ready_ok))


if __name__=='__main__':
    # A task executes this file directly, without importing any user profiles.
    parser=argparse.ArgumentParser();parser.add_argument('--broker',nargs=3,type=int,required=True)
    args=parser.parse_args();broker(*args.broker)
