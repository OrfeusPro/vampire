"""Explicit, pinned Dumper-7 experiment; no privilege or protection bypass."""
import argparse
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
from pathlib import Path
import time

GAME = Path('C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe')
GAME_SHA = 'c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8'
DLL = Path('F:/PhoneExit Resources/Vampir/tools/dumper7/Dumper-7-90d1f390d26e31a1f71d29af56c6bd2f240b7493/Dumper/x64/Release/Dumper-7.dll')
DLL_SHA = '7f88848e0ce6db4a922f670494c6ff94e2c113e5218aa61362cbd0056965a99e'
CONFIG = Path('C:/Dumper-7/Dumper-7.ini')
ROOT = Path('F:/PhoneExit Resources/Vampir/dumper7-live')


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--run-name', required=True)
    parser.add_argument('--execute', action='store_true', help='Requires explicit user authorization')
    args = parser.parse_args()
    if not args.run_name or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in args.run_name):
        parser.error('run-name must contain lowercase ASCII letters, digits or hyphens')
    if C.sizeof(C.c_void_p) != 8 or args.pid <= 0:
        parser.error('Requires 64-bit Python and a positive PID')
    folder = ROOT / args.run_name
    folder.mkdir(parents=True, exist_ok=False)
    report_path = folder / 'report.json'
    result = dict(pid=args.pid, execute=args.execute, state='preflight', injected=False,
                  loader_thread_created=False, load_rights_available=False)
    result['probe_sha256'] = sha(Path(__file__))

    def save():
        report_path.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')

    kernel = C.WinDLL('kernel32', use_last_error=True)

    def api(name, restype, *argtypes):
        fn = getattr(kernel, name)
        fn.restype, fn.argtypes = restype, argtypes
        return fn

    ptr, size = C.c_void_p, C.c_size_t
    open_process = api('OpenProcess', W.HANDLE, W.DWORD, W.BOOL, W.DWORD)
    close = api('CloseHandle', W.BOOL, W.HANDLE)
    image_name = api('QueryFullProcessImageNameW', W.BOOL, W.HANDLE, W.DWORD, W.LPWSTR, C.POINTER(W.DWORD))
    wait = api('WaitForSingleObject', W.DWORD, W.HANDLE, W.DWORD)
    alloc = api('VirtualAllocEx', ptr, W.HANDLE, ptr, size, W.DWORD, W.DWORD)
    free = api('VirtualFreeEx', W.BOOL, W.HANDLE, ptr, size, W.DWORD)
    write = api('WriteProcessMemory', W.BOOL, W.HANDLE, ptr, ptr, size, C.POINTER(size))
    create = api('CreateRemoteThread', W.HANDLE, W.HANDLE, ptr, size, ptr, ptr, W.DWORD, C.POINTER(W.DWORD))
    get_exit = api('GetExitCodeThread', W.BOOL, W.HANDLE, C.POINTER(W.DWORD))
    get_module = api('GetModuleHandleW', W.HMODULE, W.LPCWSTR)
    get_proc = api('GetProcAddress', ptr, W.HMODULE, C.c_char_p)
    module_from_address = api('GetModuleHandleExW', W.BOOL, W.DWORD, ptr, C.POINTER(W.HMODULE))
    module_name = api('GetModuleFileNameW', W.DWORD, W.HMODULE, W.LPWSTR, W.DWORD)
    enum_modules = api('K32EnumProcessModulesEx', W.BOOL, W.HANDLE, C.POINTER(W.HMODULE), W.DWORD, C.POINTER(W.DWORD), W.DWORD)
    remote_name = api('K32GetModuleFileNameExW', W.DWORD, W.HANDLE, W.HMODULE, W.LPWSTR, W.DWORD)
    process = thread = remote = None
    config_owned = False
    thread_finished = False

    def checked(value, operation):
        if not value:
            raise OSError(C.get_last_error(), operation)
        return value

    def modules():
        entries = (W.HMODULE * 4096)()
        needed = W.DWORD()
        checked(enum_modules(process, entries, C.sizeof(entries), C.byref(needed), 3), 'EnumProcessModules')
        if needed.value > C.sizeof(entries):
            raise RuntimeError('Module list exceeds bound')
        found = []
        for handle in entries[:needed.value // C.sizeof(W.HMODULE)]:
            name = C.create_unicode_buffer(32768)
            if remote_name(process, handle, name, len(name)):
                found.append((handle, Path(name.value)))
        return found

    try:
        result['admin'] = bool(C.windll.shell32.IsUserAnAdmin())
        for path, expected in ((GAME, GAME_SHA), (DLL, DLL_SHA)):
            if sha(path) != expected:
                raise RuntimeError('Pinned input SHA mismatch: ' + path.name)
        result.update(game_sha256=GAME_SHA, dll_sha256=DLL_SHA)
        process = checked(open_process(0x1000, False, args.pid), 'OpenProcess identity')
        name, length = C.create_unicode_buffer(32768), W.DWORD(32768)
        checked(image_name(process, 0, name, C.byref(length)), 'QueryFullProcessImageName')
        if Path(name.value).resolve() != GAME.resolve():
            raise RuntimeError('PID does not identify pinned Vampir executable')
        close(process)
        process = None
        # Only normal documented rights; no SeDebugPrivilege or driver requests.
        process = checked(open_process(0x10043A, False, args.pid), 'OpenProcess load rights')
        result['load_rights_available'] = True
        name, length = C.create_unicode_buffer(32768), W.DWORD(32768)
        checked(image_name(process, 0, name, C.byref(length)), 'Recheck process identity')
        if Path(name.value).resolve() != GAME.resolve():
            raise RuntimeError('Process identity changed before load')
        result['state'] = 'access-confirmed'
        save()
        if not args.execute:
            return
        loaded = modules()
        if any(path.name.lower() == 'dumper-7.dll' for _, path in loaded):
            raise RuntimeError('Dumper-7 already loaded; refusing a second load')
        # Match the resolved system implementation, including forwarded exports.
        address = checked(get_proc(get_module('kernel32.dll'), b'LoadLibraryW'), 'GetProcAddress')
        owner = W.HMODULE()
        checked(module_from_address(6, address, C.byref(owner)), 'GetModuleHandleEx')
        owner_path = C.create_unicode_buffer(32768)
        checked(module_name(owner, owner_path, len(owner_path)), 'GetModuleFileName')
        owners = [(base, path) for base, path in loaded if path.resolve() == Path(owner_path.value).resolve()]
        if len(owners) != 1:
            raise RuntimeError('Cannot uniquely match system loader module')
        remote_loader = owners[0][0] + address - owner.value
        # A local profile takes precedence over global; never overwrite either.
        for parent in (GAME.parent, GAME.parents[3]):
            if (parent / 'Dumper-7.ini').exists():
                raise RuntimeError('Existing local Dumper-7 profile requires inspection')
        CONFIG.parent.mkdir(parents=True, exist_ok=True)
        config_text = ('[Settings]\nSleepTimeout=0\nDumpKey=0\n'
                       f'SDKGenerationPath={folder.as_posix()}/output\n'
                       f'LogFilePath={folder.as_posix()}/dumper.log\n'
                       'ShouldAutoUnload=1\nExecuteSDKTestScript=0\n')
        with CONFIG.open('x', encoding='ascii') as stream:
            stream.write(config_text)
        config_owned = True
        result['config_sha256'] = sha(CONFIG)
        save()
        payload = C.create_string_buffer((str(DLL) + '\0').encode('utf-16-le'))
        remote = checked(alloc(process, None, len(payload), 0x3000, 4), 'VirtualAllocEx path')
        written = size()
        checked(write(process, remote, payload, len(payload), C.byref(written)), 'WriteProcessMemory path')
        if written.value != len(payload):
            raise RuntimeError('Incomplete DLL path write')
        thread_id = W.DWORD()
        thread = checked(create(process, None, 0, remote_loader, remote, 0, C.byref(thread_id)), 'CreateRemoteThread loader')
        result['loader_thread_created'] = True
        result['injected'] = None  # Unknown until the module is observed.
        result['state'] = 'loader-started'
        save()
        waited = wait(thread, 30000)
        if waited != 0:
            raise RuntimeError('Loader did not finish within 30 seconds; no retry')
        thread_finished = True
        exit_code = W.DWORD()
        checked(get_exit(thread, C.byref(exit_code)), 'GetExitCodeThread')
        result['loader_exit_low32'] = exit_code.value
        result['injected'] = any(path.resolve() == DLL.resolve() for _, path in modules())
        result['state'] = 'module-observed' if result['injected'] else 'module-not-observed'
        save()
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            if wait(process, 0) == 0:
                result['state'] = 'game-exited'
                break
            log = folder / 'dumper.log'
            if log.exists():
                content = log.read_bytes()[-65536:]
                if b'Generating SDK took' in content:
                    result['state'] = 'generation-finished'
                    break
            time.sleep(1)
        else:
            result['state'] = 'generation-timeout'
        result['output_files'] = sum(1 for p in (folder / 'output').rglob('*') if p.is_file())
    except Exception as error:
        result.update(state='failed', error_type=type(error).__name__, error=str(error), winerror=getattr(error, 'errno', None))
    finally:
        # Settings are read asynchronously by the DLL worker. Keep the profile
        # if a still-running loader may not have consumed it yet.
        config_consumed = (folder / 'dumper.log').exists()
        game_ended = bool(process and wait(process, 0) == 0)
        can_remove_config = not thread or config_consumed or game_ended
        if remote and (not thread or thread_finished):
            result['path_memory_freed'] = bool(free(process, remote, 0, 0x8000))
        if thread:
            close(thread)
        if process:
            close(process)
        if config_owned:
            # Do not delete a profile changed by somebody else during the run.
            if can_remove_config and CONFIG.exists() and sha(CONFIG) == result.get('config_sha256'):
                CONFIG.unlink()
                result['temporary_config_removed'] = True
            else:
                result['temporary_config_retained'] = True
        save()
        print(json.dumps(result))


if __name__ == '__main__':
    main()
