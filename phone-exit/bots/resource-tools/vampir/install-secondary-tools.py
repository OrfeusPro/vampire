"""Install pinned offline research tools outside Git; never run/inject the game."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import urllib.request
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))


def digest(path, algorithm='sha256'):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, algorithm).hexdigest()


def install(record, root):
    archive = root / record['archive']
    if not archive.exists():
        temporary = archive.with_suffix('.download')
        urllib.request.urlretrieve(record['url'], temporary)
        temporary.replace(archive)
    algorithm = 'sha512' if 'sha512' in record else 'sha256'
    if digest(archive, algorithm) != record[algorithm]:
        raise ValueError('Archive hash mismatch: ' + str(archive))
    if 'directory' not in record:
        return archive
    target = root / record['directory']
    marker = target / '.phoneexit-archive.json'
    if marker.exists() and json.loads(marker.read_text('utf-8')) == record:
        return target
    target.mkdir(exist_ok=True)
    with zipfile.ZipFile(archive) as bundle:
        for entry in bundle.infolist():
            if not (target / entry.filename).resolve().is_relative_to(target.resolve()):
                raise ValueError('Unsafe ZIP path')
        for entry in bundle.infolist():
            destination = target / entry.filename
            if entry.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            # Preserve identical files if an SDK build server currently holds them.
            with bundle.open(entry) as stream:
                expected = hashlib.file_digest(stream, 'sha256').hexdigest()
            if destination.is_file() and digest(destination) == expected:
                continue
            bundle.extract(entry, target)
    marker.write_text(json.dumps(record, indent=2), encoding='utf-8')
    return target


def main():
    lock = json.loads((HERE / 'secondary-tools.lock.json').read_text('utf-8'))
    root = ROOT / 'tools'
    root.mkdir(parents=True, exist_ok=True)
    sdk = install(lock['sdk'], root)
    install(lock['cue4parse'], root)
    dumper = install(lock['dumper7'], root) / lock['dumper7']['source_directory']
    env = dict(os.environ, DOTNET_CLI_HOME=str(root / 'dotnet-home'),
               NUGET_PACKAGES=str(root / 'nuget-packages'), DOTNET_NOLOGO='1')
    output = root / 'cue4parse-probe'
    output.mkdir(exist_ok=True)
    def run(command, log, cwd=None):
        with log.open('w', encoding='utf-8') as stream:
            subprocess.run(command, env=env, cwd=cwd, stdout=stream,
                           stderr=subprocess.STDOUT, check=True)
    project = HERE / 'cue4parse-probe'
    run([str(sdk / 'dotnet.exe'), 'build', 'Cue4ParseProbe.csproj', '-c', 'Release',
         '-p:RestoreLockedMode=true', '--nologo', '-o', str(output)],
        output / 'build.log', project)
    vswhere = Path(os.environ.get('ProgramFiles(x86)', 'C:/Program Files (x86)')) / 'Microsoft Visual Studio/Installer/vswhere.exe'
    msbuild = subprocess.check_output([str(vswhere), '-latest', '-products', '*',
        '-requires', 'Microsoft.Component.MSBuild', '-find', 'MSBuild/Current/Bin/MSBuild.exe'], text=True).strip()
    if not msbuild or not Path(msbuild).is_file():
        raise FileNotFoundError('Visual Studio MSBuild with C++ v143 is required')
    # Upstream .sln references an absent SDKTest subproject. Build actual DLL project.
    run([msbuild, str(dumper / 'Dumper/Dumper.vcxproj'), '/p:Configuration=Release',
         '/p:Platform=x64', '/p:PlatformToolset=v143', '/m:2', '/nologo', '/verbosity:minimal'],
        dumper.parent / 'build-project.log')
    receipt = dict(lock_sha256=digest(HERE / 'secondary-tools.lock.json'),
        package_lock_sha256=digest(project / 'packages.lock.json'),
        msbuild=msbuild, scope='Build only; game not launched or injected',
        outputs=[dict(path=str(p), sha256=digest(p)) for p in [
            output / 'Cue4ParseProbe.dll', output / 'CUE4Parse.dll',
            dumper / 'Dumper/x64/Release/Dumper-7.dll']])
    (root / 'secondary-tools-install.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
