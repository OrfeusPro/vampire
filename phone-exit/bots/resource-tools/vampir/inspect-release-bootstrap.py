"""Inspect the observed bootstrap scalar in the verified saved new Ghidra project."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import uuid

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
SHA = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--connected', action='store_true', help='Inspect ctor-bound connected table slots instead of searching bytes')
    mode.add_argument('--scalar-only', action='store_true', help='Search low 16 bits of scalars without wire fragment searches')
    mode.add_argument('--send', action='store_true', help='Inspect source-bound game wrapper slots and one level of callees')
    mode.add_argument('--lifecycle', action='store_true', help='Inspect remaining source-bound wrapper lifecycle slots')
    mode.add_argument('--ping', action='store_true', help='Trace PktPing literal, candidate table, constructor uses and callers')
    mode.add_argument('--clock', action='store_true', help='Inspect references to the source-bound Ping clock pointer')
    args = parser.parse_args()
    comparison = ROOT / 'ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c'
    receipt_path = comparison / 'provenance.json'
    receipt = json.loads(receipt_path.read_text('utf-8'))
    if receipt['new_source_sha256'] != SHA or digest(Path(receipt['new_source'])) != SHA:
        raise ValueError('Saved source mismatch')
    lock = json.loads((HERE / 'ghidra-tools.lock.json').read_text('utf-8'))
    tools = ROOT / 'tools/ghidra'
    for name in ('ghidra', 'jdk'):
        if json.loads((tools / lock[name]['directory'] / '.phoneexit-verified.json').read_text('utf-8')) != lock[name]:
            raise ValueError('Pinned tool mismatch')
    script = HERE / 'InspectVampirBootstrap.java'
    inputs = {str(p): digest(p) for p in (Path(__file__), script, receipt_path)}
    if args.send or args.lifecycle:
        constructor = comparison / 'details/run-318565bc90d7/details.json'
        if digest(constructor) != 'a0d199a7b60fba31c926aedb5862670d061adafb31bf00b3d9bbd78812aa9a22':
            raise ValueError('Source-bound wrapper constructor export changed')
        inputs[str(constructor)] = digest(constructor)
    if args.clock:
        constructor = comparison / 'bootstrap/run-4398dc0d34cf/export/bootstrap.json'
        if digest(constructor) != 'd6d1c226ecad9f5ef0ac389c4ddef9d3ffdffe7dbd3fef602d72583ca42bbb63':
            raise ValueError('Clock constructor evidence changed')
        inputs[str(constructor)] = digest(constructor)
        initialize = comparison / 'bootstrap/run-aa9d3f766ff1/export/bootstrap.json'
        if digest(initialize) != '0d7ed611834d0ab44e77f701c0094bb2e7c8393a829b7b62c80e71f9f819e96c':
            raise ValueError('Clock initialize/addend evidence changed')
        inputs[str(initialize)] = digest(initialize)
        datetime = comparison / 'details/run-7c4690fdf614/details.json'
        if digest(datetime) != '8a66f7e97ce2f6061b93b74140201ffde77150069c1f8f4356919dad1bb95e46':
            raise ValueError('Datetime source evidence changed')
        inputs[str(datetime)] = digest(datetime)
    out = comparison / 'bootstrap' / ('run-' + uuid.uuid4().hex[:12])
    out.mkdir(parents=True)
    env = os.environ.copy()
    env['JAVA_HOME'] = str(tools / lock['jdk']['directory'])
    env['GHIDRA_HEADLESS_MAXMEM'] = '8G'
    env['GHIDRA_HEADLESS_JAVA_OPTIONS'] = '-Duser.home=' + (HERE.parents[2] / '.tools/vampir-ghidra-home').as_posix()
    command = [str(tools / lock['ghidra']['directory'] / 'support/analyzeHeadless.bat'),
        receipt['command'][1], 'NewRelease', '-process', Path(receipt['new_source']).name,
        '-noanalysis', '-max-cpu', '2', '-scriptPath', str(HERE), '-postScript', script.name,
        SHA, str(out / 'export')]
    if args.connected:
        command.append('connected')
    elif args.scalar_only:
        command.append('scalar')
    elif args.send:
        command.append('send')
    elif args.lifecycle:
        command.append('lifecycle')
    elif args.ping:
        command.append('ping')
    elif args.clock:
        command.append('clock')
    invocation = dict(source_sha256=SHA, inputs=inputs, tools=lock, command=command)
    (out / 'invocation.json').write_text(json.dumps(invocation, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(output=str(out))), flush=True)
    with (out / 'headless.log').open('w', encoding='utf-8') as stream:
        completed = subprocess.run(command, env=env, stdout=stream, stderr=subprocess.STDOUT)
    if completed.returncode or not (out / 'export/bootstrap.json').is_file():
        raise RuntimeError('Bootstrap export failed; inspect ' + str(out / 'headless.log'))
    if any(digest(Path(p)) != sha for p, sha in inputs.items()):
        raise ValueError('Inputs changed during export')
    invocation['files'] = {str(p.relative_to(out)): digest(p) for p in out.rglob('*') if p.is_file()}
    (out / 'provenance.json').write_text(json.dumps(invocation, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(out / 'export/bootstrap.json'), sha256=digest(out / 'export/bootstrap.json'))))


if __name__ == '__main__':
    main()
