"""Import a new saved EXE in an isolated project and correlate with old Ghidra data."""
import hashlib
import argparse
import json
import os
from pathlib import Path
import subprocess
import uuid

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
OLD = 'c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8'
NEW = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--resume-from', type=Path, help='Completed saved import; correlate without reimport or reanalysis')
    args = parser.parse_args()
    lock = json.loads((HERE / 'ghidra-tools.lock.json').read_text('utf-8'))
    tools = ROOT / 'tools/ghidra'
    for name in ('ghidra', 'jdk'):
        if json.loads((tools / lock[name]['directory'] / '.phoneexit-verified.json').read_text('utf-8')) != lock[name]:
            raise ValueError('Pinned tool installation mismatch')
    source = ROOT / 'client-code-snapshots' / NEW / 'ProjectRED-Win64-Shipping.exe'
    old_source = ROOT / 'client-code-snapshots' / OLD / source.name
    if digest(source) != NEW or digest(old_source) != OLD:
        raise ValueError('Saved EXE mismatch')
    latest = ROOT / 'ghidra/latest-export.json'
    old_export = json.loads(latest.read_text('utf-8'))
    report_path = Path(old_export['output']) / 'functions.json'
    if old_export['source_sha256'] != OLD or digest(report_path) != old_export['report_sha256']:
        raise ValueError('Historical export changed')
    out = ROOT / 'ghidra/release-comparisons' / (OLD[:12] + '-' + NEW[:12]) / ('run-' + uuid.uuid4().hex[:12])
    out.mkdir(parents=True)
    projects = out / 'projects'
    prior_inputs = {}
    incomplete = False
    if args.resume_from is not None:
        prior = args.resume_from / 'invocation.json'
        prior_report = json.loads(prior.read_text('utf-8'))
        if prior_report['old_source_sha256'] != OLD or prior_report['new_source_sha256'] != NEW:
            raise ValueError('Resume source mismatch')
        projects = args.resume_from / 'projects'
        if not (projects / 'NewRelease.gpr').is_file():
            raise ValueError('Saved project missing')
        prior_log = args.resume_from / 'headless.log'
        if 'Save succeeded for:' not in prior_log.read_text('utf-8'):
            raise ValueError('Saved import not confirmed')
        prior_inputs = {str(p): digest(p) for p in (prior, prior_log)}
        incomplete = True  # Resuming partial analysis never implies full coverage.
    else:
        projects.mkdir()
    script = HERE / 'CompareVampirRelease.java'
    inputs = {str(p): digest(p) for p in (Path(__file__), script, latest, report_path)}
    inputs.update(prior_inputs)
    env = os.environ.copy()
    env['JAVA_HOME'] = str(tools / lock['jdk']['directory'])
    env['GHIDRA_HEADLESS_MAXMEM'] = '8G'
    home = HERE.parents[2] / '.tools/vampir-ghidra-home'
    home.mkdir(exist_ok=True)
    env['GHIDRA_HEADLESS_JAVA_OPTIONS'] = '-Duser.home=' + home.as_posix()
    base = [str(tools / lock['ghidra']['directory'] / 'support/analyzeHeadless.bat'), str(projects), 'NewRelease']
    command = base + ['-process', source.name, '-noanalysis', '-max-cpu', '2', '-scriptPath', str(HERE),
               '-postScript', script.name, str(ROOT / 'ghidra/projects'), 'Vampir_' + OLD[:12],
               OLD, NEW, str(out / 'candidates.json'), 'true' if incomplete else 'false']
    receipt = dict(schema=1, old_source=str(old_source), old_source_sha256=OLD,
                   new_source=str(source), new_source_sha256=NEW, inputs=inputs,
                   tools=lock, command=command, max_heap='8G', max_cpu=2, analysis_timeout_seconds=900)
    (out / 'invocation.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(output=str(out), log=str(out / 'headless.log'))), flush=True)
    if args.resume_from is None:
        import_command = base + ['-import', str(source), '-max-cpu', '2', '-analysisTimeoutPerFile', '900']
        receipt['import_command'] = import_command
        with (out / 'import.log').open('w', encoding='utf-8') as stream:
            imported = subprocess.run(import_command, env=env, stdout=stream, stderr=subprocess.STDOUT)
        import_log = (out / 'import.log').read_text('utf-8')
        if imported.returncode or 'Save succeeded for:' not in import_log:
            raise RuntimeError('Import not saved; inspect import.log')
        command[-1] = 'true' if 'Analysis timed out' in import_log else 'false'
        (out / 'invocation.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    with (out / 'headless.log').open('w', encoding='utf-8') as stream:
        completed = subprocess.run(command, env=env, stdout=stream, stderr=subprocess.STDOUT)
    if completed.returncode or not (out / 'candidates.json').is_file():
        raise RuntimeError('Comparison did not produce a report; inspect ' + str(out / 'headless.log'))
    if any(digest(Path(p)) != sha for p, sha in inputs.items()):
        raise ValueError('Comparison inputs changed during execution')
    if digest(source) != NEW or digest(old_source) != OLD:
        raise ValueError('Source changed during comparison')
    result = json.loads((out / 'candidates.json').read_text('utf-8'))
    if result['old_source_sha256'] != OLD or result['new_source_sha256'] != NEW:
        raise ValueError('Comparison source mismatch')
    receipt['files'] = {p.name: digest(p) for p in out.iterdir() if p.is_file()}
    receipt['analysis_timed_out'] = result['analysis_timed_out']
    (out / 'provenance.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(output=str(out), analysis_timed_out=result['analysis_timed_out'],
                          matches={p['correlator']: len(p['matches']) for p in result['passes']})), flush=True)


if __name__ == '__main__':
    main()
