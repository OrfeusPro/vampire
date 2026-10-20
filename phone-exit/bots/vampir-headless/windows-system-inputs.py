"""Observe and bind Windows inputs using only the bot's locally built helper."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'vampir-shared'))
from vampir_core.windows_cpu import observe_windows_cpu
from vampir_core.windows_version import observe_windows_version
from vampir_core.version_inputs import bind_windows_version_inputs


def observe_inputs():
    folder = HERE.parents[1] / '.tools/vampir-runtime-windows'
    receipt_path = folder / 'receipt.json'
    if receipt_path.stat().st_size > 16384: raise ValueError('CPU build receipt exceeds budget')
    receipt = json.loads(receipt_path.read_text('utf-8'))
    if (receipt.get('schema_version') != 1 or receipt.get('architecture') != 'x64' or
            receipt.get('compiler_version') != '14.44.35207' or receipt.get('windows_sdk') != '10.0.22621.0'):
        raise ValueError('Unsupported CPU input build receipt')
    for key, path in (('source_sha256', HERE / 'windows/system-inputs.cpp'),
            ('project_sha256', HERE / 'windows/system-inputs.vcxproj'),
            ('build_script_sha256', HERE / 'build-system-inputs.ps1')):
        if hashlib.sha256(path.read_bytes()).hexdigest() != receipt.get(key):
            raise ValueError('CPU input source changed; rebuild the helper')
    cpu = observe_windows_cpu(folder / 'vampir_system_inputs.dll', expected_sha256=receipt['binary_sha256'])
    return cpu, observe_windows_version()


def bind_observed_inputs(payload):
    cpu, windows_version = observe_inputs()
    return bind_windows_version_inputs(payload, cpu=cpu, windows_version=windows_version)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true', required=True)
    parser.parse_args()
    try:
        cpu, version = observe_inputs()
        print(json.dumps(dict(cpu_observed=True, vendor_bytes=len(cpu.vendor), brand_bytes=len(cpu.brand),
            cpu_format_ready=bool(cpu.text()), windows_api_succeeded=version is not None, game_started=False)))
    except (OSError, ValueError, RuntimeError, KeyError):
        print(json.dumps(dict(cpu_observed=False, error='windows_inputs_unavailable')))
        sys.exit(2)
