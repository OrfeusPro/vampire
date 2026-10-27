"""Assemble the checked SDK/GMC2/NID offline candidate; runtime stays disabled."""
import hashlib
import importlib.util
from pathlib import Path

HERE=Path(__file__).resolve().parent
SHA='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'


def build(root=None):
    root=Path(root) if root else Path('F:/PhoneExit Resources/Vampir')
    spec=importlib.util.spec_from_file_location('sdk_batch_profile',HERE/'run-sdk-batch-11318.py')
    batch=importlib.util.module_from_spec(spec);spec.loader.exec_module(batch)
    path,report,_=batch.run(root)
    if report['source_sha256']!=SHA or report['native_case_executions']!=3667:
        raise ValueError('SDK candidate batch source/coverage differs')
    return dict(schema=1,name='recovered-11318-candidate',source_sha256=SHA,
        source=str(root/'client-code-snapshots'/SHA/'ProjectRED-Win64-Shipping.exe'),
        **report['profile_candidate'],
        evidence=dict(batch=dict(path=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                                 cases=3667,primitive_cases=report['primitive_cases'],limits=report['limits'])),
        runtime_enabled=False,network_ready=False,active_runtime_settings_verified=False,
        supported_auth_flows=[],game_protocol_verified=False,
        local_choices=['Environment real, NMENV absent, PC platform byte 3, raw webview type 0 and English language are explicit choices.',
                       'All native identities are synthetic; actual device/account/route data must come from a fresh isolated session.'],
        next_checks=['Bind the current launcher runtime profile and source guards without fallback to old evidence.',
                     'Current CharacterList/clock/game profile and separate live session remain required.'])
