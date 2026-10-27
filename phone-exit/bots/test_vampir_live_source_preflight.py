"""Invalid source must fail before a password prompt, network owner or scheduled task."""
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


def launcher():
    p=Path(__file__).parent/'vampir-headless/run-live-sessions.py'
    spec=importlib.util.spec_from_file_location('source_preflight_launcher',p)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


class SourcePreflightTests(unittest.TestCase):
    def test_real_profile_guard_is_used_and_errors_are_redacted(self):
        module=launcher()
        load=Mock(return_value=SimpleNamespace(source_exe_sha256='a'*64,app_version='1.2.3'))
        fake=SimpleNamespace(load_profile=load)
        with patch.object(module.importlib.util,'module_from_spec',return_value=fake),patch.object(
                module.importlib.util,'spec_from_file_location',return_value=SimpleNamespace(loader=SimpleNamespace(exec_module=lambda m:None))):
            result=module.verify_launch_source()
            load.assert_called_once_with(selected_profile='candidate-11316')
            self.assertEqual((result['status'],result['app_version']),('source_verified','1.2.3'))
            self.assertFalse(result['network_attempted']);self.assertFalse(result['online_verified'])
            load.side_effect=ValueError('private-password and private/path')
            with self.assertRaises(module.SourceProfileNotVerified) as caught:module.verify_launch_source()
            self.assertEqual(str(caught.exception),'')

    def test_source_failure_precedes_accounts_password_and_background_launch(self):
        for detached in (False,True):
            module=launcher();output=io.StringIO()
            args=['run-live-sessions.py','--accounts','missing-private-accounts.json',
                '--manifest','missing-manifest.json','--client-version','1']+(['--detached'] if detached else [])
            scheduled=SimpleNamespace(launch_scheduled=Mock())
            with patch.object(module.sys,'argv',args),patch.object(module,'verify_launch_source',side_effect=module.SourceProfileNotVerified()),patch.object(
                    module.getpass,'getpass') as password,patch.object(module,'launch_options') as launch,patch.dict(
                    module.sys.modules,{'vampir_core.scheduled_worker':scheduled}),redirect_stdout(output),self.assertRaises(SystemExit) as stop:
                module.main()
            self.assertEqual(stop.exception.code,2)
            password.assert_not_called();launch.assert_not_called();scheduled.launch_scheduled.assert_not_called()
            result=json.loads(output.getvalue())
            self.assertEqual(result['reason'],'source_profile_not_verified')
            self.assertEqual(result['stage'],'source_validation');self.assertFalse(result['network_attempted'])
            self.assertNotIn('private',output.getvalue())

    def test_standalone_check_does_not_require_accounts_or_open_owner(self):
        module=launcher();output=io.StringIO();proof=dict(status='source_verified',network_attempted=False,online_verified=False)
        with patch.object(module.sys,'argv',['run-live-sessions.py','--check-source']),patch.object(
                module,'verify_launch_source',return_value=proof),patch.object(module.getpass,'getpass') as password,patch.object(
                module,'launch_options') as launch,redirect_stdout(output):module.main()
        self.assertEqual(json.loads(output.getvalue()),proof)
        password.assert_not_called();launch.assert_not_called()


if __name__=='__main__':unittest.main()
