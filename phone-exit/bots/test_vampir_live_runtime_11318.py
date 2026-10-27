"""Explicit current profile handoff/preflight; no secrets, owner or network."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch
from test_vampir_live_source_preflight import launcher


class LiveRuntime11318Tests(unittest.TestCase):
    def test_direct_current_helper_rejects_projection_before_owner(self):
        module=launcher()
        with patch.object(module,'LiveSessionServer') as owner,patch.object(module,'verify_launch_source') as source:
            with self.assertRaisesRegex(ValueError,'Проекция карты'):
                module.run_accounts([],{},manifest='unused',client_version=1,
                    profile='candidate-11318',projection=object(),probe=Mock())
        owner.assert_not_called();source.assert_not_called()

    def test_current_owner_cannot_exceed_bounded_runtime(self):
        module=launcher()
        with patch.object(module,'verify_launch_source'),patch.object(module,'LiveSessionServer') as owner:
            for duration in (301,86400,True):
                with self.subTest(duration=duration),self.assertRaisesRegex(ValueError,'300'):
                    module.run_accounts([],{},manifest='unused',client_version=1,
                        profile='candidate-11318',max_runtime_seconds=duration,probe=Mock())
        owner.assert_not_called()

    def test_current_cli_check_selects_current_without_owner(self):
        module=launcher();out=io.StringIO()
        with patch.object(module.sys,'argv',['runner','--check-source','--profile','candidate-11318']),patch.object(
                module,'verify_launch_source',return_value={'network_attempted':False}) as source,patch.object(
                module.getpass,'getpass') as password,patch.object(module,'launch_options') as start,redirect_stdout(out):
            module.main()
        source.assert_called_once_with('candidate-11318');password.assert_not_called();start.assert_not_called()
        self.assertFalse(json.loads(out.getvalue())['network_attempted'])

    def test_detached_handoff_uses_explicit_current_and_no_projection(self):
        module=launcher()
        with tempfile.TemporaryDirectory() as directory:
            manifest=Path(directory)/'manifest.json';manifest.write_text('{}')
            options=dict(accounts=[],manifest=str(manifest),client_version=1,projection=None,
                sign_in_parallelism=1,port=17947,max_runtime_seconds=1,result_path=None,profile='candidate-11318')
            with patch.object(module,'verify_launch_source') as source,patch.object(module,'run_accounts',return_value=[]) as run:
                module.launch_options(options,{})
            source.assert_called_once_with('candidate-11318')
            self.assertEqual(run.call_args.kwargs['profile'],'candidate-11318')
            options['projection']='old-projection.json'
            with patch.object(module,'verify_launch_source'),patch.object(module,'run_accounts') as run:
                with self.assertRaisesRegex(ValueError,'Проекция карты'):module.launch_options(options,{})
            run.assert_not_called()

    def test_current_source_failure_is_redacted_before_password(self):
        module=launcher();out=io.StringIO()
        with patch.object(module.sys,'argv',['runner','--check-source','--profile','candidate-11318']),patch.object(
                module,'verify_launch_source',side_effect=module.SourceProfileNotVerified()),patch.object(
                module.getpass,'getpass') as password,redirect_stdout(out),self.assertRaises(SystemExit):module.main()
        password.assert_not_called();result=json.loads(out.getvalue())
        self.assertEqual(result['profile'],'candidate-11318');self.assertFalse(result['network_attempted'])


if __name__=='__main__':unittest.main()
