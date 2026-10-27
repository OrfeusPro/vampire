"""Explicit owner lifetime opt-in; fake SDK and no socket or scheduled task."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
from test_vampir_live_source_preflight import launcher


def accounts():
    return [dict(bot_id='owned',email='fixture@example.invalid',socks_port=21001,
        region='JP',server_id=256,character_index=0)]


class KeepOnlineRunnerTests(unittest.TestCase):
    def owner_run(self,keep_online=False,**changes):
        module=launcher();seen=[];ready=[]
        def run(email,**kwargs):
            seen.append(kwargs['session_control'])
            return dict(status='game_login_probe',game=dict(status='connection_closed',login_result_code=0))
        with patch.object(module,'verify_launch_source'),patch.object(module,'LiveSessionServer') as server, \
                patch.object(module,'Timer') as timer,redirect_stdout(io.StringIO()):
            server.return_value.__enter__.return_value=SimpleNamespace(server=SimpleNamespace(server_port=17947))
            result=module.run_accounts(accounts(),{'owned':'fixture-password'},manifest=Path('fixture'),
                client_version=1,profile='candidate-11318',keep_online=keep_online,
                probe=SimpleNamespace(run=run),ready_callback=ready.append,**changes)
        return seen,ready,result,timer

    def test_current_default_keeps_300_second_timer(self):
        sessions,ready,result,timer=self.owner_run()
        timer.assert_called_once();self.assertEqual(timer.call_args.args[0],300)
        timer.return_value.start.assert_called_once();timer.return_value.cancel.assert_called_once()
        self.assertFalse(sessions[0].keep_online)
        self.assertEqual(ready[0]['max_runtime_seconds'],300)
        self.assertFalse(ready[0]['keep_online'])
        self.assertEqual(result[0]['login_result_code'],0)

    def test_opt_in_has_no_timer_and_marks_owned_session_and_readiness(self):
        sessions,ready,result,timer=self.owner_run(True)
        timer.assert_not_called()
        self.assertTrue(sessions[0].keep_online)
        self.assertTrue(ready[0]['keep_online'])
        self.assertIsNone(ready[0]['max_runtime_seconds'])
        self.assertEqual(result[0]['game_status'],'connection_closed')

    def test_invalid_opt_in_or_conflicting_timer_fails_before_owner(self):
        module=launcher()
        for values in ({'keep_online':1},{'keep_online':'yes'},{'keep_online':None},
                       {'keep_online':True,'max_runtime_seconds':300}):
            with self.subTest(values=values),patch.object(module,'LiveSessionServer') as server, \
                    patch.object(module,'verify_launch_source') as source,self.assertRaises(ValueError):
                module.run_accounts([],{},manifest=Path('fixture'),client_version=1,
                    profile='candidate-11318',**values)
            server.assert_not_called();source.assert_not_called()

    def test_handoff_accepts_old_payload_and_explicit_opt_in_only(self):
        module=launcher()
        with tempfile.TemporaryDirectory() as directory:
            manifest=Path(directory)/'manifest.json';manifest.write_text('{}')
            base=dict(accounts=accounts(),manifest=str(manifest),client_version=1,projection=None,
                sign_in_parallelism=1,port=17947,max_runtime_seconds=None,result_path=None)
            with patch.object(module,'run_accounts',return_value=[]) as run:
                module.launch_options(base,{'owned':'fixture-password'})
                self.assertFalse(run.call_args.kwargs['keep_online'])
                module.launch_options(dict(base,keep_online=True),{'owned':'fixture-password'})
                self.assertTrue(run.call_args.kwargs['keep_online'])
            for changes in ({'keep_online':1},{'keep_online':True,'max_runtime_seconds':5},
                            {'keep_online':True,'unexpected':True}):
                with self.subTest(changes=changes),patch.object(module,'run_accounts') as run, \
                        self.assertRaises(ValueError):
                    module.launch_options(dict(base,**changes),{'owned':'fixture-password'})
                run.assert_not_called()

    def test_detached_cli_removes_both_timers_only_on_explicit_flag(self):
        for keep in (False,True):
            module=launcher();scheduled=SimpleNamespace(launch_scheduled=Mock(return_value={'status':'ready'}))
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory);manifest=root/'manifest.json';manifest.write_text('{}')
                rows=root/'accounts.json';rows.write_text(json.dumps(accounts()))
                args=['runner','--profile','candidate-11318','--accounts',str(rows),
                    '--manifest',str(manifest),'--client-version','1','--detached']+(['--keep-online'] if keep else [])
                with patch.object(module.sys,'argv',args),patch.object(module,'verify_launch_source'), \
                        patch.object(module.getpass,'getpass',return_value='fixture-password'), \
                        patch.dict(module.sys.modules,{'vampir_core.scheduled_worker':scheduled}),redirect_stdout(io.StringIO()):
                    module.main()
            scheduled.launch_scheduled.assert_called_once()
            payload=scheduled.launch_scheduled.call_args.args[1]['options']
            self.assertEqual(payload['keep_online'],keep)
            self.assertEqual(payload['max_runtime_seconds'],None if keep else 300)
            if keep:self.assertTrue(scheduled.launch_scheduled.call_args.kwargs['unlimited'])
            else:self.assertNotIn('unlimited',scheduled.launch_scheduled.call_args.kwargs)


if __name__=='__main__':unittest.main()
