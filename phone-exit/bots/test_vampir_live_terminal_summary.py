"""Durable terminal summaries retain bounded pump codes without private diagnostics."""
from contextlib import redirect_stdout
from datetime import datetime
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def launcher():
    path=Path(__file__).parent/'vampir-headless/run-live-sessions.py'
    spec=importlib.util.spec_from_file_location('terminal_summary_launcher',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


class TerminalSummaryTests(unittest.TestCase):
    def test_terminal_file_keeps_distinct_account_codes_and_redacts_unknown_diagnostics(self):
        module=launcher();rows=[dict(bot_id=bot,email=bot+'@example.invalid',socks_port=port,
            region='JP',server_id=256,character_index=0) for bot,port in [('a',21001),('b',21002),('c',21003)]]
        def probe(email,**kwargs):
            bot=kwargs['session_control'].bot_id
            kwargs['_progress']('game_login_exchange')
            return dict(status='game_login_probe',game=dict(status='connection_closed',login_result_code=0,
                error={'a':'ping_recovery_required','b':'private-token@example.invalid','c':None}[bot],
                periodic_ping_queued={'a':100,'b':True,'c':-1}[bot],
                ping_results_received={'a':90,'b':2**63,'c':'private-count'}[bot],
                body=b'private-body',access_token='private-token'))
        real_run=module.run_accounts
        def run(*args,**kwargs):
            return real_run(*args,**dict(kwargs,port=0,probe=SimpleNamespace(run=probe)))
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);manifest=root/'manifest';manifest.write_text('{}')
            result_file=root/'result.json';passwords={r['bot_id']:'private-password' for r in rows}
            options=dict(accounts=rows,manifest=str(manifest),client_version=1,projection=None,
                sign_in_parallelism=2,port=17947,max_runtime_seconds=None,result_path=str(result_file))
            output=io.StringIO()
            with patch.object(module,'run_accounts',side_effect=run),redirect_stdout(output):
                summaries=module.launch_options(options,passwords)
            saved=json.loads(result_file.read_text(encoding='utf-8'))
            self.assertEqual(saved,dict(status='finished',results=summaries));self.assertFalse(passwords)
            by_bot={r['bot_id']:r for r in summaries}
            self.assertEqual(by_bot['a']['connection_error'],'ping_recovery_required')
            self.assertEqual(by_bot['b']['connection_error'],'unclassified')
            self.assertIsNone(by_bot['c']['connection_error'])
            self.assertEqual((by_bot['a']['periodic_ping_queued'],by_bot['a']['ping_results_received']),(100,90))
            for bot in ('b','c'):
                self.assertIsNone(by_bot[bot]['periodic_ping_queued']);self.assertIsNone(by_bot[bot]['ping_results_received'])
            for row in summaries:
                self.assertEqual(row['game_status'],'connection_closed')
                self.assertEqual(datetime.fromisoformat(row['ended_at_utc']).utcoffset().total_seconds(),0)
                self.assertGreaterEqual(row['duration_seconds'],0)
            self.assertNotIn('private-',result_file.read_text()+output.getvalue())
            self.assertNotIn('@example.invalid',result_file.read_text()+output.getvalue())
            before=result_file.read_bytes()
            with patch.object(module,'run_accounts') as blocked,self.assertRaises(ValueError):
                module.launch_options(options,{r['bot_id']:'private-password' for r in rows})
            blocked.assert_not_called();self.assertEqual(result_file.read_bytes(),before)

    def test_worker_exception_has_type_and_timing_without_message(self):
        module=launcher();rows=[dict(bot_id='failed',email='private@example.invalid',socks_port=21001,
            region='JP',server_id=256,character_index=0)]
        def probe(*args,**kwargs):raise OSError('private-password and private-address')
        output=io.StringIO()
        with redirect_stdout(output):
            result=module.run_accounts(rows,{'failed':'private-password'},manifest=Path('fixture'),
                client_version=1,probe=SimpleNamespace(run=probe),port=0)
        self.assertEqual(result[0]['error_type'],'OSError');self.assertEqual(result[0]['status'],'failed')
        self.assertGreaterEqual(result[0]['duration_seconds'],0)
        self.assertNotIn('private-',json.dumps(result)+output.getvalue())


if __name__=='__main__':unittest.main()
