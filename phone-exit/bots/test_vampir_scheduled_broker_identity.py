"""Scheduled broker preserves the requested interpreter and owns child lifetime."""
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core import scheduled_worker as module


class ScheduledBrokerIdentityTests(unittest.TestCase):
    def handoffs(self,value):
        read_fd,write_fd=os.pipe()
        os.write(write_fd,json.dumps(value).encode('utf-8'));os.close(write_fd)
        response_read,response_write=os.pipe()
        self.addCleanup(os.close,response_read)
        return read_fd,response_write

    def payload(self):
        return dict(command=[str(Path(sys.executable).with_name('python.exe')),'-X','utf8',
            str(Path(__file__).resolve())],payload={'secret':'synthetic-秘密'},cwd=str(Path.cwd()))

    def test_exact_interpreter_and_anonymous_payload_wait_until_owner_exits(self):
        value=self.payload();handles=self.handoffs(value)
        stdin=io.BytesIO();child=Mock(stdin=stdin);child.poll.return_value=0
        events=[];spawned={}
        class Input(io.BytesIO):
            def close(self):
                if not self.closed:spawned['input']=self.getvalue();events.append('input_closed')
                super().close()
        child.stdin=Input()
        def spawn(command,**kwargs):
            events.append('spawn');spawned.update(command=command,options=kwargs)
            return child
        def wait():
            self.assertTrue(child.stdin.closed)
            self.assertTrue(spawned['options']['stdout'].closed)
            events.append('owner_waited');return 0
        child.wait.side_effect=wait
        with patch.object(module,'duplicate_handoffs',return_value=handles), \
                patch.object(module.subprocess,'Popen',side_effect=spawn):
            module.broker(100,200,300)
        self.assertEqual(spawned['command'],value['command'])
        self.assertEqual(spawned['options']['cwd'],value['cwd'])
        self.assertEqual(spawned['options']['creationflags'],module.subprocess.CREATE_NO_WINDOW)
        self.assertEqual(spawned['options']['stderr'],module.subprocess.DEVNULL)
        self.assertEqual(json.loads(spawned['input']),value['payload'])
        self.assertNotIn('synthetic-秘密',repr(spawned['command']))
        self.assertEqual(events,['spawn','input_closed','owner_waited'])
        child.wait.assert_called_once_with()
        child.terminate.assert_not_called()

    def test_failed_input_closes_pipe_and_terminates_owned_child(self):
        value=self.payload();handles=self.handoffs(value)
        class BrokenInput(io.BytesIO):
            def write(self,frame):raise BrokenPipeError('synthetic closed worker')
        child=Mock(stdin=BrokenInput());child.poll.return_value=None
        with patch.object(module,'duplicate_handoffs',return_value=handles), \
                patch.object(module.subprocess,'Popen',return_value=child):
            with self.assertRaises(BrokenPipeError):module.broker(100,200,300)
        self.assertTrue(child.stdin.closed)
        child.terminate.assert_called_once_with()
        child.wait.assert_called_once_with(timeout=5)

    def test_invalid_interpreter_closes_response_before_spawn(self):
        value=self.payload();value['command'][0]='other.exe';handles=self.handoffs(value)
        with patch.object(module,'duplicate_handoffs',return_value=handles), \
                patch.object(module.subprocess,'Popen') as spawn:
            with self.assertRaises(ValueError):module.broker(100,200,300)
            spawn.assert_not_called()
        with self.assertRaises(OSError):os.fstat(handles[1])


if __name__=='__main__':unittest.main()
