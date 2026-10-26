"""Real owned Windows static server; no game, account, browser or profile IO."""
import json
import os
from pathlib import Path
import subprocess
import socket
import sys
import tempfile
import time
import unittest
from urllib.request import urlopen


@unittest.skipUnless(os.name=='nt','Windows task owner')
class UiServerOwnerTests(unittest.TestCase):
    def test_server_survives_launcher_and_closes_at_own_lifetime(self):
        script=Path(__file__).parent/'resource-tools/vampir/serve-ui-prototype.py'
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);page=root/'ui-prototype/snapshots/synthetic/index.html';page.parent.mkdir(parents=True)
            page.write_text('<title>synthetic</title>','utf-8')
            result=subprocess.run([sys.executable,'-X','utf8',str(script),'--detached','--root',directory,
                '--port','0','--lifetime-seconds','3'],capture_output=True,text=True,encoding='utf-8',timeout=20,check=True)
            ready=json.loads(result.stdout)
            self.assertEqual(ready['launcher'],'windows_interactive_task')
            self.assertNotEqual(ready['pid'],os.getpid())
            base='http://127.0.0.1:'+str(ready['port'])
            with urlopen(base+'/ui-prototype/snapshots/synthetic/index.html',timeout=2) as response:
                self.assertEqual(response.read(),b'<title>synthetic</title>')
                self.assertIn('immutable',response.headers['Cache-Control'])
                self.assertEqual(response.headers['X-Content-Type-Options'],'nosniff')
            deadline=time.monotonic()+9
            while time.monotonic()<deadline:
                try:
                    with socket.create_connection(('127.0.0.1',ready['port']),timeout=3):pass
                except ConnectionRefusedError:break
                except TimeoutError:pass
                time.sleep(.1)
            else:self.fail('UI server outlived its explicit lifetime')


if __name__=='__main__':unittest.main()
