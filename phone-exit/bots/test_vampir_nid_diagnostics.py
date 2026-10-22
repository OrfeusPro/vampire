import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

WINDOWS = Path(__file__).parent / 'vampir-headless/windows'


class NidDiagnosticsTests(unittest.TestCase):
    def test_failure_observer_returns_only_fixed_label_on_official_visible_page(self):
        source = (WINDOWS / 'nid-page-status.js').read_text('utf-8')
        fixture = r'''
const vm=require('node:vm');
const source=JSON.parse(require('node:fs').readFileSync(0,'utf8'));
function run(origin,path,text,visible=true,body=null){
 const context={location:{origin,pathname:path},document:{body:{innerText:body},querySelectorAll(){return [{innerText:text,getClientRects(){return visible?[{}]:[];}}];}}};
 return vm.runInNewContext(source,context)();
}
process.stdout.write(JSON.stringify([
 run('https://members.netmarble.com','/auth/signin/email','Login Failed'),
 run('https://members.netmarble.com','/auth/error','Login Failed\nprivate response text'),
 run('https://members.netmarble.com','/auth/signin/email','Login Failed',false),
 run('https://other.invalid','/auth/signin/email','Login Failed'),
 run('https://members.netmarble.com','/auth/signup/email/input','Login Failed'),
 run('https://members.netmarble.com','/auth/signin/email','What to do if Login Failed'),
 run('https://members.netmarble.com','/auth/signin/email','private email / password / token'),
 run('https://members.netmarble.com','/auth/signin/email','Login Failed\n'+'x'.repeat(4096)),
 run('https://members.netmarble.com','/auth','',true,'Login Failed\nprivate text'),
 run('https://members.netmarble.com','/auth','',true,'Login Failed\n'+'x'.repeat(8192))]));
'''
        result = subprocess.run(['node', '-e', fixture], input=json.dumps(source), text=True,
            capture_output=True, check=True, timeout=10)
        self.assertEqual(json.loads(result.stdout),
            ['login_failed', 'login_failed', 'waiting', 'unknown', 'unknown', 'waiting', 'waiting', 'waiting', 'login_failed', 'waiting'])
        self.assertNotIn('private', result.stdout)

    @unittest.skipUnless(sys.platform == 'win32', 'Windows WebView helper')
    def test_http_diagnostics_retain_only_integer_codes_and_exact_first_party_post(self):
        script = r'''
param([string]$Source)
$ErrorActionPreference='Stop'
Add-Type -Path $Source -ReferencedAssemblies 'System.Web.Extensions'
Add-Type -TypeDefinition @'
public sealed class ZeroOffsetStream : System.IO.MemoryStream {
 public ZeroOffsetStream(byte[] body) : base(body) { }
 public override int Read(byte[] buffer, int offset, int count) {
  if (offset != 0) throw new System.NotImplementedException();
  return base.Read(buffer, offset, System.Math.Min(count, 3));
 }
}
'@
$cases=@(
 '{"errorCode":123,"accessToken":"private-fixture"}',
 '{"code":456,"message":"private-password"}',
 '{"error":{"code":789,"email":"private-fixture"}}',
 '{"code":"private-token"}', '{"errorCode":true}', '{"code":1.5}',
 '{"code":2147483648}', 'not JSON', '{"accessToken":"private-fixture"}'
 '{"errorCode":"123"}', '{"resultCode":321}', '{"errorCode":"00123"}'
)
$codes=@($cases | ForEach-Object { [NidHttpDiagnostics]::ParseCode($_) })
$endpoints=@(
 [NidHttpDiagnostics]::IsEndpoint('https://members.netmarble.com/api/auth?private=fixture','POST'),
 [NidHttpDiagnostics]::IsEndpoint('https://members.netmarble.com/api/auth','GET'),
 [NidHttpDiagnostics]::IsEndpoint('http://members.netmarble.com/api/auth','POST'),
 [NidHttpDiagnostics]::IsEndpoint('https://members.netmarble.com:8443/api/auth','POST'),
 [NidHttpDiagnostics]::IsEndpoint('https://members.netmarble.com.evil.invalid/api/auth','POST'),
 [NidHttpDiagnostics]::IsEndpoint('https://user@members.netmarble.com/api/auth','POST')
)
function Inspect([string]$Body, $Length, [bool]$ZeroOffset=$false) {
 $bytes=[System.Text.Encoding]::UTF8.GetBytes($Body)
 $stream=if ($ZeroOffset) { [ZeroOffsetStream]::new($bytes) } else { [System.IO.MemoryStream]::new($bytes) }
 try {
  $result=[NidHttpDiagnostics]::ReadAsync($stream,$Length).GetAwaiter().GetResult()
  @{code=$result.Code;state=$result.State;read=$stream.Position}
 } finally { $stream.Dispose() }
}
$bounded=@(
 (Inspect '{"code":"456"}' $null),
 (Inspect '{"code":123}' 1),
 (Inspect ('x'*20000) $null),
 (Inspect '{"code":123}' 20000),
 (Inspect '{"accessToken":"private-fixture"}' $null),
 (Inspect '{"code":654}' $null $true)
)
$invalid=[System.IO.MemoryStream]::new([byte[]]@(255))
$closed=[System.IO.MemoryStream]::new(); $closed.Dispose()
try {
 $failures=@(
  [NidHttpDiagnostics]::ReadAsync($invalid,$null).GetAwaiter().GetResult().State,
  [NidHttpDiagnostics]::ReadAsync($closed,$null).GetAwaiter().GetResult().State
 )
} finally { $invalid.Dispose() }
@{codes=$codes;endpoints=$endpoints;bounded=$bounded;failures=$failures;large=[NidHttpDiagnostics]::ParseCode(('x'*16385))} | ConvertTo-Json -Compress -Depth 5
'''
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'fixture.ps1'; path.write_text(script, encoding='utf-8-sig')
            result = subprocess.run(['powershell.exe', '-NoProfile', '-File', str(path),
                '-Source', str((WINDOWS / 'nid-http-diagnostics.cs').resolve())],
                capture_output=True, text=True, check=True, timeout=30)
        data = json.loads(result.stdout)
        # PowerShell pipelines omit null results; no rejected values reach output.
        self.assertEqual([v for v in data['codes'] if v is not None], [123, 456, 789, 123, 321])
        self.assertEqual(data['endpoints'], [True, False, False, False, False, False])
        self.assertIsNone(data['large'])
        self.assertEqual([row['state'] for row in data['bounded']],
            ['numeric_code', 'length_mismatch', 'body_limit', 'length_limit', 'no_numeric_code', 'numeric_code'])
        self.assertEqual(data['bounded'][0]['code'], 456)
        self.assertEqual(data['bounded'][2]['read'], 16385)
        self.assertEqual(data['bounded'][3]['read'], 0)
        self.assertEqual(data['bounded'][5]['code'], 654)
        self.assertEqual(data['failures'], ['invalid_utf8', 'read_failed'])
        self.assertNotIn('private', result.stdout)


if __name__ == '__main__': unittest.main()
