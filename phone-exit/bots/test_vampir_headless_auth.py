"""Static SDK provenance, native escaping primitives and offline token plans."""
import hashlib,json,os,sys,unittest
from pathlib import Path
from urllib.parse import parse_qs

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.auth_request import plan_authorization_code,plan_refresh_token,_escape_ascii


class AuthPlanTests(unittest.TestCase):
    def test_code_and_refresh_forms_do_not_mix_credentials(self):
        plan=plan_authorization_code(client_id='synthetic-client',device_key='synthetic-device',code='code +/&=%')
        self.assertEqual(plan.method,'POST');self.assertEqual(plan.endpoint_key,'authTokenUrl')
        self.assertEqual(plan.relative_path,'v2/access-token')
        self.assertEqual(plan.content_type,'application/x-www-form-urlencoded')
        self.assertEqual(parse_qs(plan.body.decode('ascii')),dict(grant_type=['authorization_code'],
                         client_id=['synthetic-client'],device_key=['synthetic-device'],code=['code +/&=%']))
        self.assertIn(b'%20%2B%2F%26%3D%25',plan.body)
        self.assertNotIn('synthetic',repr(plan));self.assertNotIn('code +',repr(plan))
        refresh=plan_refresh_token(client_id='client',device_key='device',refresh_token='refresh/+=')
        self.assertEqual(parse_qs(refresh.body.decode('ascii'))['grant_type'],['refresh_token'])
        self.assertNotIn('code',parse_qs(refresh.body.decode('ascii')))

    def test_missing_control_unicode_and_resource_limits(self):
        for invalid in ['',None,'x'*4097,'line\r\n','юникод']:
            with self.assertRaises(ValueError):plan_authorization_code(client_id='client',device_key='device',code=invalid)
        with self.assertRaises(ValueError):
            plan_refresh_token(client_id='/'*4096,device_key='/'*4096,refresh_token='/'*4096)


class AuthEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root=Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES','F:/PhoneExit Resources/Vampir'))
        path=root/'code-clues/headless-auth-index.json'
        if not path.exists():raise unittest.SkipTest('Generate SDK auth evidence first')
        cls.report=json.loads(path.read_text('utf-8'));cls.raw=Path(cls.report['source']).read_bytes()

    def test_source_fragments_and_literals(self):
        r=self.report;self.assertFalse(r['network_ready'])
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(),r['sha256'])
        self.assertEqual(r['missing'],[]);self.assertEqual(r['rejected_candidates'],[])
        self.assertEqual((r['statistics']['symbols'],r['statistics']['xrefs'],r['statistics']['roots']),(24,34,24))
        for f in r['fragments']+r['request_helper_fragments']:
            data=self.raw[f['file_offset']:f['file_offset']+f['end_rva']-f['begin_rva']]
            self.assertEqual(hashlib.sha256(data).hexdigest(),f['sha256'])
            self.assertEqual(data,b''.join(bytes.fromhex(i['bytes']) for i in f['instructions']))
        for row in r['symbols']+r['referenced_constants']+r['escape_primitives']['bodies']+r['escape_primitives']['data']:
            data=bytes.fromhex(row['bytes']);off=row['file_offset']
            self.assertEqual(self.raw[off:off+len(data)],data)

    def test_lea_boundaries_and_request_call_sites(self):
        r=self.report;rows={i['address']:i for f in r['fragments'] for i in f['instructions']}
        for xref in r['xrefs']:
            row=rows[xref['instruction']['address']]
            self.assertEqual(row['mnemonic'],'lea')
            self.assertEqual(row,xref['instruction'])
        for address in [0x1450e2d80,0x1450e36e1]:
            # Locate request dispatch by its actual target; no inferred HTTP from names alone.
            self.assertEqual(rows[address]['direct_target'],0x14451c570)
        constants={row['text'] for row in r['referenced_constants']}
        self.assertTrue({'authTokenUrl','authUrl','v2/access-token','v1/sign-in','grant_type',
                        'authorization_code','client_id','device_key','code','refresh_token',
                        'Content-Type','application/x-www-form-urlencoded','POST','{0}={1}','&'}.issubset(constants))

    def test_ascii_escaping_matches_all_native_byte_primitives(self):
        evidence=self.report['escape_primitives'];self.assertEqual(len(evidence['cases']),256)
        self.assertEqual(evidence['safe_ascii'],'-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~')
        for row in evidence['cases']:
            value=row['byte'];self.assertEqual(row['hex'],f'{value:02X}')
            if 32<=value<=126:
                expected=chr(value) if row['safe'] else '%'+row['hex']
                self.assertEqual(_escape_ascii(chr(value)),expected)


if __name__=='__main__':unittest.main()
