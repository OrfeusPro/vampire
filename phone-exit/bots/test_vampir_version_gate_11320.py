"""Actual source/export gate boundaries; mutations are isolated local fixtures."""
import copy,hashlib,json,unittest
from pathlib import Path
from types import SimpleNamespace
from test_vampir_update_contracts import load
ROOT=Path('F:/PhoneExit Resources/Vampir')
class VersionGate11320Tests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.gate=load('version-gate-switch-11320');cls.native=load('build-native-entry-code')
  cls.raw=(ROOT/'client-code-snapshots'/cls.gate.SHA/'ProjectRED-Win64-Shipping.exe').read_bytes()
  if hashlib.sha256(cls.raw).hexdigest()!=cls.gate.SHA:raise ValueError('Gate source changed')
  cls.image=cls.native.Image(cls.raw)
  path=ROOT/'ghidra/request-exports'/cls.gate.SHA/'run-cd7653218083/details.json'
  cls.export=json.loads(path.read_bytes())
  cls.function=next(f for f in cls.export['functions'] if int(f['address'],16)==cls.gate.ENTRY)
 def harness(self,raw=None,function=None):
  return SimpleNamespace(sha=self.gate.SHA,image=self.image,raw=raw or self.raw,fragments=[copy.deepcopy(function or self.function)])
 def test_actual_export_separates_code_from_inline_switch_data(self):
  result=self.gate.validate(self.native,self.harness())
  self.assertEqual(result['input_count'],227);self.assertEqual(result['code_instructions'],251)
  self.assertEqual(len(bytes.fromhex(result['index_hex'])),227)
 def test_foreign_source_and_incomplete_export_are_rejected(self):
  with self.assertRaisesRegex(ValueError,'source'):self.gate.rows(self.native,self.image,'0'*64)
  function=copy.deepcopy(self.function);function['block_coverage_complete']=False
  with self.assertRaisesRegex(ValueError,'coverage incomplete'):self.gate.validate(self.native,self.harness(function=function))
 def test_changed_table_index_or_dispatch_are_rejected(self):
  for at in (self.gate.TABLE,self.gate.INDEX,self.gate.DISPATCH_START):
   with self.subTest(address=hex(at)):
    raw=bytearray(self.raw);off=self.image.offset(at-self.image.pe.base);raw[off]^=1
    with self.assertRaises(ValueError):self.gate.validate(self.native,self.harness(raw=bytes(raw)))
 def test_changed_export_instruction_is_not_accepted(self):
  f=copy.deepcopy(self.function);f['instructions'][0]['bytes']='90'
  with self.assertRaisesRegex(ValueError,'code/data separation'):self.gate.validate(self.native,self.harness(function=f))
if __name__=='__main__':unittest.main()
