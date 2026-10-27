"""Current stat whole-native parity and independent portable boundary regressions."""
import hashlib,importlib.util,json,struct,sys,unittest
from pathlib import Path
HERE=Path(__file__).parent
TOOLS=HERE/'resource-tools/vampir'
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core import stat_change_11318 as codec
from vampir_core.stat_change import SOURCE_SHA256 as OLD
from vampir_core.character_select_result import SelectionRecord

def tool(name):
 s=importlib.util.spec_from_file_location(name.replace('-','_'),TOOLS/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

class StatBatch11318Tests(unittest.TestCase):
 def test_whole_current_native_notify_and_initial_match_portable_codec(self):
  for kind,count in (('notify',1119),('initial',203)):
   with self.subTest(kind=kind):
    result=tool('replay-stat-'+kind+'-11318').verify()
    raw=Path(result['report']).read_bytes();report=json.loads(raw)
    self.assertEqual(hashlib.sha256(raw).hexdigest(),result['sha256'])
    self.assertEqual(report['source_sha256'],codec.SOURCE_SHA256)
    self.assertEqual(len(report['cases']),count)
    self.assertEqual(report['portable_decoder_sha256'],hashlib.sha256(Path(codec.__file__).read_bytes()).hexdigest())
    self.assertFalse(report['network_used']);self.assertFalse(report['profile_activated'])
    self.assertFalse(report['runtime_decoder_admitted'])
    if kind=='initial':self.assertTrue(any('1c8' in str(row).lower() for row in report['character_stat_link']))
 def test_source_scope_and_exact_wire_size_remain_fail_closed(self):
  body=struct.pack('<QHiQQBH',2**64-1,1,4,0,2**64-1,255,65535)
  got=codec.decode_stat_change(body,source_sha256=codec.SOURCE_SHA256)
  self.assertEqual(got.entity_key,2**64-1);self.assertEqual(got.values[0].signed_second,-1)
  self.assertTrue(got.flag);self.assertEqual(got.reason,65535)
  for source in (OLD,'0'*64,None):
   with self.subTest(source=source),self.assertRaises(ValueError):codec.decode_stat_change(body,source_sha256=source)
  for changed in (body[:-1],body+b'\0',bytes(9)):
   with self.subTest(size=len(changed)),self.assertRaises(ValueError):codec.decode_stat_change(changed,source_sha256=codec.SOURCE_SHA256)
  with self.assertRaises(BufferError):codec.decode_stat_change(body,source_sha256=codec.SOURCE_SHA256,max_records=0)
 def test_initial_values_preserve_signed_boundaries_and_reject_layout_changes(self):
  records=(SelectionRecord(((8,0xffffffff),(16,2**64-1))),SelectionRecord(((8,134),(16,2**63))))
  self.assertEqual(codec.initial_stat_values(records,source_sha256=codec.SOURCE_SHA256),((-1,-1),(134,-2**63)))
  with self.assertRaises(ValueError):codec.initial_stat_values((SelectionRecord(((16,1),(8,4))),),source_sha256=codec.SOURCE_SHA256)
  with self.assertRaises(ValueError):codec.initial_stat_values(records,source_sha256=OLD)
 def test_level_notification_has_no_stat_tail_and_keeps_uint64_identity(self):
  body=struct.pack('<QHiQQ',2**64-1,1,3,0,12)
  value=codec.decode_character_level_up(body,source_sha256=codec.SOURCE_SHA256)
  self.assertEqual(value.entity_key,2**64-1);self.assertEqual(value.values[0].signed_second,12)
  self.assertIsNone(value.flag);self.assertIsNone(value.reason)
  with self.assertRaises(ValueError):codec.decode_stat_change(body,source_sha256=codec.SOURCE_SHA256)

class StatSourceBindings11318Tests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.root=Path('F:/PhoneExit Resources/Vampir')
  cls.raw=(cls.root/'client-code-snapshots'/codec.SOURCE_SHA256/'ProjectRED-Win64-Shipping.exe').read_bytes()
  if hashlib.sha256(cls.raw).hexdigest()!=codec.SOURCE_SHA256:raise ValueError('Current source changed')
  cls.image=tool('build-native-entry-code').Image(cls.raw)
 def test_actual_current_packet_ids_reader_slots_and_constructor_stores(self):
  for sha,pkt,reader in (('c390d402da90e1b0a4aef9347c5b87d38aa0c4828264eeaeb1e5e5eae3675b3f',321,'0x1456c4b20'),('4dcd921f619e8883cabf5a231723b33e06a609abf1f93ca7007733536a08d93f',322,'0x1456c5a10')):
   p=self.root/'code-clues/stat-packet-bindings-11318'/sha/'manifest.json';raw=p.read_bytes();r=json.loads(raw)
   self.assertEqual(hashlib.sha256(raw).hexdigest(),sha);self.assertEqual(r['source_sha256'],codec.SOURCE_SHA256)
   self.assertEqual(r['tool_sha256'],hashlib.sha256((TOOLS/'inspect-stat-bindings-11318.py').read_bytes()).hexdigest())
   self.assertTrue(r['binding_verified']);self.assertEqual(r['packet_id'],pkt);self.assertEqual(r['slots'][4],reader)
   at=int(r['candidate_table'],16);off=self.image.offset(at-self.image.pe.base);table=bytes.fromhex(r['table_bytes'])
   self.assertEqual(self.raw[off:off+len(table)],table)
   self.assertEqual(struct.unpack('<8Q',table),tuple(int(a,16) for a in r['slots']))
   at=int(r['slots'][5],16);off=self.image.offset(at-self.image.pe.base)
   self.assertEqual(self.raw[off:off+6],b'\xb8'+struct.pack('<I',pkt)+b'\xc3')
   self.assertEqual(len(r['reviewed_constructors']),1)
   for row in r['reviewed_constructors'][0]['instructions']:
    data=bytes.fromhex(row['bytes']);off=self.image.offset(int(row['address'],16)-self.image.pe.base)
    self.assertEqual(self.raw[off:off+len(data)],data)
 def test_actual_current_estat_descriptors_bind_vital_ids_without_name_guessing(self):
  sha='a9a373cdc17c73008ae0bc804a335d0996749187f092b49d7c8afc71a53d98e5'
  p=self.root/'knowledge/stat-enums-11318'/sha/'manifest.json';raw=p.read_bytes();r=json.loads(raw)
  self.assertEqual(hashlib.sha256(raw).hexdigest(),sha);self.assertEqual(r['source_sha256'],codec.SOURCE_SHA256)
  rows=r['enums']['EStat'];self.assertEqual(len(rows),208)
  for row in rows:
   descriptor=row['descriptor_offset'];name=row['name'].encode()+b'\0';name_offset=row['name_offset']
   self.assertEqual(self.raw[name_offset:name_offset+len(name)],name)
   pointer,value=struct.unpack_from('<Qq',self.raw,descriptor)
   self.assertEqual(self.image.offset(pointer-self.image.pe.base),name_offset);self.assertEqual(value,row['value'])
  values={r['name']:r['value'] for r in rows}
  self.assertEqual({k:values[k] for k in ('EStat::Level','EStat::Hp','EStat::MaxHp','EStat::Mp','EStat::MaxMp')},{'EStat::Level':3,'EStat::Hp':4,'EStat::MaxHp':5,'EStat::Mp':9,'EStat::MaxMp':10})
 def test_current_context_regeneration_matches_committed_source_bindings(self):
  alignment=self.root/'knowledge/stat-batch-alignment-11318/d6b4ec7817e28a30f19da1463337e989cd7cd7cfb1c430dfd9aab557db86ac81/manifest.json'
  exports=[self.root/'ghidra/request-exports'/codec.SOURCE_SHA256/run/'details.json' for run in ('run-c76e7785700f','run-ceaa0e5d6498')]
  regenerated=tool('generate-stat-contexts-11318').generate(self.root,alignment,exports)
  for kind,value in regenerated.items():
   self.assertEqual(value,json.loads((TOOLS/'knowledge/native-contexts'/('stat-'+kind+'-11318.json')).read_text('utf-8')))

from test_vampir_stat_batch_alignment_11318 import StatBatchAlignment11318Tests
def load_tests(loader,tests,pattern):
 return unittest.TestSuite(loader.loadTestsFromTestCase(case) for case in (StatBatch11318Tests,StatSourceBindings11318Tests,StatBatchAlignment11318Tests))
if __name__=='__main__':unittest.main()
