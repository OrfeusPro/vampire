"""Bounded current stat replay fixtures/comparator; not imported by production runtime."""
import importlib.util,struct,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
SHA='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
def load(name):
 s=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def make_harness(context):
 if context['source_sha256']!=SHA:raise ValueError('Stat context source mismatch')
 h=load('native-request-harness-11316').make_harness(context['exports'],{int(v,16) for v in context['functions'].values()},leaves={int(k,16):v for k,v in context['leaves'].items()},source_sha256=SHA,copy_thunk=int(context['helpers']['memcpy'],16))
 h.stat_context=context;return h
def install(h,model,native_setter):
 uc,x=h.uc,h.x;elements,buckets=h.scratch+0x19000,h.scratch+0x1d000;types=list(range(207));writes=[]
 def init():
  uc.mem_write(model,bytes(0x200));uc.mem_write(model+0x50,struct.pack('<QI',elements,len(types)));uc.mem_write(model+0x90,struct.pack('<QI',buckets,128));heads=[-1]*128
  for index,stat in enumerate(types):
   bucket=stat&127;uc.mem_write(elements+24*index,struct.pack('<i4xQi4x',stat,0xfeed,heads[bucket]));heads[bucket]=index
  uc.mem_write(buckets,struct.pack('<128i',*heads));writes.clear()
 def values():return {stat:int.from_bytes(uc.mem_read(elements+24*i+8,8),'little') for i,stat in enumerate(types)}
 def setter(machine):
  if machine.reg_read(x.UC_X86_REG_RCX)!=model:raise ValueError('Stat model receiver differs')
  value=machine.reg_read(x.UC_X86_REG_R8);writes.append((machine.reg_read(x.UC_X86_REG_RDX)&0xffffffff,value if value<2**63 else value-2**64));machine.reg_write(x.UC_X86_REG_RIP,native_setter)
 h.add_fixture(int(h.stat_context['fixtures']['0x1455f10f0'],16),setter)
 return init,values,writes,types
def model_value(stat,value):return (-1 if value<0 else 1)*(abs(value)//100) if stat==134 else value
sys.path.insert(0,str(HERE.parents[1]/'vampir-shared'))
from vampir_core.stat_change_11318 import decode_stat_change,decode_character_level_up,initial_stat_values
