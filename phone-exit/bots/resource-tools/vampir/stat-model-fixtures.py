"""Existing-key native model storage fixture, shared by stat reader replays."""
import struct


def install(h,model,native_setter):
    uc,x=h.uc,h.x
    elements,buckets=h.scratch+0x19000,h.scratch+0x1d000
    types=list(range(207))
    writes=[]
    def init():
        uc.mem_write(model,bytes(0x200));uc.mem_write(model+0x50,struct.pack('<QI',elements,len(types)))
        uc.mem_write(model+0x90,struct.pack('<QI',buckets,128))
        heads=[-1]*128
        for index,stat in enumerate(types):
            bucket=stat&127
            uc.mem_write(elements+24*index,struct.pack('<i4xQi4x',stat,0xfeed,heads[bucket]))
            heads[bucket]=index
        uc.mem_write(buckets,struct.pack('<128i',*heads));writes.clear()
    def values():return {stat:int.from_bytes(uc.mem_read(elements+24*i+8,8),'little') for i,stat in enumerate(types)}
    def setter(machine):
        if machine.reg_read(x.UC_X86_REG_RCX)!=model:raise ValueError('Stat model receiver differs')
        value=machine.reg_read(x.UC_X86_REG_R8)
        writes.append((machine.reg_read(x.UC_X86_REG_RDX)&0xffffffff,value if value<2**63 else value-2**64))
        machine.reg_write(x.UC_X86_REG_RIP,native_setter)
    h.add_fixture(0x1455f10f0,setter)
    return init,values,writes,types


def model_value(stat,value):
    # Native apply has a special signed division for CombatPower (EStat 134).
    return (-1 if value<0 else 1)*(abs(value)//100) if stat==134 else value
