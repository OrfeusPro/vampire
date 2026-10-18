"""Bounded class selection and post-initialization flow on synthetic objects.

UObject loading, the base lifecycle and query cache are explicit stubs. This
checks selection/ordering, not a live mesh or the cache implementation.
"""
import hashlib
import importlib.util
import math
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('selection_apply_base', HERE/'recast-filter-apply-emulator.py')
parent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parent)
FIELDS = {'Default': 0x780, 'ShortPath': 0x788, 'ExcludeHiddenPath': 0x790}
WRAPPERS = {'Default': 0x1454dedd0, 'ShortPath': 0x1454e07b0, 'ExcludeHiddenPath': 0x1454dee80}


class FilterSelectionEmulator(parent.FilterApplyEmulator):
    def __init__(self, root=Path('F:/PhoneExit Resources/Vampir')):
        super().__init__(root)
        spec = importlib.util.spec_from_file_location('selection_native', HERE/'build-native-entry-code.py')
        native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(native)
        addresses = [*WRAPPERS.values(), 0x1452818e0, 0x1454da500]
        self.selection_fragments = native.decode_ranges(self.image,
            {self.image.roots[self.image.containing(a)] for a in addresses})
        self.allowed.extend((self.image.pe.base+f['begin_rva'], self.image.pe.base+f['end_rva'])
                            for f in self.selection_fragments)
        self.output = self.base+0x11000
        self.classes = {name: self.base+0xe000+0x200*i for i, name in enumerate(FIELDS)}
        self.cdos = {name: self.base+0x10000+0x200*i for i, name in enumerate(FIELDS)}
        self.events = []
        self.callback_flag_address = 0x14b35a640
        self.callback_page_mapped = False

    def map_page(self, uc, access, address, size, value, extra):
        flag = getattr(self, 'callback_flag_address', 0)
        if flag and (address & ~4095) == (flag & ~4095):
            if access != self.u.UC_MEM_READ_UNMAPPED or address != flag or size != 1:
                raise ValueError('Unexpected synthetic global access')
            rva = flag-self.image.pe.base
            if not any(s['rva']+s['raw_size'] <= rva < s['rva']+s['size'] for s in self.image.pe.sections):
                raise ValueError('Callback flag is no longer in the PE zero-fill region')
            uc.mem_map(flag & ~4095, 4096, self.u.UC_PROT_READ)
            self.callback_page_mapped = True
            return True
        return super().map_page(uc, access, address, size, value, extra)

    def stub_return(self, value=0):
        uc, x = self.uc, self.x
        rsp = uc.reg_read(x.UC_X86_REG_RSP)
        if not self.base <= rsp < rsp+8 <= self.base+0x40000:
            raise ValueError('Stub return outside scratch')
        ret = struct.unpack('<Q', uc.mem_read(rsp, 8))[0]
        if not any(lo <= ret < hi for lo, hi in self.allowed):
            raise ValueError('Stub return outside reviewed code')
        uc.reg_write(x.UC_X86_REG_RAX, value)
        uc.reg_write(x.UC_X86_REG_RSP, rsp+8)
        uc.reg_write(x.UC_X86_REG_RIP, ret)

    def guard(self, uc, address, size, extra):
        x = self.x
        if address == 0x145267a60:
            self.events.append(dict(kind='filter_class_getter'))
            self.stub_return(self.root_class)
            return
        if address in (0x1416aaaf0, 0x1416dceb0):
            pointer = uc.reg_read(x.UC_X86_REG_RCX)
            name = next((k for k,v in self.classes.items() if v == pointer), None)
            if name is None:
                raise ValueError('Unexpected UObject stub input')
            if address == 0x1416aaaf0:
                uc.mem_write(pointer+0x110, struct.pack('<Q', self.cdos[name]))
            self.events.append(dict(kind='create_cdo' if address == 0x1416aaaf0 else 'class_pointer_callback', field=name))
            self.stub_return()
            return
        if address == 0x143801260:
            if uc.reg_read(x.UC_X86_REG_RCX) != self.owner:
                raise ValueError('Unexpected base lifecycle input')
            self.events.append(dict(kind='base_lifecycle_stub'))
            self.stub_return()
            return
        if address == 0x145281400:
            cdo = uc.reg_read(x.UC_X86_REG_RCX)
            name = next((k for k,v in self.cdos.items() if v == cdo), None)
            destination = uc.reg_read(x.UC_X86_REG_RDX)
            if name is None or uc.reg_read(x.UC_X86_REG_R8) != self.owner or uc.reg_read(x.UC_X86_REG_R9) != 0:
                raise ValueError('Unexpected query cache stub input')
            if not self.base <= destination < destination+16 <= self.base+0x40000:
                raise ValueError('Query result outside scratch')
            self.events.append(dict(kind='query_cache_stub', field=name, base_state=self.snapshot()))
            uc.mem_write(destination, struct.pack('<QQ', self.shared, 0))
            self.stub_return(destination)
            return
        if address == 0x145294560:
            self.events.append(dict(kind='travel_setter', area_id=uc.reg_read(x.UC_X86_REG_RDX)&255,
                value=struct.unpack('<f', struct.pack('<I', uc.reg_read(x.UC_X86_REG_XMM2)&0xffffffff))[0]))
        super().guard(uc, address, size, extra)

    def run(self, entry='lifecycle', states=None, base_present=True, costs=None, callback_flag=False):
        if entry != 'lifecycle' and entry not in WRAPPERS:
            raise ValueError('Unknown selection entry')
        states = states or {}
        if set(states)-set(FIELDS) or any(v not in ('present','missing_cdo','null','wrong_parent') for v in states.values()):
            raise ValueError('Unknown synthetic class state')
        costs = costs or {}
        if type(callback_flag) is not bool or type(base_present) is not bool:
            raise ValueError('Invalid synthetic bool')
        if any(type(k) is not int or not 0 <= k < 64 or not math.isfinite(v) or v < 0 for k,v in costs.items()):
            raise ValueError('Invalid synthetic base cost')
        uc, x = self.uc, self.x
        if not self.callback_page_mapped:
            self.map_page(uc, self.u.UC_MEM_READ_UNMAPPED, self.callback_flag_address, 1, 0, None)
        uc.mem_write(self.callback_flag_address, bytes([int(callback_flag)]))
        uc.mem_write(self.impl, bytes(0x430))
        self.execute(0x145299c20, {x.UC_X86_REG_RCX:self.impl, x.UC_X86_REG_RDX:0})
        self.events = []
        self.setter_calls = []
        for k,v in costs.items():
            uc.mem_write(self.impl+16+k*8, struct.pack('<d', v))
        uc.mem_write(self.shared, bytes(40))
        uc.mem_write(self.shared+0x10, struct.pack('<Q', self.impl))
        uc.mem_write(self.owner, bytes(0x1000))
        uc.mem_write(self.owner+0x400, struct.pack('<Q', self.shared if base_present else 0))
        uc.mem_write(self.root_class, bytes(0x50))
        uc.mem_write(self.output, bytes(16))
        for name, field in FIELDS.items():
            pointer, state = self.classes[name], states.get(name,'present')
            uc.mem_write(pointer, bytes(0x180))
            uc.mem_write(pointer+0x30, struct.pack('<QI', pointer+0x140, 0))
            uc.mem_write(pointer+0x140, struct.pack('<Q', self.root_class+0x30+(8 if state=='wrong_parent' else 0)))
            uc.mem_write(pointer+0x110, struct.pack('<Q', 0 if state=='missing_cdo' else self.cdos[name]))
            uc.mem_write(self.owner+field, struct.pack('<Q', 0 if state=='null' else pointer))
        before = self.snapshot()
        self.execute(0x1454da500 if entry=='lifecycle' else WRAPPERS[entry],
                     {x.UC_X86_REG_RCX:self.owner, x.UC_X86_REG_RDX:self.output})
        returned = struct.unpack('<QQ', uc.mem_read(self.output,16))
        return dict(entry=entry, states=states, base_present=base_present, callback_flag=callback_flag, before=before,
            after=self.snapshot(), events=list(self.events),
            output_has_filter=bool(returned[0]) if entry!='lifecycle' else None,
            runtime_verified=False)
