"""Source-bound CharacterSelect body, without network or session assumptions."""
from dataclasses import dataclass, field
import struct

SOURCE_SHA256='c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8'


@dataclass(frozen=True,slots=True)
class CharacterSelectPayload:
    """Raw fields at native offsets10/18/20; meanings are not all established."""
    raw10: int=field(repr=False)
    raw18: int=field(repr=False)
    raw20: int=field(repr=False)

    def __post_init__(self):
        for value,maximum in ((self.raw10,2**64-1),(self.raw18,2**32-1),(self.raw20,2**64-1)):
            if type(value) is not int or not 0<=value<=maximum:
                raise ValueError('CharacterSelect requires unsigned raw integer fields')

    def encode(self,*,max_payload_size):
        if type(max_payload_size) is not int or not 0<=max_payload_size<=0xffffff:
            raise ValueError('CharacterSelect requires an explicit byte budget')
        if max_payload_size<20:raise BufferError('CharacterSelect exceeds local byte budget')
        return struct.pack('<QIQ',self.raw10,self.raw18,self.raw20)
