"""Source-bound CharacterSelect body, without network or session assumptions."""
from dataclasses import dataclass, field
import struct
from .character_list import CharacterListBody

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

    @classmethod
    def from_character_list(cls,body,index,*,state_raw_f0):
        """Fields used by the verified UI indexed-record path, without I/O.

        The caller supplies the accepted current list after session/policy gates
        and current rawF0 state (initially body.tail[3], mutable through the native
        setter). This builder does not establish readiness or send a packet.
        """
        if not isinstance(body,CharacterListBody) or body.result_code!=0:
            raise ValueError('CharacterSelect requires an accepted character list')
        if type(index) is not int or not 0<=index<len(body.records):
            raise ValueError('CharacterSelect index is outside the current list')
        return cls(body.records[index].u64[0],0,state_raw_f0)

    def encode(self,*,max_payload_size):
        if type(max_payload_size) is not int or not 0<=max_payload_size<=0xffffff:
            raise ValueError('CharacterSelect requires an explicit byte budget')
        if max_payload_size<20:raise BufferError('CharacterSelect exceeds local byte budget')
        return struct.pack('<QIQ',self.raw10,self.raw18,self.raw20)
