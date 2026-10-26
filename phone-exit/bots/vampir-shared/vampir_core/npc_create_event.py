"""Source-bound ID324 wire record; actor, visibility and world semantics are separate."""
from dataclasses import dataclass,field

from .character_select_result import SelectionRecord

SOURCE_SHA256='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'


@dataclass(frozen=True,slots=True)
class NpcCreateNotify:
    flag:bool
    data:SelectionRecord=field(repr=False)

    @property
    def npc(self):return self.data.at(8)


def decode_npc_create_notify(body,*,source_sha256,max_collection_items=1024):
    """Consume exactly one body, charging every nested wire entry including duplicate keys.

    Offsets are native object offsets; no NPC ID/name/world meaning is assigned.
    Heading retains the original byte before native math canonicalization. Vector
    bits are retained, and require finite_values() before use as coordinates.
    """
    from .current_record_reader import CurrentRecordReader
    reader=CurrentRecordReader(body,source_sha256=source_sha256,max_collection_items=max_collection_items)
    flag=reader.flag();data=reader.npc_create_data();reader.finish()
    return NpcCreateNotify(flag,data)
