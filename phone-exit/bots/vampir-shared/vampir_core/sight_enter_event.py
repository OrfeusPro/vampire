"""Source-bound composed SightEnter wire reader.

Whole mixed-array native callbacks/copies/cleanup are checked separately. Session
semantics use static handler/typed actor bindings; engine side effects stay unknown.
"""
from .current_record_reader import CurrentRecordReader,SOURCE_SHA256


def decode_sight_enter(body,*,source_sha256,max_collection_items=1024):
    reader=CurrentRecordReader(body,source_sha256=source_sha256,max_collection_items=max_collection_items)
    value=reader.sight_enter();reader.finish();return value
