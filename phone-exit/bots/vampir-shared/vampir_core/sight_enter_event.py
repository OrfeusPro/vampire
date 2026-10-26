"""Composed SightEnter wire reader; not enabled in a live session yet.

Outer order is source-bound; whole mixed-array native callbacks and handler/world
association must be verified before assigning semantics or enabling runtime ID301.
"""
from .current_record_reader import CurrentRecordReader,SOURCE_SHA256


def decode_sight_enter(body,*,source_sha256,max_collection_items=1024):
    reader=CurrentRecordReader(body,source_sha256=source_sha256,max_collection_items=max_collection_items)
    value=reader.sight_enter();reader.finish();return value
