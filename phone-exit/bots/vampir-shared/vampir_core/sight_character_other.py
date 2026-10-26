"""Source-bound whole PktCharacterOther; actor/world meaning is separate."""
from .current_record_reader import CurrentRecordReader,SOURCE_SHA256


def decode_character_other(body,*,source_sha256,max_collection_items=1024):
    reader=CurrentRecordReader(body,source_sha256=source_sha256,max_collection_items=max_collection_items)
    value=reader.character_other();reader.finish();return value
