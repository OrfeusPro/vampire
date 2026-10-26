"""Explicit immutable projection audit input; never selects a manifest implicitly."""
import hashlib
import json
from pathlib import Path
from .map_position import MapProjection

def load_projection(path,*,source_sha256):
    path=Path(path).resolve(strict=True)
    if path.stat().st_size>1048576:raise ValueError('Projection audit exceeds limit')
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=path.parent.name:raise ValueError('Immutable projection audit required')
    manifest=json.loads(raw)
    projection=MapProjection(manifest,source_sha256=source_sha256)
    archive=manifest['installed_archive'];source=Path(archive['path']);before=source.stat()
    with source.open('rb') as stream:
        if hashlib.file_digest(stream,'sha256').hexdigest()!=archive['sha256']:raise ValueError('Map archive changed since audit')
    after=source.stat()
    if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):raise ValueError('Map archive changed during validation')
    return projection
