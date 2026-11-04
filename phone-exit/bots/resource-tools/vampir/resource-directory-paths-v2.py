"""Полные компоненты PAK directory и ограниченное соединение mount / dir / name."""


LIMIT = 32 * 1024 * 1024
MAX_ENTRIES = 100000
MAX_DIRECTORIES = 10000


def directory_parts(raw, expected_count, Cursor):
    """Preserve the legacy path/offset alongside its authenticated components."""
    if (not isinstance(raw, (bytes, bytearray)) or not 0 < len(raw) <= LIMIT
            or type(expected_count) is not int or not 0 <= expected_count <= MAX_ENTRIES):
        raise ValueError('Invalid directory component input')
    cursor = Cursor(raw)
    count = cursor.number('<I')
    if count > MAX_DIRECTORIES:
        raise ValueError('Directory component count exceeds budget')
    rows, seen = [], set()
    for _ in range(count):
        directory = cursor.string()
        files = cursor.number('<I')
        if files > expected_count or len(rows) + files > expected_count:
            raise ValueError('Directory component file count inconsistent')
        for _ in range(files):
            name, offset = cursor.string(), cursor.number('<i')
            path = directory + name
            if path in seen or offset < 0:
                raise ValueError('Duplicate or unsupported directory component entry')
            seen.add(path)
            rows.append(dict(path=path, encoded_entry_offset=offset,
                directory=directory, name=name))
    if len(rows) != expected_count or len(raw) - cursor.pos > 15:
        raise ValueError('Directory component count/trailer mismatch')
    return dict(directory_count=count, file_count=len(rows),
        trailing_bytes=len(raw) - cursor.pos, entries=rows)


def canonical_path(mount, directory, name, format_helper):
    """Trim one directory separator only at the verified mount boundary.

    CUE4Parse ReadIndexUpdated joins mount, directory and filename, trimming
    one leading slash from the directory when the mount ends with a slash.
    Names never receive this permission. The existing strict logical-path
    validator retains traversal, platform-path and budget boundaries.
    """
    if (not isinstance(mount, str) or not mount.endswith('/')
            or not isinstance(directory, str) or not isinstance(name, str)
            or not name or name.startswith('/')):
        raise ValueError('Unsupported directory mount/name form')
    if directory.startswith('/'):
        directory = directory[1:]
    return format_helper.canonical_path(mount, directory + name)
