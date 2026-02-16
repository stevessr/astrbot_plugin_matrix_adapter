from astrbot.api.message_components import ComponentType, Record


def _matches_component_type(segment, expected) -> bool:
    """Best-effort matcher for component type enum / enum value / string."""
    seg_type = getattr(segment, "type", None)
    if seg_type is None:
        return False
    if seg_type == expected:
        return True
    seg_value = getattr(seg_type, "value", seg_type)
    exp_value = getattr(expected, "value", expected)
    return str(seg_value) == str(exp_value)


def is_record_component(segment) -> bool:
    """Return True for Record instance or ComponentType.Record-like segment."""
    return isinstance(segment, Record) or _matches_component_type(
        segment, ComponentType.Record
    )


def coerce_record_component(segment) -> Record | None:
    """Convert Record-like component to astrbot Record object."""
    if isinstance(segment, Record):
        return segment

    if not _matches_component_type(segment, ComponentType.Record):
        return None

    file_attr = getattr(segment, "file", None)
    if isinstance(file_attr, str) and file_attr.strip():
        return Record(file=file_attr.strip())

    path_attr = getattr(segment, "path", None)
    if isinstance(path_attr, str) and path_attr.strip():
        return Record.fromFileSystem(path_attr.strip())

    url_attr = getattr(segment, "url", None)
    if isinstance(url_attr, str) and url_attr.strip():
        url = url_attr.strip()
        if url.startswith("http://") or url.startswith("https://"):
            return Record.fromURL(url)
        if url.startswith("file:///"):
            return Record(file=url)
        return Record.fromFileSystem(url)

    data_attr = getattr(segment, "data", None)
    if isinstance(data_attr, dict):
        for key in ("file", "path", "url"):
            value = data_attr.get(key)
            if isinstance(value, str) and value.strip():
                if key == "url" and (
                    value.startswith("http://") or value.startswith("https://")
                ):
                    return Record.fromURL(value)
                if value.startswith("file:///"):
                    return Record(file=value)
                return Record.fromFileSystem(value)

    return None
