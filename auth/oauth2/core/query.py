"""Query parameter compatibility helpers for web callbacks."""


def _get_request_query_params(request) -> object:
    if request is None:
        return {}

    params = getattr(request, "args", None)
    if params is not None:
        return params

    params = getattr(request, "query_params", None)
    if params is not None:
        return params

    params = getattr(request, "query", None)
    if params is not None:
        return params

    rel_url = getattr(request, "rel_url", None)
    params = getattr(rel_url, "query", None)
    if params is not None:
        return params

    return {}


def _get_query_param(params: object, name: str, default: str = "") -> str:
    """Return the first scalar query value from common web-framework mappings."""
    if params is None:
        return default

    getall = getattr(params, "getall", None)
    if callable(getall):
        try:
            values = getall(name)
            if values:
                value = values[0]
                return str(value) if value is not None else default
        except Exception:
            pass

    getter = getattr(params, "get", None)
    if callable(getter):
        try:
            value = getter(name, default)
        except TypeError:
            try:
                value = getter(name)
            except Exception:
                value = default
        except Exception:
            value = default
    elif isinstance(params, dict):
        value = params.get(name, default)
    else:
        value = default

    if isinstance(value, (list, tuple)):
        value = value[0] if value else default
    if value is None:
        return default
    return str(value)


def _has_query_param(params: object, name: str) -> bool:
    if params is None:
        return False
    try:
        return name in params
    except Exception:
        pass
    return _get_query_param(params, name, "") != ""
