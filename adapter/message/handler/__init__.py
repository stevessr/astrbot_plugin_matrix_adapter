"""Composable Matrix adapter message handling operations."""

import time

from astrbot.api import logger

from ....constants import (
    M_REACTION,
    M_ROOM_ENCRYPTED,
    M_ROOM_MESSAGE,
    M_ROOM_REDACTION,
    MSGTYPE_AUDIO,
    MSGTYPE_FILE,
    MSGTYPE_IMAGE,
    MSGTYPE_NOTICE,
    MSGTYPE_STICKER,
    MSGTYPE_VIDEO,
    REL_TYPE_REPLACE,
)
from .. import get_plugin_config
from ..archive import (
    _append_stalk_archive,
    _find_stalk_archive_message,
    _is_live_message_draft,
    _normalize_text,
)
from .callback import MatrixAdapterMessageCallbackMixin
from .common import _get_plugin_config
from .dispatch import MatrixAdapterMessageDispatchMixin
from .reaction import MatrixAdapterMessageReactionMixin


class MatrixAdapterMessageMixin(
    MatrixAdapterMessageReactionMixin,
    MatrixAdapterMessageCallbackMixin,
    MatrixAdapterMessageDispatchMixin,
):
    """Matrix message callback and event conversion integration."""

    pass


# Preserve direct method attributes exposed by the former monolithic mixin.
for _mixin in (
    MatrixAdapterMessageReactionMixin,
    MatrixAdapterMessageCallbackMixin,
    MatrixAdapterMessageDispatchMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if callable(_method) and not _method_name.startswith("__"):
            setattr(MatrixAdapterMessageMixin, _method_name, _method)


__all__ = [
    "M_REACTION",
    "M_ROOM_ENCRYPTED",
    "M_ROOM_MESSAGE",
    "M_ROOM_REDACTION",
    "MSGTYPE_AUDIO",
    "MSGTYPE_FILE",
    "MSGTYPE_IMAGE",
    "MSGTYPE_NOTICE",
    "MSGTYPE_STICKER",
    "MSGTYPE_VIDEO",
    "MatrixAdapterMessageCallbackMixin",
    "MatrixAdapterMessageDispatchMixin",
    "MatrixAdapterMessageMixin",
    "MatrixAdapterMessageReactionMixin",
    "REL_TYPE_REPLACE",
    "_append_stalk_archive",
    "_find_stalk_archive_message",
    "_get_plugin_config",
    "_is_live_message_draft",
    "_normalize_text",
    "get_plugin_config",
    "logger",
    "time",
]
