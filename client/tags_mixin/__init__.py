"""Composable Matrix room tag operations."""

from typing import Any  # noqa: F401

from ..path_utils import quote_path_segment  # noqa: F401
from .mutations import TagsMutationMixin
from .read import TagsReadMixin


class TagsMixin(
    TagsReadMixin,
    TagsMutationMixin,
):
    """Room tag management methods for Matrix client."""

    pass


# Preserve direct method attributes exposed by the former mixin.
TagsMixin.get_room_tags = TagsReadMixin.__dict__["get_room_tags"]
TagsMixin.set_room_tag = TagsMutationMixin.__dict__["set_room_tag"]
TagsMixin.delete_room_tag = TagsMutationMixin.__dict__["delete_room_tag"]


__all__ = ["Any", "TagsMixin", "quote_path_segment"]
