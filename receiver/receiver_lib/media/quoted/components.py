"""Quoted-media HTTP component append helpers."""

from astrbot.api.message_components import File, Image, Record, Video

from .....constants import MSGTYPE_AUDIO, MSGTYPE_FILE, MSGTYPE_IMAGE, MSGTYPE_VIDEO


def append_http_component(chain, msgtype: str, filename: str, http_url: str) -> bool:
    """Append a remote-URL media component to the chain when supported."""
    if msgtype == MSGTYPE_IMAGE:
        chain.chain.append(Image.fromURL(http_url))
        return True
    if msgtype == MSGTYPE_VIDEO:
        chain.chain.append(Video.fromURL(http_url))
        return True
    if msgtype == MSGTYPE_AUDIO:
        chain.chain.append(Record.fromURL(http_url))
        return True
    if msgtype == MSGTYPE_FILE:
        chain.chain.append(File(name=filename, url=http_url))
        return True
    return False
