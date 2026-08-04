"""Formatted Matrix text -> message chain conversion."""

from astrbot.api.message_components import AtAll

from ......constants import MATRIX_HTML_FORMAT
from ..patterns import PLAIN_MENTION_RE
from .inline import _append_formatted_body
from .mentions import _add_mention, _append_plain


def append_formatted_text(
    receiver,
    chain,
    text: str,
    content: dict,
) -> None:
    text = text or ""
    content = content or {}
    mentions = content.get("m.mentions") or {}
    format_type = content.get("format") or ""
    formatted_body = content.get("formatted_body") or ""
    if format_type != MATRIX_HTML_FORMAT:
        formatted_body = ""

    seen_mentions: set[str] = set()

    inline_added = False
    appended_from_formatted = len(chain.chain)
    if formatted_body:
        inline_added = _append_formatted_body(
            chain,
            seen_mentions,
            receiver,
            formatted_body,
            appended_from_formatted,
        )

    if isinstance(mentions, dict) and mentions.get("room"):
        chain.chain.append(AtAll())

    if isinstance(mentions, dict):
        for user_id in mentions.get("user_ids", []) or []:
            if isinstance(user_id, str) and user_id.startswith("@"):
                _add_mention(chain, seen_mentions, user_id)

    if not inline_added:
        # Some clients only emit plain-text MXID mentions without m.mentions.
        if receiver.user_id and receiver.user_id in text:
            _add_mention(
                chain,
                seen_mentions,
                receiver.user_id,
                receiver.bot_name or receiver.user_id,
            )
            text = text.replace(receiver.user_id, "", 1).lstrip()

        if receiver.bot_name and text.startswith(f"@{receiver.bot_name}"):
            text = text[len(receiver.bot_name) + 1 :].lstrip()
            _add_mention(chain, seen_mentions, receiver.user_id, receiver.bot_name)

        plain_mention_match = PLAIN_MENTION_RE.match(text)
        if plain_mention_match and receiver.bot_name:
            mention_name = plain_mention_match.group(1).strip()
            if mention_name == receiver.bot_name:
                _add_mention(chain, seen_mentions, receiver.user_id, receiver.bot_name)
                text = text[plain_mention_match.end() :].lstrip()

        if text:
            _append_plain(chain, text)
