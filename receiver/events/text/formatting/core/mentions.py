"""Plain component and mention append helpers."""

from astrbot.api.message_components import At, Plain

from ..patterns import PLAIN_MENTION_RE


def _append_plain(chain, value: str) -> None:
    if not value:
        return
    if chain.chain and isinstance(chain.chain[-1], Plain):
        chain.chain[-1].text += value
    else:
        chain.chain.append(Plain(value))


def _add_mention(
    chain, seen_mentions: set[str], user_id: str, display_name: str | None = None
) -> None:
    if not user_id or user_id in seen_mentions:
        return
    seen_mentions.add(user_id)
    chain.chain.append(At(qq=user_id, name=display_name or user_id))


def _consume_leading_plain_mention(
    chain, receiver, seen_mentions: set[str], start_index: int
) -> bool:
    if start_index >= len(chain.chain):
        return False
    component = chain.chain[start_index]
    if not isinstance(component, Plain) or not receiver.bot_name:
        return False
    plain_mention_match = PLAIN_MENTION_RE.match(component.text)
    if not plain_mention_match:
        return False
    mention_name = plain_mention_match.group(1).strip()
    if mention_name != receiver.bot_name:
        return False

    remaining_text = component.text[plain_mention_match.end() :].lstrip()
    del chain.chain[start_index]
    _add_mention(chain, seen_mentions, receiver.user_id, receiver.bot_name)
    if remaining_text:
        chain.chain.insert(start_index + 1, Plain(remaining_text))
    return True
