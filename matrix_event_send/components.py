from astrbot.api.message_components import BaseMessageComponent, ComponentType

from ..constants import M_POLL, M_POLL_KIND_DISCLOSED, M_POLL_START


class Poll(BaseMessageComponent):
    type = ComponentType.Unknown
    question: str
    answers: list[str]
    max_selections: int | None = 1
    kind: str | None = M_POLL_KIND_DISCLOSED
    event_type: str | None = M_POLL_START
    poll_key: str | None = M_POLL
    fallback_text: str | None = None
    fallback_html: str | None = None

    def __init__(
        self,
        question: str,
        answers: list[str],
        max_selections: int | None = 1,
        kind: str | None = M_POLL_KIND_DISCLOSED,
        event_type: str | None = M_POLL_START,
        poll_key: str | None = M_POLL,
        fallback_text: str | None = None,
        fallback_html: str | None = None,
        **_,
    ):
        super().__init__(
            question=question,
            answers=answers,
            max_selections=max_selections,
            kind=kind,
            event_type=event_type,
            poll_key=poll_key,
            fallback_text=fallback_text,
            fallback_html=fallback_html,
            **_,
        )
