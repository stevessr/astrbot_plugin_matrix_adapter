"""Aggregated (non-live) streaming message dispatch."""

from astrbot.api.event import MessageChain


class MatrixPlatformEventMessagesAggregateMixin:
    """Aggregate generator output into plain room messages."""

    async def _send_streaming_aggregated(self, generator, *, metric_cls) -> None:
        used_self_send = False
        buffer = ""
        async for chain in generator:
            if not isinstance(chain, MessageChain):
                continue
            if chain.type == "break":
                if buffer:
                    await self.send(MessageChain().message(buffer))
                    used_self_send = True
                    buffer = ""
                self._response_thread_context = None
                continue
            text = chain.get_plain_text()
            if text:
                buffer += text
        if buffer:
            await self.send(MessageChain().message(buffer))
            used_self_send = True
        if not used_self_send:
            await self._mark_stream_operation(metric_cls)
