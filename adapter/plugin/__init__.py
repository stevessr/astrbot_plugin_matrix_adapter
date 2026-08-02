"""AstrBot Matrix plugin entrypoint and command registrations."""

import bleach  # noqa: F401
import markdown_it  # noqa: F401

from astrbot.api import logger  # noqa: F401
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, register
from astrbot.core.star.filter.permission import PermissionType

from ...constants import PREFIX_ED25519  # noqa: F401
from ...utils import MatrixUtils
from .commands import approve_device as _approve_device
from .lifecycle import initialize_plugin
from .reaction import matrix_react_to_event as _matrix_react_to_event


@register(
    "astrbot_plugin_matrix_adapter",
    "stevessr",
    "Matrix 协议适配器，支持端到端加密、消息线程等功能",
    "0.3.1",
)
class MatrixPlugin(Star):
    def __init__(self, context: Context, config=None):
        super().__init__(context, config)
        initialize_plugin(config)

    @filter.llm_tool(name="matrix_react_to_event")
    async def matrix_react_to_event(
        self,
        event: AstrMessageEvent,
        message_content: str,
        reaction: str,
        time: str = "",
        matrix_platform_id: str = "",
        room_id: str = "",
    ) -> str:
        """React to the nearest Matrix message matching the given content.

        Prefer exact body matches, then substring matches. When ``time`` is omitted,
        the search anchors at the current tool-call time (or the inbound message
        timestamp when available).

        Args:
            message_content(string): Text used to locate the target Matrix message.
                Exact matches are preferred over substring matches.
            reaction(string): Unicode emoji, emoji/sticker shortcode (e.g. ``:smile:``
                or ``thinking``), or custom Matrix reaction key / ``mxc://`` URL.
            time(string): Optional anchor time. Accepts Unix seconds/ms or ISO-8601.
                Defaults to now / inbound message time.
            matrix_platform_id(string): AstrBot Matrix platform ID. Required only
                when the current event is not Matrix and multiple Matrix adapters run.
            room_id(string): Optional Matrix room ID. Defaults to the current Matrix
                room.

        Returns:
            A concise status message for the next LLM turn.
        """
        return await _matrix_react_to_event(
            self,
            event,
            message_content,
            reaction,
            time,
            matrix_platform_id,
            room_id,
        )

    # ========== Commands ==========
    # 装饰器必须定义在 main.py 中，否则 handler 的 __module__ 不匹配

    @filter.command("approve_device")
    @filter.permission_type(PermissionType.ADMIN)
    async def approve_device(
        self,
        event: AstrMessageEvent,
        user_id: str,
        device_id: str,
        matrix_platform_id: str = "",
    ):
        """手动批准 Matrix 设备

        用法：
            /approve_device <用户 ID> <设备 ID> [matrix_platform_id]

        示例：
            /approve_device @user:example.com DEVICEID123
            /approve_device @user:example.com DEVICEID123 matrix-main
        """
        async for result in _approve_device(
            self,
            event,
            user_id,
            device_id,
            matrix_platform_id,
        ):
            yield result


__all__ = ["MatrixPlugin", "MatrixUtils"]
