"""
Matrix HTTP Client - Message Override Mixin

在「发送消息」与「获取消息」两条链路的前后插入可覆写钩子，用于统一改写
content、命中本地缓存或旁路埋点，而不必改动散落各处的调用点。

两种扩展方式：

1. 子类覆写 ``before_send_message`` 等钩子方法（调用 ``super()`` 可保留
   注册式钩子的行为）；
2. 运行时 ``client.register_message_hook(hook)``，``hook`` 只需实现
   ``HOOK_METHODS`` 中的任意子集。``MatrixHTTPClient`` 由适配器直接实例化，
   因此注册式钩子是无需改动实例化点的接入方式。

钩子约定：

- ``before_send_message`` / ``after_*``：返回非 ``None`` 即替换当前值，
  返回 ``None`` 表示不改动；多个钩子按注册顺序串联。
- ``before_get_event`` / ``before_room_messages``：返回非 ``None`` 即作为
  最终结果**短路**掉 HTTP 请求（例如缓存命中）；若只想改写查询参数，请就地
  修改传入的 ``params`` 字典并返回 ``None``。

钩子抛出的异常一律被吞掉并记录告警，避免第三方钩子打断消息收发。
"""

import inspect
from typing import Any

from astrbot.api import logger


class MessageOverrideMixin:
    """Overridable hooks around message send/fetch.

    组合进 ``MatrixHTTPClient`` 时必须排在 ``RoomMixin`` 与 ``MessageMixin``
    之前，``super()`` 才能沿 MRO 落到真正发起 HTTP 的实现上。
    """

    HOOK_METHODS = (
        "before_send_message",
        "after_send_message",
        "before_get_event",
        "after_get_event",
        "before_room_messages",
        "after_room_messages",
    )

    # ------------------------------------------------------------------
    # 钩子注册
    # ------------------------------------------------------------------
    @property
    def message_hooks(self) -> list[Any]:
        """已注册的消息钩子（按注册顺序）。"""
        hooks = getattr(self, "_message_hooks", None)
        if hooks is None:
            hooks = []
            self._message_hooks = hooks
        return hooks

    def register_message_hook(self, hook: Any) -> bool:
        """注册消息钩子；重复注册或未实现任何钩子方法时返回 ``False``。"""
        if hook is None or hook in self.message_hooks:
            return False
        if not any(callable(getattr(hook, name, None)) for name in self.HOOK_METHODS):
            logger.warning("Matrix 消息钩子未实现任何钩子方法，已忽略注册")
            return False
        self.message_hooks.append(hook)
        return True

    def unregister_message_hook(self, hook: Any) -> bool:
        """注销消息钩子；未注册过时返回 ``False``。"""
        try:
            self.message_hooks.remove(hook)
        except ValueError:
            return False
        return True

    # ------------------------------------------------------------------
    # 钩子分发
    # ------------------------------------------------------------------
    async def _transform_via_hooks(self, method: str, value: Any, *context: Any) -> Any:
        """依次调用各钩子，非 ``None`` 返回值替换当前 ``value``。"""
        for hook in list(self.message_hooks):
            fn = getattr(hook, method, None)
            if not callable(fn):
                continue
            try:
                result = fn(*context, value)
                if inspect.isawaitable(result):
                    result = await result
            except Exception as e:
                logger.warning(f"Matrix 消息钩子 {method} 执行失败，已跳过：{e}")
                continue
            if result is not None:
                value = result
        return value

    async def _short_circuit_via_hooks(self, method: str, *context: Any) -> Any:
        """依次调用各钩子，首个非 ``None`` 返回值直接作为结果短路。"""
        for hook in list(self.message_hooks):
            fn = getattr(hook, method, None)
            if not callable(fn):
                continue
            try:
                result = fn(*context)
                if inspect.isawaitable(result):
                    result = await result
            except Exception as e:
                logger.warning(f"Matrix 消息钩子 {method} 执行失败，已跳过：{e}")
                continue
            if result is not None:
                return result
        return None

    # ------------------------------------------------------------------
    # 可覆写钩子（默认转交注册式钩子）
    # ------------------------------------------------------------------
    async def before_send_message(
        self, room_id: str, msg_type: str, content: dict[str, Any]
    ) -> dict[str, Any]:
        return await self._transform_via_hooks(
            "before_send_message", content, room_id, msg_type
        )

    async def after_send_message(
        self,
        room_id: str,
        msg_type: str,
        content: dict[str, Any],
        response: dict[str, Any],
    ) -> dict[str, Any]:
        return await self._transform_via_hooks(
            "after_send_message", response, room_id, msg_type, content
        )

    async def before_get_event(
        self, room_id: str, event_id: str
    ) -> dict[str, Any] | None:
        return await self._short_circuit_via_hooks(
            "before_get_event", room_id, event_id
        )

    async def after_get_event(
        self, room_id: str, event_id: str, event: dict[str, Any]
    ) -> dict[str, Any]:
        return await self._transform_via_hooks(
            "after_get_event", event, room_id, event_id
        )

    async def before_room_messages(
        self, room_id: str, params: dict[str, Any]
    ) -> dict[str, Any] | None:
        return await self._short_circuit_via_hooks(
            "before_room_messages", room_id, params
        )

    async def after_room_messages(
        self, room_id: str, params: dict[str, Any], response: dict[str, Any]
    ) -> dict[str, Any]:
        return await self._transform_via_hooks(
            "after_room_messages", response, room_id, params
        )

    # ------------------------------------------------------------------
    # 包装真实实现
    # ------------------------------------------------------------------
    async def send_message(
        self,
        room_id: str,
        msg_type: str,
        content: dict[str, Any],
        txn_id: str | None = None,
        tracker_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        content = await self.before_send_message(room_id, msg_type, content)
        response = await super().send_message(
            room_id,
            msg_type,
            content,
            txn_id=txn_id,
            tracker_metadata=tracker_metadata,
        )
        return await self.after_send_message(room_id, msg_type, content, response)

    async def get_event(self, room_id: str, event_id: str) -> dict[str, Any]:
        cached = await self.before_get_event(room_id, event_id)
        if cached is not None:
            return cached
        event = await super().get_event(room_id, event_id)
        return await self.after_get_event(room_id, event_id, event)

    async def room_messages(
        self,
        room_id: str,
        from_token: str | None = None,
        to_token: str | None = None,
        direction: str = "b",
        limit: int = 10,
    ) -> dict[str, Any]:
        # 钩子可就地改写 params 以调整查询，或返回非 None 直接短路。
        params: dict[str, Any] = {
            "from_token": from_token,
            "to_token": to_token,
            "direction": direction,
            "limit": limit,
        }
        cached = await self.before_room_messages(room_id, params)
        if cached is not None:
            return cached
        response = await super().room_messages(
            room_id,
            from_token=params.get("from_token"),
            to_token=params.get("to_token"),
            direction=params.get("direction", "b"),
            limit=params.get("limit", 10),
        )
        return await self.after_room_messages(room_id, params, response)
