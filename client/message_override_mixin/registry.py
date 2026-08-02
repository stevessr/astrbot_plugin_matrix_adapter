"""Runtime message hook registration."""

from typing import Any

from astrbot.api import logger


class MessageOverrideRegistryMixin:
    HOOK_METHODS = (
        "before_send_message",
        "after_send_message",
        "before_get_event",
        "after_get_event",
        "before_room_messages",
        "after_room_messages",
    )

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
