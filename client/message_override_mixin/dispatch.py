"""Message hook transformation and short-circuit dispatch."""

import inspect
from typing import Any

from astrbot.api import logger


class MessageOverrideDispatchMixin:
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
