"""Auto-accept/reject/manual policy for in-room verification requests."""

import asyncio

from astrbot.api import logger


class SASVerificationRoomRequestPolicyMixin:
    """按 auto_verify_mode 处理房间内验证请求。"""

    async def _apply_room_request_policy(
        self,
        session: dict,
        methods: list,
        transaction_id: str,
    ):
        if self.auto_verify_mode == "auto_reject":
            logger.info("[E2EE-Verify] 自动拒绝验证请求 (mode=auto_reject)")
            await self._send_in_room_cancel(
                session["room_id"], transaction_id, "m.user", "自动拒绝"
            )
            return

        if self.auto_verify_mode == "manual":
            logger.info(
                "[E2EE-Verify] 手动模式，发送 ready 并等待管理员确认 (mode=manual)"
            )
            if "m.sas.v1" in methods:
                # 触发一次自身设备密钥查询，帮助服务器同步我们的设备信息
                try:
                    await self.client.query_keys({self.user_id: []})
                    logger.debug("[E2EE-Verify] 已触发自身设备密钥查询")
                except Exception as e:
                    logger.debug(f"[E2EE-Verify] 自身密钥查询失败（非关键）：{e}")

                await asyncio.sleep(1.0)
                await self._send_in_room_ready(session["room_id"], transaction_id)
            else:
                await self._send_in_room_cancel(
                    session["room_id"],
                    transaction_id,
                    "m.unknown_method",
                    "不支持的验证方法",
                )
            return

        # auto_accept: 发送 ready
        if "m.sas.v1" in methods:
            logger.info("[E2EE-Verify] 自动接受房间内验证请求 (mode=auto_accept)")
            # 触发一次自身设备密钥查询，帮助服务器同步我们的设备信息
            # 这有助于确保对方客户端能获取到我们的设备密钥
            try:
                await self.client.query_keys({self.user_id: []})
                logger.debug("[E2EE-Verify] 已触发自身设备密钥查询")
            except Exception as e:
                logger.debug(f"[E2EE-Verify] 自身密钥查询失败（非关键）：{e}")

            # 等待一小段时间，让设备密钥有时间在服务器间传播
            # 这有助于避免 "unknown_device" 错误
            await asyncio.sleep(1.0)
            await self._send_in_room_ready(session["room_id"], transaction_id)
        else:
            logger.warning(f"[E2EE-Verify] 不支持的验证方法：{methods}")
            await self._send_in_room_cancel(
                session["room_id"],
                transaction_id,
                "m.unknown_method",
                "不支持的验证方法",
            )
