"""Recovery of Olm sessions after a missing-session decryption failure."""

import time

from astrbot.api import logger

from ....constants import DEFAULT_OLM_RECOVERY_RETRY_SEC


class E2EEManagerRequestsSessionCoreMixin:
    """主动建立新的 Olm 会话并跟踪恢复节流。"""

    async def _request_new_session(
        self, sender_key: str, sender_user_id: str | None = None
    ) -> bool:
        """
        当检测到未知一次性密钥时，主动建立新的 Olm 会话

        通过 claim 对方的一次性密钥，创建新的出站 Olm 会话，
        然后发送加密的 m.dummy 消息，通知对方使用新会话通信。

        Args:
            sender_key: 发送者的 curve25519 密钥
            sender_user_id: 可选的发送者用户 ID（如果已知，可用于查询设备）
        """
        masked_sender_key = (sender_key or "")[:8]
        if not self._olm or not sender_user_id or not sender_key:
            logger.warning(
                f"Cannot recover Olm session: sender={sender_user_id or '<empty>'} "
                f"key={masked_sender_key}..."
            )
            return False

        result = await self._find_device_by_sender_key(sender_key, sender_user_id)
        if not result:
            # Never pick an arbitrary device. It would not repair the session
            # associated with the sender Curve25519 identity key.
            logger.warning(
                f"No signed device matches sender_key {masked_sender_key}..."
            )
            return False
        target_user, target_device = result

        attempts = getattr(self, "_olm_recovery_attempts", None)
        if not isinstance(attempts, dict):
            attempts = {}
            self._olm_recovery_attempts = attempts
        attempt_key = (target_user, target_device)
        now = time.monotonic()
        retry_interval = float(
            getattr(
                self,
                "_olm_recovery_retry_interval_sec",
                DEFAULT_OLM_RECOVERY_RETRY_SEC,
            )
        )
        last_attempt = attempts.get(attempt_key)
        if last_attempt is not None and now - float(last_attempt) < retry_interval:
            return False
        attempts[attempt_key] = now

        return await self._establish_new_olm_session(
            target_user,
            target_device,
            sender_key,
        )

    def _mark_olm_send_succeeded(self, user_id: str, device_id: str) -> None:
        """Allow a future m.no_olm after a successful Olm communication."""
        sent = getattr(self, "_no_olm_withheld_sent", None)
        if isinstance(sent, set):
            sent.discard((user_id, device_id))
