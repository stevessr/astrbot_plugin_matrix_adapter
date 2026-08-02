"""Backup recovery policy operations."""

import time

from astrbot.api import logger


class KeyBackupRestorePolicyMixin:
    """判断当前账户是否需要执行密钥备份恢复。"""

    def should_restore_for_session(
        self, session_id: str | None = None, force: bool = False
    ) -> bool:
        """Whether backup restoration should run for current account state."""
        if force:
            return self.can_attempt_restore()

        if not self.can_attempt_restore():
            return False

        # This account already has keys: skip restore by default.
        if self.has_local_room_keys():
            return False

        # If a specific session already exists locally, skip.
        if session_id and self.store.has_megolm_inbound(session_id):
            return False

        now = time.monotonic()
        if now - self._last_restore_attempt_ts < self._restore_cooldown_sec:
            return False
        return True

    async def restore_room_keys_if_needed(
        self,
        session_id: str | None = None,
        reason: str = "runtime",
        force: bool = False,
    ) -> bool:
        """Restore keys from backup only when account key state requires it."""
        if not self.should_restore_for_session(session_id=session_id, force=force):
            logger.debug(f"跳过备份恢复：reason={reason} session={session_id or '-'}")
            return False
        return await self.restore_room_keys()
