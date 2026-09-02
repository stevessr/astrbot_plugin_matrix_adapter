"""Sync API error handling."""

import asyncio
import time

from astrbot.api import logger

from ....client.http_client import MatrixAPIError

_TOKEN_INVALID_ERRCODES = {"M_UNKNOWN_TOKEN", "M_MISSING_TOKEN"}
_ACCOUNT_RESTRICTION_ERRCODES = {"M_USER_LOCKED", "M_USER_SUSPENDED"}


class MatrixSyncManagerLoopFailureMixin:
    """Record and back off from Matrix API sync failures."""

    async def _handle_sync_api_error(self, e: MatrixAPIError):
        self._last_sync_failure_at = time.time()
        self._sync_failure_count += 1
        self._last_sync_error = str(e)
        self._sync_consecutive_failures += 1

        errcode = e.errcode
        if errcode in _ACCOUNT_RESTRICTION_ERRCODES:
            # Matrix v1.12 / MSC3939 requires M_USER_LOCKED clients to retain
            # the session (including E2EE state) and continue probing the server
            # at a limited rate so an unlock can be detected. MSC3823 suspension
            # is likewise an account-state error, not evidence that the access
            # token itself is invalid. Never route either condition through the
            # token refresh / re-login callback.
            soft_logout = (
                isinstance(e.data, dict) and e.data.get("soft_logout") is True
            )
            logger.warning(
                "Matrix account restricted during /sync "
                f"({errcode}, soft_logout={soft_logout}); preserving session"
            )
            await asyncio.sleep(10)
        elif e.status == 401 and errcode in _TOKEN_INVALID_ERRCODES:
            logger.error(f"Sync access token rejected ({errcode}): {e}")
            token_refreshed = False
            if self.on_token_invalid:
                try:
                    token_refreshed = await self.on_token_invalid()
                except Exception as cb_e:
                    logger.error(f"Token invalid callback failed: {cb_e}")
            if not token_refreshed:
                await asyncio.sleep(10)
        elif e.status in (401, 403):
            # Authentication/authorization errors other than the standard token
            # invalidation codes are not grounds for rotating credentials. This
            # avoids destructive refresh/re-login loops for new stable errcodes.
            logger.warning(
                f"Sync request rejected without token invalidation ({errcode}): {e}"
            )
            await asyncio.sleep(10)
        elif e.status == 429:
            retry_after_ms = (
                e.data.get("retry_after_ms", 5000)
                if isinstance(e.data, dict)
                else 5000
            )
            await asyncio.sleep(retry_after_ms / 1000.0)
        elif hasattr(self, "_retry_policy") and self._retry_policy is not None:
            await self._retry_policy.sleep(
                self._sync_consecutive_failures,
                f"Sync API error: {e}",
            )
        else:
            await asyncio.sleep(5)


__all__ = ["MatrixSyncManagerLoopFailureMixin"]
