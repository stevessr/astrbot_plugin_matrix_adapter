"""User-interactive authentication for cross-signing uploads."""

import asyncio
import inspect

from astrbot.api import logger

from ....client.http_client import MatrixAPIError
from ....constants import LOGIN_TYPE_DUMMY, LOGIN_TYPE_OAUTH


class CrossSigningUploadUIAMixin:
    """Handle UIA fallback, including Matrix v1.17 ``m.oauth`` approval."""

    _OAUTH_UIA_POLL_INTERVAL_SECONDS = 2.0
    _OAUTH_UIA_MAX_ATTEMPTS = 30

    async def _retry_cross_signing_upload(
        self,
        *,
        master_key: dict,
        self_signing_key: dict,
        user_signing_key: dict,
        auth: dict,
    ) -> None:
        await self.client.upload_signing_keys(
            master_key=master_key,
            self_signing_key=self_signing_key,
            user_signing_key=user_signing_key,
            auth=auth,
        )

    async def _notify_oauth_uia_approval(self, approval: dict) -> None:
        callback = getattr(self, "oauth_uia_callback", None)
        if not callable(callback):
            return
        result = callback(dict(approval))
        if inspect.isawaitable(result):
            await result

    async def _complete_oauth_uia(
        self,
        *,
        challenge: MatrixAPIError,
        master_key: dict,
        self_signing_key: dict,
        user_signing_key: dict,
    ) -> None:
        """Complete stable MSC4312 after out-of-band OAuth approval."""
        approval = self._extract_oauth_uia_approval(challenge)
        if approval is None:
            raise RuntimeError("m.oauth UIA completion requested without m.oauth challenge")

        self.pending_oauth_uia = dict(approval)
        logger.warning(
            "[E2EE-CrossSign] Matrix 需要 OAuth 审批以替换 cross-signing keys。"
            f"请打开：{approval['url']}"
        )
        await self._notify_oauth_uia_approval(approval)

        callback = getattr(self, "oauth_uia_callback", None)
        interval = max(
            0.0,
            float(getattr(self, "_OAUTH_UIA_POLL_INTERVAL_SECONDS", 2.0)),
        )
        attempts = max(1, int(getattr(self, "_OAUTH_UIA_MAX_ATTEMPTS", 30)))
        last_error: MatrixAPIError = challenge

        for attempt in range(attempts):
            # A callback is expected to return after the user has approved the
            # action, so retry immediately. Headless/log-only mode gives the
            # user one polling interval before the first retry.
            if interval and (not callable(callback) or attempt > 0):
                await asyncio.sleep(interval)

            try:
                await self._retry_cross_signing_upload(
                    master_key=master_key,
                    self_signing_key=self_signing_key,
                    user_signing_key=user_signing_key,
                    auth=self._build_oauth_uia_completion(approval["session"]),
                )
                self.pending_oauth_uia = None
                logger.info("[E2EE-CrossSign] OAuth UIA 审批完成")
                return
            except MatrixAPIError as error:
                last_error = error
                if not self._uia_supports_stage(error, LOGIN_TYPE_OAUTH):
                    raise
                refreshed = self._extract_oauth_uia_approval(error)
                if refreshed is None:
                    raise RuntimeError("Homeserver returned an invalid m.oauth challenge")
                if refreshed != approval:
                    approval = refreshed
                    self.pending_oauth_uia = dict(approval)
                    logger.warning(
                        "[E2EE-CrossSign] OAuth UIA challenge 已更新，请使用："
                        f"{approval['url']}"
                    )
                    await self._notify_oauth_uia_approval(approval)

        raise RuntimeError(
            "OAuth UIA approval was not completed before the bounded polling window ended; "
            f"approval URL: {approval['url']}"
        ) from last_error

    async def _upload_signing_keys_with_uia(
        self,
        *,
        master_key: dict,
        self_signing_key: dict,
        user_signing_key: dict,
    ) -> None:
        try:
            await self.client.upload_signing_keys(
                master_key=master_key,
                self_signing_key=self_signing_key,
                user_signing_key=user_signing_key,
            )
            return
        except MatrixAPIError as first_error:
            # Matrix v1.17 / MSC4312: OAuth-authenticated sessions approve
            # cross-signing replacement out-of-band. Never weaken an advertised
            # m.oauth challenge to password UIA, even if its params are malformed.
            if self._uia_supports_stage(first_error, LOGIN_TYPE_OAUTH):
                await self._complete_oauth_uia(
                    challenge=first_error,
                    master_key=master_key,
                    self_signing_key=self_signing_key,
                    user_signing_key=user_signing_key,
                )
                return

            session_id = self._extract_uia_session(first_error)
            if not session_id:
                raise

            try:
                await self._retry_cross_signing_upload(
                    master_key=master_key,
                    self_signing_key=self_signing_key,
                    user_signing_key=user_signing_key,
                    auth={"type": LOGIN_TYPE_DUMMY, "session": session_id},
                )
                return
            except MatrixAPIError as dummy_error:
                if self._uia_supports_stage(dummy_error, LOGIN_TYPE_OAUTH):
                    await self._complete_oauth_uia(
                        challenge=dummy_error,
                        master_key=master_key,
                        self_signing_key=self_signing_key,
                        user_signing_key=user_signing_key,
                    )
                    return

                session_id = self._extract_uia_session(dummy_error) or session_id
                if not self.password:
                    logger.warning(
                        "[E2EE-CrossSign] 上传交叉签名密钥失败（未配置 matrix_password）"
                    )
                    raise

                await self._retry_cross_signing_upload(
                    master_key=master_key,
                    self_signing_key=self_signing_key,
                    user_signing_key=user_signing_key,
                    auth=self._build_password_auth(session_id),
                )
