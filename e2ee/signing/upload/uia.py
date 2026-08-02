"""User-interactive authentication for cross-signing uploads."""

from astrbot.api import logger

from ....client.http_client import MatrixAPIError
from ....constants import LOGIN_TYPE_DUMMY


class CrossSigningUploadUIAMixin:
    """处理交叉签名密钥上传的 UIA 回退流程。"""

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
            session_id = self._extract_uia_session(first_error)
            if not session_id:
                raise

            try:
                await self.client.upload_signing_keys(
                    master_key=master_key,
                    self_signing_key=self_signing_key,
                    user_signing_key=user_signing_key,
                    auth={"type": LOGIN_TYPE_DUMMY, "session": session_id},
                )
                return
            except MatrixAPIError as dummy_error:
                session_id = self._extract_uia_session(dummy_error) or session_id
                if not self.password:
                    logger.warning(
                        "[E2EE-CrossSign] 上传交叉签名密钥失败（未配置 matrix_password）"
                    )
                    raise

                await self.client.upload_signing_keys(
                    master_key=master_key,
                    self_signing_key=self_signing_key,
                    user_signing_key=user_signing_key,
                    auth=self._build_password_auth(session_id),
                )
