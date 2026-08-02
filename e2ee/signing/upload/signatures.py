"""Signature upload and server-state confirmation helpers."""

import asyncio

from astrbot.api import logger


class CrossSigningUploadSignaturesMixin:
    """上传交叉签名并确认服务器状态。"""

    async def _upload_signature_and_confirm(
        self,
        upload_payload: dict,
        verify,
        failure_context: str,
    ) -> bool:
        upload_response = await self.client.upload_signatures(signatures=upload_payload)
        failures = (
            upload_response.get("failures")
            if isinstance(upload_response, dict)
            else None
        )
        if isinstance(failures, dict) and failures:
            logger.warning(
                f"[E2EE-CrossSign] {failure_context}上传被服务器拒绝：failures={failures}"
            )
            return False

        for _ in range(5):
            if await verify():
                return True
            await asyncio.sleep(1.0)

        logger.warning(f"[E2EE-CrossSign] {failure_context}未在服务器状态中出现")
        return False
