"""Device-key upload orchestration."""

from astrbot.api import logger

from .....constants import (
    MEGOLM_ALGO,
    OLM_ALGO,
    SIGNED_CURVE25519,
)


class E2EEManagerDeviceKeysCoreMixin:
    """上传设备身份密钥、一次性密钥和 fallback key。"""

    async def _upload_device_keys(self):
        """上传设备密钥到服务器"""
        if not self._olm:
            logger.warning("OlmMachine 未初始化，跳过设备密钥上传")
            return

        try:
            current_key_counts = await self._get_server_key_counts()
            server_otk_count = current_key_counts.get(SIGNED_CURVE25519, 0)
            logger.debug(f"服务器上当前一次性密钥数量：{server_otk_count}")

            device_keys = await self._resolve_device_keys_to_upload()

            if device_keys:
                algorithms = device_keys.get("algorithms", [])
                logger.debug(f"支持的加密算法：{algorithms}")
                keys_info = list(device_keys.get("keys", {}).keys())
                logger.debug(f"密钥列表：{keys_info}")

                signatures = device_keys.get("signatures", {})
                logger.debug(f"签名用户：{list(signatures.keys())}")

                required_algos = [OLM_ALGO, MEGOLM_ALGO]
                missing_algos = [
                    algo for algo in required_algos if algo not in algorithms
                ]
                if missing_algos:
                    logger.error(f"缺少必要的加密算法：{missing_algos}")
                else:
                    logger.debug("设备密钥包含所有必要的加密算法")

            one_time_keys, fallback_keys = self._prepare_one_time_and_fallback_keys(
                server_otk_count
            )

            if device_keys or one_time_keys or fallback_keys:
                logger.debug("正在上传密钥到服务器...")
                response = await self.client.upload_keys(
                    device_keys=device_keys,
                    one_time_keys=one_time_keys if one_time_keys else None,
                    fallback_keys=fallback_keys if fallback_keys else None,
                )
                if "error" in response or "errcode" in response:
                    logger.error(f"密钥上传失败：{response}")
                    return

                self._olm.mark_keys_as_published()

                counts = response.get("one_time_key_counts", {})
                logger.info(f"密钥已上传，一次性密钥数量：{counts}")

                if device_keys:
                    await self._verify_uploaded_device_keys()
            else:
                logger.debug("没有需要上传的密钥")

        except Exception as e:
            import traceback

            logger.error(f"上传设备密钥失败：{e}")
            logger.error(f"异常详情：{traceback.format_exc()}")
