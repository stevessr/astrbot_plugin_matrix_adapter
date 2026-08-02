"""One-time-key and fallback-key maintenance operations."""

import time

from astrbot.api import logger

from ....constants import DEFAULT_ONE_TIME_KEYS_COUNT, SIGNED_CURVE25519


class E2EEManagerKeyMaintenanceMixin:
    """查询并补充服务器上的一次性密钥与 fallback key。"""

    async def _get_server_key_counts(self) -> dict:
        """获取服务器上的密钥数量"""
        try:
            response = await self.client.upload_keys()
            return response.get("one_time_key_counts", {})
        except Exception as e:
            logger.warning(f"获取服务器密钥数量失败：{e}")
            return {}

    async def ensure_sufficient_one_time_keys(
        self,
        server_counts: dict | None = None,
        unused_fallback_key_types: list[str] | None = None,
    ) -> None:
        """Top up OTKs and replace a fallback key after the server uses it."""
        if not self._olm or not self._initialized or getattr(self, "_closing", False):
            return

        try:
            counts = server_counts if isinstance(server_counts, dict) else None
            if counts is None:
                counts = await self._get_server_key_counts()

            server_otk_count = int(counts.get(SIGNED_CURVE25519, 0))

            # 使用配置的阈值比例
            threshold_ratio = getattr(self, "otk_threshold_ratio", 33) / 100.0
            min_threshold = max(1, int(DEFAULT_ONE_TIME_KEYS_COUNT * threshold_ratio))
            needs_otk_refill = server_otk_count < min_threshold
            fallback_state_known = isinstance(unused_fallback_key_types, list)
            needs_fallback_replacement = fallback_state_known and (
                SIGNED_CURVE25519 not in unused_fallback_key_types
            )
            if not needs_otk_refill and not needs_fallback_replacement:
                return

            now = time.monotonic()
            last_ts = getattr(self, "_last_otk_maintenance_ts", 0.0)
            # 使用配置的维护间隔
            maintenance_interval = getattr(self, "key_maintenance_interval", 60)
            if now - last_ts < maintenance_interval:
                return
            self._last_otk_maintenance_ts = now

            keys_to_generate = max(0, DEFAULT_ONE_TIME_KEYS_COUNT - server_otk_count)
            one_time_keys = {}
            if needs_otk_refill and keys_to_generate > 0:
                one_time_keys = self._olm.generate_one_time_keys(keys_to_generate)

            fallback_keys = {}
            if needs_fallback_replacement:
                fallback_keys = self._olm.generate_fallback_key()

            if not one_time_keys and not fallback_keys:
                return

            response = await self.client.upload_keys(
                one_time_keys=one_time_keys if one_time_keys else None,
                fallback_keys=fallback_keys if fallback_keys else None,
            )

            if "error" in response or "errcode" in response:
                logger.warning(f"自动补充一次性密钥失败：{response}")
                return

            self._olm.mark_keys_as_published()
            updated_counts = response.get("one_time_key_counts", {})
            actions = []
            if one_time_keys:
                actions.append(
                    f"OTK {server_otk_count} -> "
                    f"{updated_counts.get(SIGNED_CURVE25519, server_otk_count)}"
                )
            if fallback_keys:
                actions.append("fallback key replaced")
            logger.info(f"Completed E2EE key maintenance: {', '.join(actions)}")
        except Exception as e:
            logger.warning(f"主动补充一次性密钥失败：{e}")
