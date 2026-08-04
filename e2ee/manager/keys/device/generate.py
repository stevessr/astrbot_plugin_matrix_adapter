"""One-time and fallback key generation."""

from astrbot.api import logger

from .....constants import DEFAULT_ONE_TIME_KEYS_COUNT


class E2EEManagerDeviceGenerateMixin:
    """Generate missing one-time keys and initial fallback keys."""

    def _prepare_one_time_and_fallback_keys(
        self,
        server_otk_count: int,
    ) -> tuple[dict, dict]:
        """Return (one_time_keys, fallback_keys) needing upload."""
        keys_to_generate = max(0, DEFAULT_ONE_TIME_KEYS_COUNT - server_otk_count)
        one_time_keys = {}
        if keys_to_generate > 0:
            one_time_keys = self._olm.generate_one_time_keys(keys_to_generate)
            logger.debug(f"生成了 {len(one_time_keys)} 个一次性密钥（补充）")
        else:
            logger.debug(
                f"服务器上已有足够的一次性密钥（{server_otk_count}），跳过生成"
            )

        fallback_keys = {}
        # A new account needs its initial fallback key immediately. For an
        # existing account, /sync's device_unused_fallback_key_types is the
        # authoritative signal that replacement is needed; rotating on
        # every process start would defeat fallback replay mitigation.
        if self._olm.is_new_account:
            fallback_keys = self._olm.generate_fallback_key()
            if fallback_keys:
                logger.debug("生成了 fallback key")

        return one_time_keys, fallback_keys
