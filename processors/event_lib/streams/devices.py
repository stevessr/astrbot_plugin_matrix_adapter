"""Matrix Event Processor - /sync device and key-count stream handlers."""

from astrbot.api import logger


class MatrixEventProcessorStreamsDevicesMixin:
    """Process device list and one-time key state from /sync."""

    async def process_device_lists(self, device_lists: dict):
        """Process device list updates from /sync."""
        changed = device_lists.get("changed", []) or []
        left = device_lists.get("left", []) or []
        if isinstance(changed, list):
            self.device_lists["changed"].update(changed)
            if changed and self.e2ee_manager:
                try:
                    await self.e2ee_manager.on_device_list_changed(changed)
                except Exception as e:
                    logger.warning(
                        "Event-driven room-key sharing after a device-list change "
                        f"failed: {e}"
                    )
        if isinstance(left, list):
            self.device_lists["left"].update(left)
            if left and self.e2ee_manager:
                try:
                    await self.e2ee_manager.on_device_list_left(left)
                except Exception as e:
                    logger.warning(f"Failed to remove departed user device keys: {e}")
        logger.debug(f"设备列表更新：changed={len(changed)} left={len(left)}")

    async def process_device_one_time_keys_count(
        self,
        counts: dict,
        unused_fallback_key_types: list[str] | None = None,
    ):
        """Process one-time and fallback key state from /sync."""
        if isinstance(counts, dict):
            self.one_time_keys_count = counts
            self.unused_fallback_key_types = (
                list(unused_fallback_key_types)
                if isinstance(unused_fallback_key_types, list)
                else None
            )
            if self.e2ee_manager:
                try:
                    await self.e2ee_manager.ensure_sufficient_one_time_keys(
                        counts,
                        self.unused_fallback_key_types,
                    )
                except Exception as e:
                    logger.warning(f"自动补充一次性密钥失败：{e}")
            logger.debug(f"更新 device_one_time_keys_count: {list(counts.keys())}")


__all__ = ["MatrixEventProcessorStreamsDevicesMixin"]
