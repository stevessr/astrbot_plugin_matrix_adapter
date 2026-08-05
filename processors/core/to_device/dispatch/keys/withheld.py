"""To-device room-key withheld event handling."""

from astrbot.api import logger


class MatrixEventProcessorToDeviceKeysWithheldMixin:
    """Handle withheld notices for room keys."""

    async def _handle_room_key_withheld(self, sender: str, content: dict) -> None:
        if self.e2ee_manager:
            try:
                await self.e2ee_manager.handle_room_key_withheld(
                    sender,
                    content,
                )
            except Exception as e:
                logger.error(f"Failed to process m.room_key.withheld: {e}")


__all__ = ["MatrixEventProcessorToDeviceKeysWithheldMixin"]
