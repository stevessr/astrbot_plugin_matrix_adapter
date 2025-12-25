"""
Matrix 事件处理组件（如自动加群、消息分发等）（不依赖 matrix-nio）
"""

import logging

logger = logging.getLogger("astrbot.matrix.event_handler")


class MatrixEventHandler:
    def __init__(self, client, auto_join_rooms=True):
        self.client = client
        self.auto_join_rooms = auto_join_rooms

    async def invite_callback(
        self, room_id, invite_data
    ):  # Fixed signature to match call
        try:
            logger.info(
                f"Received invite to room {room_id}",
                extra={"plugin_tag": "matrix", "short_levelname": "INFO"},
            )
            if not self.auto_join_rooms:
                logger.info(
                    "Auto-join disabled, ignoring invite",
                    extra={"plugin_tag": "matrix", "short_levelname": "INFO"},
                )
                return
            logger.info(
                f"Attempting to join room {room_id}...",
                extra={"plugin_tag": "matrix", "short_levelname": "INFO"},
            )
            result = await self.client.join_room(room_id)
            if result and result.get("room_id"):
                logger.info(
                    f"Successfully joined room {result['room_id']}",
                    extra={"plugin_tag": "matrix", "short_levelname": "INFO"},
                )
            else:
                logger.error(
                    f"Failed to join room {room_id}: {result}",
                    extra={"plugin_tag": "matrix", "short_levelname": "ERRO"},
                )
        except Exception as e:
            logger.error(
                f"Error handling room invite: {e}",
                extra={"plugin_tag": "matrix", "short_levelname": "ERRO"},
            )
