"""
Matrix 事件处理组件（如自动加群、消息分发等）（不依赖 matrix-nio）
"""

from astrbot.api import logger


class MatrixEventHandler:
    def __init__(self, client, auto_join_rooms=True):
        self.client = client
        self.auto_join_rooms = auto_join_rooms
        # Sticker 同步器（由 MatrixAdapter 设置）
        self.sticker_syncer = None
        self.sticker_auto_sync = False

    def set_sticker_syncer(self, syncer, auto_sync: bool = False):
        """设置 sticker 同步器"""
        self.sticker_syncer = syncer
        self.sticker_auto_sync = auto_sync

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
                # 同步新房间的 sticker 包（如果启用）
                if self.sticker_syncer and self.sticker_auto_sync:
                    try:
                        count = await self.sticker_syncer.sync_room_stickers(room_id)
                        if count > 0:
                            logger.info(f"同步了房间 {room_id} 的 {count} 个 sticker")
                    except Exception as sync_e:
                        logger.debug(f"同步房间 {room_id} sticker 失败：{sync_e}")
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
