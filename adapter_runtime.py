"""
Matrix adapter runtime lifecycle helpers.
"""

from astrbot.api import logger

from .storage_paths import MatrixStoragePaths


class MatrixAdapterRuntimeMixin:
    async def run(self):
        try:
            await self.auth.login()

            if self.auth.user_id:
                current_user_id = self.auth.user_id

                if hasattr(self.event_processor, "user_id"):
                    self.event_processor.user_id = current_user_id

                if hasattr(self.receiver, "user_id"):
                    self.receiver.user_id = current_user_id

                if hasattr(self.sync_manager, "user_id"):
                    self.sync_manager.user_id = current_user_id

                    if (
                        self._matrix_config.store_path
                        and self._matrix_config.homeserver
                    ):
                        try:
                            new_sync_path = str(
                                MatrixStoragePaths.get_sync_file_path(
                                    self._matrix_config.store_path,
                                    self._matrix_config.homeserver,
                                    current_user_id,
                                )
                            )
                            self.sync_manager.sync_store_path = new_sync_path
                            self.sync_manager._load_sync_token()
                        except Exception as e:
                            logger.warning(f"Failed to update sync storage path: {e}")

            try:
                media_config = await self.client.get_media_config()
                server_max_size = media_config.get("m.upload.size")
                if server_max_size and isinstance(server_max_size, int):
                    self.max_upload_size = server_max_size
                    logger.info(
                        f"Matrix 媒体服务器最大上传大小：{self.max_upload_size / 1024 / 1024:.1f}MB"
                    )
                else:
                    logger.info(
                        f"使用默认最大上传大小：{self.max_upload_size / 1024 / 1024:.1f}MB"
                    )
            except Exception as e:
                logger.debug(f"获取媒体配置失败，使用默认值：{e}")

            try:
                await self.client.set_presence("online")
                logger.info("Matrix 在线状态已设置为 online")
            except Exception as e:
                logger.debug(f"设置在线状态失败：{e}")

            if self.e2ee_manager:
                try:
                    actual_device_id = (
                        self.client.device_id or self._matrix_config.device_id
                    )
                    if actual_device_id != self.e2ee_manager.device_id:
                        logger.info(
                            f"更新 E2EE device_id：{self.e2ee_manager.device_id} -> {actual_device_id}"
                        )
                        self.e2ee_manager.device_id = actual_device_id
                        # 持久化服务器返回的 device_id
                        self._matrix_config.set_device_id(actual_device_id)
                    await self.e2ee_manager.initialize()
                except Exception as e:
                    logger.error(f"E2EE 初始化失败：{e}")

            if self._matrix_config.sticker_auto_sync:
                try:
                    if self._matrix_config.sticker_sync_user_emotes:
                        user_count = await self.sticker_syncer.sync_user_stickers()
                        if user_count > 0:
                            logger.info(f"同步了 {user_count} 个用户 sticker")

                    joined_rooms = await self.client.get_joined_rooms()
                    total_synced = 0
                    for room_id in joined_rooms:
                        try:
                            count = await self.sticker_syncer.sync_room_stickers(
                                room_id
                            )
                            total_synced += count
                        except Exception as room_e:
                            logger.debug(f"同步房间 {room_id} sticker 失败：{room_e}")

                    if total_synced > 0:
                        logger.info(f"同步了 {total_synced} 个房间 sticker")
                except Exception as e:
                    logger.warning(f"Sticker 包同步失败：{e}")

            try:
                removed = self.receiver.gc_media_cache()
                if removed > 0:
                    logger.info(f"清理了 {removed} 个媒体缓存文件")
            except Exception as e:
                logger.debug(f"媒体缓存清理失败：{e}")

            logger.info(
                f"Matrix 平台适配器正在为 {self._matrix_config.user_id} 在 {self._matrix_config.homeserver} 上运行"
            )
            await self.sync_manager.sync_forever()
        except KeyboardInterrupt:
            logger.info("Matrix 适配器收到关闭信号")
            raise
        except Exception as e:
            logger.error(f"Matrix 适配器错误：{e}")
            logger.error("Matrix 适配器启动失败。请检查配置并查看上方详细错误信息。")
            raise

    async def terminate(self):
        try:
            logger.info("正在关闭 Matrix 适配器...")

            try:
                await self.client.set_presence("offline")
            except Exception as e:
                logger.debug(f"设置离线状态失败：{e}")

            if hasattr(self, "sync_manager"):
                self.sync_manager.stop()

            if self.client:
                await self.client.close()

            logger.info("Matrix 适配器已被优雅地关闭")
        except Exception as e:
            logger.error(f"Matrix 适配器关闭时出错：{e}")
