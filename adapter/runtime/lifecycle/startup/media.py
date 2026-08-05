"""Media configuration and presence stages of the Matrix adapter startup."""

from astrbot.api import logger


async def _startup_media_config(self) -> None:
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


async def _startup_presence(self) -> None:
    try:
        await self.client.set_presence("online")
        logger.info("Matrix 在线状态已设置为 online")
        if getattr(self, "runtime_state", None):
            self.runtime_state.mark_presence_updated()
    except Exception as e:
        logger.debug(f"设置在线状态失败：{e}")
