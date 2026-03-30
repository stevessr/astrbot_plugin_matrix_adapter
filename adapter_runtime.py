"""
Matrix adapter runtime lifecycle helpers.
"""

import asyncio

from astrbot.api import logger

from .storage_paths import MatrixStoragePaths
from .utils.utils import mask_device_id


class MatrixAdapterRuntimeMixin:
    _MEDIA_CACHE_GC_INTERVAL_SECONDS = 6 * 60 * 60

    # 使用公共工具函数代替内联实现
    _mask_device_id = staticmethod(mask_device_id)

    async def _on_sync_response(self, sync_response: dict) -> None:
        runtime_state = getattr(self, "runtime_state", None)
        if runtime_state:
            runtime_state.mark_sync_ok()

    def get_runtime_status(self) -> dict:
        runtime_state = getattr(self, "runtime_state", None)
        sync_manager = getattr(self, "sync_manager", None)
        outbound_tracker = getattr(self, "outbound_tracker", None)
        client = getattr(self, "client", None)
        matrix_config = getattr(self, "_matrix_config", None)
        status = runtime_state.snapshot() if runtime_state else {}
        if matrix_config:
            status.update(
                {
                    "homeserver": matrix_config.homeserver,
                    "user_id": matrix_config.user_id,
                    "device_id_masked": self._mask_device_id(
                        getattr(client, "device_id", None) or matrix_config.device_id
                    ),
                    "auth_method": matrix_config.auth_method,
                    "e2ee_enabled": bool(getattr(self, "e2ee_manager", None)),
                }
            )
        if sync_manager and hasattr(sync_manager, "status_snapshot"):
            status["sync"] = sync_manager.status_snapshot()
            if not status.get("last_error_message"):
                status["last_error_message"] = status["sync"].get("last_sync_error")
                if status.get("last_error_message") and not status.get(
                    "last_error_category"
                ):
                    status["last_error_category"] = "sync"
        if outbound_tracker:
            status["outbound"] = outbound_tracker.summary()
            status["outbound_recent"] = outbound_tracker.list_records(limit=5)
        return status

    def request_reconnect(self) -> bool:
        runtime_state = getattr(self, "runtime_state", None)
        if runtime_state:
            runtime_state.mark_reconnect_requested()
        sync_manager = getattr(self, "sync_manager", None)
        if sync_manager and hasattr(sync_manager, "request_reconnect"):
            return bool(sync_manager.request_reconnect())
        return False

    async def _media_cache_gc_loop(self):
        try:
            while True:
                await asyncio.sleep(self._MEDIA_CACHE_GC_INTERVAL_SECONDS)
                try:
                    removed = self.receiver.gc_media_cache()
                    if removed > 0:
                        logger.info(f"定期清理了 {removed} 个媒体缓存文件")
                except Exception as e:
                    logger.debug(f"定期媒体缓存清理失败：{e}")
        except asyncio.CancelledError:
            raise

    def _handle_media_cache_gc_task_done(self, task: asyncio.Task) -> None:
        if getattr(self, "_media_cache_gc_task", None) is task:
            self._media_cache_gc_task = None
        try:
            task.result()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"媒体缓存清理任务异常退出：{e}")

    async def run(self):
        try:
            if getattr(self, "runtime_state", None):
                self.runtime_state.mark_lifecycle("starting")
                self.runtime_state.mark_auth_started()
            save_config = getattr(self, "_save_config", None)
            if callable(save_config):
                await save_config()

            if getattr(self, "unified_webhook", None) and self.unified_webhook():
                webhook_uuid = str(self.config.get("webhook_uuid") or "").strip()
                if webhook_uuid:
                    logger.info(
                        f"Matrix 认证回调将复用 AstrBot Webhook: {self._matrix_config.auth_callback_url}"
                    )
                    try:
                        from astrbot.core.utils.webhook_utils import log_webhook_info

                        log_webhook_info(f"{self.meta().id}(Matrix Auth)", webhook_uuid)
                    except Exception as e:
                        logger.debug(f"打印 Matrix Webhook 信息失败：{e}")

            await self.auth.login()
            if getattr(self, "runtime_state", None):
                self.runtime_state.mark_auth_ok()
            persist_auth_config = getattr(self, "_persist_auth_config_if_needed", None)
            if callable(persist_auth_config):
                await persist_auth_config()

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
                if getattr(self, "runtime_state", None):
                    self.runtime_state.mark_presence_updated()
            except Exception as e:
                logger.debug(f"设置在线状态失败：{e}")

            if self.e2ee_manager:
                try:
                    actual_device_id = (
                        self.client.device_id or self._matrix_config.device_id
                    )
                    if actual_device_id != self.e2ee_manager.device_id:
                        logger.info(
                            "更新 E2EE device_id："
                            f"{self._mask_device_id(self.e2ee_manager.device_id)} -> "
                            f"{self._mask_device_id(actual_device_id)}"
                        )
                        self.e2ee_manager.device_id = actual_device_id
                        # 持久化服务器返回的 device_id
                        self._matrix_config.set_device_id(actual_device_id)
                    await self.e2ee_manager.initialize()
                except Exception as e:
                    logger.error(f"E2EE 初始化失败：{e}")

            try:
                removed = self.receiver.gc_media_cache()
                if removed > 0:
                    logger.info(f"清理了 {removed} 个媒体缓存文件")
            except Exception as e:
                logger.debug(f"媒体缓存清理失败：{e}")

            if not hasattr(self, "_media_cache_gc_task") or (
                self._media_cache_gc_task and self._media_cache_gc_task.done()
            ):
                self._media_cache_gc_task = asyncio.create_task(
                    self._media_cache_gc_loop()
                )
                self._media_cache_gc_task.add_done_callback(
                    self._handle_media_cache_gc_task_done
                )

            logger.info(
                f"Matrix 平台适配器正在为 {self._matrix_config.user_id} 在 {self._matrix_config.homeserver} 上运行"
            )
            if getattr(self, "runtime_state", None):
                self.runtime_state.mark_lifecycle("running")
                self.runtime_state.mark_sync_started()
            await self.sync_manager.sync_forever()
        except KeyboardInterrupt:
            logger.info("Matrix 适配器收到关闭信号")
            raise
        except Exception as e:
            if getattr(self, "runtime_state", None):
                category = (
                    "auth" if self.runtime_state.auth_state != "ready" else "sync"
                )
                self.runtime_state.record_error(category, str(e))
                self.runtime_state.mark_lifecycle("error")
            logger.error(f"Matrix 适配器错误：{e}")
            logger.error("Matrix 适配器启动失败。请检查配置并查看上方详细错误信息。")
            raise

    async def terminate(self):
        try:
            logger.info("正在关闭 Matrix 适配器...")
            if getattr(self, "runtime_state", None):
                self.runtime_state.mark_lifecycle("stopping")
                self.runtime_state.mark_sync_stopped()

            try:
                await self.client.set_presence("offline")
                if getattr(self, "runtime_state", None):
                    self.runtime_state.mark_presence_updated()
            except Exception as e:
                logger.debug(f"设置离线状态失败：{e}")

            # 停止定期密钥分发检查任务
            key_share_check_task = None
            if hasattr(self, "e2ee_manager") and self.e2ee_manager:
                if hasattr(self.e2ee_manager, "stop_key_share_check_task"):
                    key_share_check_task = self.e2ee_manager.stop_key_share_check_task()
            if key_share_check_task and not key_share_check_task.done():
                try:
                    await key_share_check_task
                except asyncio.CancelledError:
                    pass

            if hasattr(self, "sync_manager"):
                stop_and_wait = getattr(self.sync_manager, "stop_and_wait", None)
                if callable(stop_and_wait):
                    await stop_and_wait()
                else:
                    self.sync_manager.stop()

            if (
                hasattr(self, "e2ee_manager")
                and self.e2ee_manager
                and hasattr(self.e2ee_manager, "close")
            ):
                await self.e2ee_manager.close()

            if hasattr(self, "receiver") and hasattr(self.receiver, "shutdown"):
                await self.receiver.shutdown()

            if hasattr(self, "_media_cache_gc_task") and self._media_cache_gc_task:
                self._media_cache_gc_task.cancel()
                try:
                    await self._media_cache_gc_task
                except asyncio.CancelledError:
                    pass
                self._media_cache_gc_task = None

            if self.client:
                await self.client.close()

            if getattr(self, "runtime_state", None):
                self.runtime_state.mark_lifecycle("stopped")
            logger.info("Matrix 适配器已被优雅地关闭")
        except Exception as e:
            if getattr(self, "runtime_state", None):
                self.runtime_state.record_error("terminate", str(e))
                self.runtime_state.mark_lifecycle("error")
            logger.error(f"Matrix 适配器关闭时出错：{e}")
