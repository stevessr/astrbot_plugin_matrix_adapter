"""Identity and sync-storage propagation stage of the Matrix adapter startup."""

from astrbot.api import logger

from .....storage.paths import MatrixStoragePaths


async def _startup_sync_identity(self) -> None:
    if self.auth.user_id:
        current_user_id = self.auth.user_id

        if hasattr(self.event_processor, "user_id"):
            self.event_processor.user_id = current_user_id

        if hasattr(self.receiver, "user_id"):
            self.receiver.user_id = current_user_id

        if hasattr(self.sync_manager, "user_id"):
            self.sync_manager.user_id = current_user_id

            if self._matrix_config.store_path and self._matrix_config.homeserver:
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
