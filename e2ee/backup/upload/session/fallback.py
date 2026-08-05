"""Single-room-key upload with batch fallback."""

from astrbot.api import logger


class KeyBackupUploadSessionFallbackMixin:
    """Upload one session key, falling back to the batch endpoint."""

    async def _upload_session_with_fallback(
        self,
        room_id: str,
        session_id: str,
        session_data: dict,
    ) -> bool:
        """Return ``True`` after a successful upload or batch fallback."""
        try:
            await self.client.store_room_key_for_session(
                self._backup_version,
                room_id,
                session_id,
                session_data,
            )
            return True
        except Exception as e:
            errcode = None
            if isinstance(getattr(e, "data", None), dict):
                errcode = e.data.get("errcode")
            if getattr(e, "status", None) != 404 or errcode != "M_UNRECOGNIZED":
                raise

            logger.info("[KeyBackup] 单会话备份接口未识别，回退到批量 room_keys 接口")
            await self.client.store_room_keys(
                self._backup_version,
                {
                    "rooms": {
                        room_id: {
                            "sessions": {
                                session_id: session_data,
                            }
                        }
                    }
                },
            )
            return True


__all__ = ["KeyBackupUploadSessionFallbackMixin"]
