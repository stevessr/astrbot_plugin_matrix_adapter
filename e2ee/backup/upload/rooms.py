"""Bulk room-session upload operations for key backups."""

import json

from astrbot.api import logger


class KeyBackupUploadRoomsMixin:
    """批量上传本地房间会话密钥。"""

    async def upload_room_keys(self, room_id: str | None = None):
        """
        上传房间密钥到备份

        Args:
            room_id: 可选，指定房间 ID
        """
        if not self._backup_version:
            logger.warning("未创建备份，无法上传")
            return

        try:
            session_ids = list(self.store.get_megolm_inbound_ids())
            if not session_ids:
                logger.debug("没有可上传的会话密钥")
                return

            rooms: dict[str, dict[str, dict]] = {}
            uploaded = 0

            for session_id in session_ids:
                metadata = self.store.get_megolm_inbound_metadata(session_id) or {}
                target_room = room_id or metadata.get("room_id")
                if not isinstance(target_room, str) or not target_room:
                    logger.debug(
                        f"跳过缺少 room_id 的会话：{(session_id or '')[:8]}..."
                    )
                    continue
                if room_id and metadata.get("room_id") not in (None, room_id):
                    continue

                session = self.olm.get_megolm_inbound_session(session_id)
                if not session:
                    continue
                first_message_index = self.olm.get_megolm_first_known_index(session)
                exported_key = session.export_at(first_message_index).to_base64()
                backed_up_session = self._build_backed_up_session_data(
                    exported_key,
                    sender_key=metadata.get("sender_key", ""),
                    sender_claimed_keys=metadata.get("sender_claimed_keys"),
                    forwarding_curve25519_key_chain=metadata.get(
                        "forwarding_curve25519_key_chain"
                    ),
                    shared_history=metadata.get("shared_history") is True,
                )
                plaintext = json.dumps(
                    backed_up_session,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()

                session_data = {
                    "first_message_index": first_message_index,
                    "forwarded_count": len(
                        backed_up_session["forwarding_curve25519_key_chain"]
                    ),
                    "is_verified": True,
                    "session_data": self._build_encrypted_session_data(plaintext),
                }

                room_sessions = rooms.setdefault(target_room, {"sessions": {}})
                room_sessions["sessions"][session_id] = session_data
                uploaded += 1

            if not uploaded:
                logger.debug("没有可上传的完整会话数据")
                return

            await self.client.store_room_keys(
                self._backup_version,
                {"rooms": rooms},
            )

            logger.info(f"已上传 {uploaded} 个会话密钥")

        except Exception as e:
            logger.error(f"上传密钥失败：{e}")
