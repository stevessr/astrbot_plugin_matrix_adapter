"""Room-session restoration from Matrix key backups."""

import time

from astrbot.api import logger

from ...crypto_utils import (
    VODOZEMAC_PK_AVAILABLE as _DEFAULT_VODOZEMAC_PK_AVAILABLE,
)
from ...crypto_utils import (
    Curve25519SecretKey as _DEFAULT_CURVE25519_SECRET_KEY,
)
from ...crypto_utils import (
    PkDecryption as _DEFAULT_PK_DECRYPTION,
)
from ...crypto_utils import (
    _decode_recovery_key as _DEFAULT_DECODE_RECOVERY_KEY,
)
from ..compat import resolve_restore_symbol


class KeyBackupRoomKeysRestoreCoreMixin:
    """从密钥备份恢复房间会话。"""

    async def restore_room_keys(self, recovery_key: str | None = None) -> bool:
        """
        从备份恢复密钥

        Args:
            recovery_key: 恢复密钥 (覆盖初始化时的密钥)
        """
        if not self._backup_version:
            logger.warning("未发现备份，无法恢复")
            return False

        # 确定使用的恢复密钥
        key_bytes = None
        if recovery_key:
            try:
                decode_recovery_key = resolve_restore_symbol(
                    "_decode_recovery_key", _DEFAULT_DECODE_RECOVERY_KEY
                )
                key_bytes = decode_recovery_key(recovery_key)
            except Exception as e:
                logger.error(f"解析恢复密钥失败：{e}")
                return False
        elif self._recovery_key_bytes:
            key_bytes = self._recovery_key_bytes
        else:
            logger.error("无恢复密钥，无法解密备份")
            return False

        self._last_restore_attempt_ts = time.monotonic()

        # 验证密钥是否匹配备份版本
        if not self._verify_recovery_key(key_bytes):
            return False

        # Keep using the verified key for subsequent runs.
        self.use_recovery_key_bytes(key_bytes, persist=True)

        # 创建 PkDecryption 对象 (如果 vodozemac 可用)
        _pk_decryption = None
        if resolve_restore_symbol(
            "VODOZEMAC_PK_AVAILABLE", _DEFAULT_VODOZEMAC_PK_AVAILABLE
        ):
            try:
                # key_bytes 需要转换为 Curve25519SecretKey 对象
                secret_key_cls = resolve_restore_symbol(
                    "Curve25519SecretKey", _DEFAULT_CURVE25519_SECRET_KEY
                )
                pk_decryption_cls = resolve_restore_symbol(
                    "PkDecryption", _DEFAULT_PK_DECRYPTION
                )
                secret_key = secret_key_cls.from_bytes(key_bytes)
                _pk_decryption = pk_decryption_cls.from_key(secret_key)
                logger.debug("使用 vodozemac PkDecryption 解密备份")
            except Exception as e:
                logger.warning(f"创建 PkDecryption 失败：{e}")

        try:
            logger.info(f"开始从备份恢复密钥 (version={self._backup_version})")
            response = await self.client.get_room_keys(self._backup_version)

            rooms = response.get("rooms", {})
            total_sessions = sum(len(s) for s in rooms.values())
            logger.info(f"获取到 {len(rooms)} 个房间，共 {total_sessions} 个会话")

            restored = 0
            skipped = 0

            for room_id, room_data in rooms.items():
                # API 返回格式：rooms[room_id] = {"sessions": {session_id: {...}}}
                sessions = room_data.get("sessions", room_data)
                if not isinstance(sessions, dict):
                    sessions = room_data  # 回退到直接使用 room_data
                for session_id, session_data in sessions.items():
                    try:
                        restored_one = await self._restore_single_session(
                            room_id, session_id, session_data, key_bytes
                        )
                        if restored_one:
                            restored += 1
                        else:
                            skipped += 1
                    except Exception as e:
                        logger.debug(f"恢复会话 {(session_id or '')[:8]}... 失败：{e}")
                        skipped += 1

            if restored > 0:
                logger.info(f"已恢复 {restored} 个会话密钥")
            if skipped > 0:
                logger.debug(f"跳过 {skipped} 个不兼容的会话")
            return restored > 0

        except Exception as e:
            logger.warning(f"恢复密钥失败：{e}")
            return False
