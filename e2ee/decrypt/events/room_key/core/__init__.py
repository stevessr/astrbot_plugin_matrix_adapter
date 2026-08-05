"""m.room_key event handling orchestration (Megolm session import)."""

from astrbot.api import logger

from .backup import E2EEManagerDecryptRoomKeyBackupMixin
from .prepare import E2EEManagerDecryptRoomKeyPrepareMixin
from .session import E2EEManagerDecryptRoomKeyImportMixin
from .validate import E2EEManagerDecryptRoomKeyValidateMixin


class E2EEManagerDecryptRoomKeyOrchestratorMixin(
    E2EEManagerDecryptRoomKeyValidateMixin,
    E2EEManagerDecryptRoomKeyPrepareMixin,
    E2EEManagerDecryptRoomKeyImportMixin,
    E2EEManagerDecryptRoomKeyBackupMixin,
):
    """Import received Megolm room keys."""

    async def handle_room_key(
        self,
        event: dict,
        sender_key: str,
        *,
        sender_claimed_keys: dict[str, str] | None = None,
        sender_user_id: str | None = None,
        forwarded: bool = False,
    ):
        """
        处理 m.room_key 事件 (接收 Megolm 会话密钥)

        Args:
            event: 解密后的 m.room_key 事件内容
            sender_key: 发送者的 curve25519 密钥
            sender_claimed_keys: Olm 载荷中发送设备声明的签名密钥
            sender_user_id: Sender user ID authenticated by the Olm plaintext
            forwarded: Whether the decrypted event was m.forwarded_room_key.
        """
        fields = self._extract_room_key_fields(event, sender_key)
        if fields is None:
            return
        room_id, session_id, session_key, _algorithm = fields

        provenance = await self._validate_room_key_provenance(
            event,
            sender_key,
            sender_user_id,
            forwarded,
        )
        if provenance is None:
            return
        forwarded_chain, original_sender_key, forwarded_ed25519, withheld = provenance

        claimed_keys = self._normalize_room_key_claims(
            sender_claimed_keys,
            forwarded_ed25519,
        )
        if claimed_keys is None:
            logger.warning("Rejected room key without an authenticated Ed25519 key")
            return

        shared_history, stored_forwarding_chain = self._compute_import_provenance(
            event,
            sender_key,
            forwarded,
            forwarded_chain,
        )

        imported = self._import_room_key_session(
            room_id,
            session_id,
            session_key,
            original_sender_key,
            claimed_keys,
            stored_forwarding_chain,
            shared_history,
            sender_user_id,
            forwarded,
            withheld,
        )
        if imported is False:
            return
        # Matrix requires the requester to cancel the outstanding request once
        # any device supplies the session. This also prevents repeated replies.
        await self._cancel_room_key_request(room_id, session_id)

        # 自动备份新接收到的密钥
        await self._backup_room_key(
            room_id=room_id,
            session_id=session_id,
            session_key=session_key,
            original_sender_key=original_sender_key,
            claimed_keys=claimed_keys,
            stored_forwarding_chain=stored_forwarding_chain,
            shared_history=shared_history,
        )


class E2EEManagerDecryptRoomKeyCoreMixin(E2EEManagerDecryptRoomKeyOrchestratorMixin):
    """Import received Megolm room keys."""


# Preserve direct method attributes expected by parent-package __dict__ lookups.
for _mixin in (
    E2EEManagerDecryptRoomKeyBackupMixin,
    E2EEManagerDecryptRoomKeyImportMixin,
    E2EEManagerDecryptRoomKeyOrchestratorMixin,
    E2EEManagerDecryptRoomKeyPrepareMixin,
    E2EEManagerDecryptRoomKeyValidateMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(E2EEManagerDecryptRoomKeyCoreMixin, _method_name, _method)


__all__ = [
    "E2EEManagerDecryptRoomKeyBackupMixin",
    "E2EEManagerDecryptRoomKeyCoreMixin",
    "E2EEManagerDecryptRoomKeyImportMixin",
    "E2EEManagerDecryptRoomKeyOrchestratorMixin",
    "E2EEManagerDecryptRoomKeyPrepareMixin",
    "E2EEManagerDecryptRoomKeyValidateMixin",
]
