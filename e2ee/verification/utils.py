import base64
import hashlib
import secrets

from astrbot.api import logger

from ...constants import (
    M_QR_CODE_SCAN_V1_METHOD,
    M_QR_CODE_SHOW_V1_METHOD,
    M_RECIPROCATE_V1_METHOD,
    PREFIX_ED25519,
    QR_CODE_HEADER,
    QR_CODE_MODE_SELF_VERIFICATION_TRUSTED_MASTER,
    QR_CODE_MODE_SELF_VERIFICATION_UNTRUSTED_MASTER,
    QR_CODE_VERSION,
    SAS_BYTES_LENGTH_6,
)
from ..verification_utils import (
    _encode_unpadded_base64,
)


class SASVerificationFlowUtilsMixin:
    @staticmethod
    def _mask_identifier(value: str | None) -> str:
        if not isinstance(value, str) or not value:
            return "<empty>"
        normalized = value.strip()
        if len(normalized) <= 4:
            return "***"
        return f"{normalized[:2]}***{normalized[-2:]}"


    @staticmethod
    def _mask_txn_id(value: str | None) -> str:
        if not isinstance(value, str) or not value:
            return "<empty>"
        normalized = value.strip()
        if len(normalized) <= 8:
            return "***"
        return f"{normalized[:8]}..."


    @staticmethod
    def _supports_method(methods: object, method: str) -> bool:
        if not isinstance(methods, (list, tuple, set)):
            return False
        return method in methods


    @staticmethod
    def _decode_unpadded_base64(data: str) -> bytes:
        normalized = str(data or "").strip()
        if not normalized:
            return b""
        padding = "=" * (-len(normalized) % 4)
        return base64.b64decode(normalized + padding)


    def _get_local_device_ed25519_key(self) -> str | None:
        olm = getattr(self, "olm", None)
        device_key = getattr(olm, "ed25519_key", None)
        if isinstance(device_key, str) and device_key:
            return device_key
        if olm and hasattr(olm, "get_identity_keys"):
            try:
                keys = olm.get_identity_keys() or {}
                key_id = f"{PREFIX_ED25519}{self.device_id}"
                candidate = keys.get(key_id)
                if isinstance(candidate, str) and candidate:
                    return candidate
            except Exception:
                return None
        return None


    @staticmethod
    def _device_trusts_master_key(response: dict, user_id: str, device_id: str) -> bool:
        master_key = (response.get("master_keys") or {}).get(user_id) or {}
        signatures = (master_key.get("signatures") or {}).get(user_id) or {}
        return f"{PREFIX_ED25519}{device_id}" in signatures


    def _can_continue_with_qr(self, sender: str, methods: object) -> bool:
        if sender != self.user_id:
            return False
        can_show_to_peer = self._supports_method(methods, M_QR_CODE_SCAN_V1_METHOD)
        can_scan_peer = self._supports_method(
            methods, M_QR_CODE_SHOW_V1_METHOD
        ) and self._supports_method(methods, M_RECIPROCATE_V1_METHOD)
        return can_show_to_peer or can_scan_peer


    def _build_self_verification_qr_payload(
        self,
        transaction_id: str,
        key1: str,
        key2: str,
        shared_secret: bytes,
        mode: int,
    ) -> bytes:
        return b"".join(
            [
                QR_CODE_HEADER,
                bytes([QR_CODE_VERSION, mode]),
                len(transaction_id).to_bytes(2, "big"),
                transaction_id.encode("ascii"),
                self._decode_unpadded_base64(key1),
                self._decode_unpadded_base64(key2),
                shared_secret,
            ]
        )


    async def _maybe_prepare_self_verification_qr(
        self,
        sender: str,
        peer_device: str | None,
        methods: object,
        transaction_id: str,
    ) -> bool:
        if sender != self.user_id or not peer_device:
            return False
        if not self._supports_method(methods, M_QR_CODE_SCAN_V1_METHOD):
            return False

        session = self._sessions.setdefault(transaction_id, {})
        if session.get("qr_payload"):
            return True

        try:
            response = await self.client.query_keys({sender: []})
            device_keys = (response.get("device_keys") or {}).get(sender) or {}
            peer_device_info = device_keys.get(peer_device) or {}
            peer_keys = peer_device_info.get("keys") or {}
            peer_device_key = peer_keys.get(f"{PREFIX_ED25519}{peer_device}")
            if peer_device_key:
                session["fingerprint"] = peer_device_key

            master_key_obj = (response.get("master_keys") or {}).get(sender) or {}
            master_keys = master_key_obj.get("keys") or {}
            if master_keys:
                master_key_id, master_key = next(iter(master_keys.items()))
                session["master_key_id"] = master_key_id
                session["master_key"] = master_key
            else:
                master_key = None

            current_device_key = self._get_local_device_ed25519_key()
            if not current_device_key or not peer_device_key or not master_key:
                logger.warning(
                    "[E2EE-Verify] QR 自验证准备失败：缺少必要密钥 "
                    f"(current={bool(current_device_key)} peer={bool(peer_device_key)} master={bool(master_key)})"
                )
                return False

            if self._device_trusts_master_key(response, sender, self.device_id):
                mode = QR_CODE_MODE_SELF_VERIFICATION_TRUSTED_MASTER
                key1, key2 = master_key, peer_device_key
            else:
                mode = QR_CODE_MODE_SELF_VERIFICATION_UNTRUSTED_MASTER
                key1, key2 = current_device_key, master_key

            shared_secret = secrets.token_bytes(16)
            payload = self._build_self_verification_qr_payload(
                transaction_id,
                key1,
                key2,
                shared_secret,
                mode,
            )
            session["qr_mode"] = mode
            session["qr_payload"] = payload
            session["qr_shared_secret"] = shared_secret
            session["qr_shared_secret_b64"] = _encode_unpadded_base64(
                shared_secret
            )

            build_terminal_qr = getattr(self, "_build_terminal_qr", None)
            if callable(build_terminal_qr):
                session["qr_ascii"] = build_terminal_qr(payload)

            logger.info(
                "[E2EE-Verify] 已生成同账号 QR 自验证码："
                f"device={self._mask_identifier(peer_device)} "
                f"mode=0x{mode:02x} txn={self._mask_txn_id(transaction_id)}"
            )
            qr_ascii = str(session.get("qr_ascii") or "").rstrip()
            if qr_ascii:
                logger.info(
                    "[E2EE-Verify] 请在另一台设备上扫描以下二维码完成验证：\n"
                    f"{qr_ascii}"
                )

            notify_qr = getattr(self, "_notify_admin_for_qr_code", None)
            if callable(notify_qr):
                await notify_qr(session, transaction_id)
            return True
        except Exception as e:
            logger.warning(f"[E2EE-Verify] 准备同账号 QR 自验证失败：{e}")
            return False


    def _compute_sas_fallback(self, session: dict, their_key: str):
        """回退的 SAS 计算（当 vodozemac SAS 不可用时）"""
        our_key = session.get("our_public_key", "")
        combined = f"{our_key}{their_key}".encode()
        sas_bytes = hashlib.sha256(combined).digest()[:SAS_BYTES_LENGTH_6]

        emojis = self._bytes_to_emoji(sas_bytes)
        decimals = self._bytes_to_decimal(sas_bytes)

        session["sas_bytes"] = sas_bytes
        session["sas_emojis"] = emojis
        session["sas_decimals"] = decimals

        emoji_str = " ".join(e[0] for e in emojis)
        logger.info(
            f"[E2EE-Verify] SAS 验证码 (fallback): {emoji_str} | 数字：{decimals}"
        )
