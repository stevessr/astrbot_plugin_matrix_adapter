"""QR verification payload decoding and scan flow."""

import base64
from pathlib import Path
from typing import Any

from astrbot.api import logger

from ....constants import (
    M_KEY_VERIFICATION_START,
    M_RECIPROCATE_V1_METHOD,
    PREFIX_ED25519,
    QR_CODE_HEADER,
    QR_CODE_MODE_SELF_VERIFICATION_TRUSTED_MASTER,
    QR_CODE_MODE_SELF_VERIFICATION_UNTRUSTED_MASTER,
    QR_CODE_VERSION,
)
from ..crypto_utils import _encode_unpadded_base64


class SASVerificationQRMixin:
    """二维码载荷解析、会话匹配和 reciprocate 发送。"""

    @staticmethod
    def _decode_base64_payload(payload: str) -> bytes:
        normalized = str(payload or "").strip()
        if not normalized:
            raise ValueError("二维码载荷不能为空")
        padding = "=" * (-len(normalized) % 4)
        return base64.b64decode(normalized + padding)

    @staticmethod
    def _decode_qr_image(image_path: Path) -> bytes:
        try:
            from PIL import Image
            from pyzbar.pyzbar import decode
        except Exception as e:
            raise RuntimeError("二维码图片解码依赖缺失，请安装 Pillow 和 pyzbar") from e

        with Image.open(image_path) as image:
            results = decode(image)
        if not results:
            raise ValueError("未在图片中识别到二维码")
        if len(results) > 1:
            raise ValueError("图片中包含多个二维码，请只保留一个")
        return bytes(results[0].data)

    @staticmethod
    def _parse_verification_qr_payload(payload: bytes) -> dict[str, object]:
        if len(payload) < 6 + 1 + 1 + 2 + 32 + 32 + 1:
            raise ValueError("二维码载荷长度无效")
        if payload[:6] != QR_CODE_HEADER:
            raise ValueError("二维码载荷头部不是 MATRIX")
        version = payload[6]
        if version != QR_CODE_VERSION:
            raise ValueError(f"不支持的二维码版本：{version}")
        mode = payload[7]
        txn_len = int.from_bytes(payload[8:10], "big")
        if len(payload) < 10 + txn_len + 64 + 1:
            raise ValueError("二维码载荷缺少事务或密钥字段")
        txn_start = 10
        txn_end = txn_start + txn_len
        key1_start = txn_end
        key2_start = key1_start + 32
        secret_start = key2_start + 32
        transaction_id = payload[txn_start:txn_end].decode("ascii")
        return {
            "version": version,
            "mode": mode,
            "transaction_id": transaction_id,
            "key1": payload[key1_start:key2_start],
            "key2": payload[key2_start:secret_start],
            "secret": payload[secret_start:],
        }

    def _load_qr_payload_bytes(self, qr_input: str) -> bytes:
        candidate = Path(str(qr_input or "").strip()).expanduser()
        if candidate.exists():
            return self._decode_qr_image(candidate)
        return self._decode_base64_payload(str(qr_input or "").strip())

    def _find_session_for_qr_scan(
        self,
        user_id: str,
        device_id: str,
        transaction_id: str | None = None,
    ) -> tuple[str, dict[str, Any]] | tuple[None, None]:
        candidates: list[tuple[str, dict[str, Any]]] = []
        for txn_id, session in self._sessions.items():
            if transaction_id and txn_id != transaction_id:
                continue
            if session.get("sender") != user_id:
                continue
            if (
                session.get("from_device") != device_id
                and session.get("their_device") != device_id
            ):
                continue
            if session.get("state") in ("done", "cancelled"):
                continue
            candidates.append((txn_id, session))

        if not candidates:
            return None, None

        for txn_id, session in candidates:
            if session.get("state") in ("ready", "ready_for_qr_scan", "requested"):
                return txn_id, session
        return candidates[0]

    async def scan_qr(
        self, user_id: str, device_id: str, qr_input: str
    ) -> tuple[bool, str]:
        """扫描同账号验证二维码并发送 reciprocate。"""
        try:
            payload = self._load_qr_payload_bytes(qr_input)
            parsed = self._parse_verification_qr_payload(payload)
            txn_id = str(parsed["transaction_id"])
            resolved_txn_id, session = self._find_session_for_qr_scan(
                user_id, device_id, txn_id
            )
            if not resolved_txn_id or session is None:
                return False, f"未找到设备 {device_id} 对应的待扫码验证会话"

            response = await self.client.query_keys({user_id: []})
            device_map = (response.get("device_keys") or {}).get(user_id) or {}
            peer_device_info = device_map.get(device_id) or {}
            peer_keys = peer_device_info.get("keys") or {}
            peer_device_key = peer_keys.get(f"{PREFIX_ED25519}{device_id}")
            master_key_obj = (response.get("master_keys") or {}).get(user_id) or {}
            master_keys = master_key_obj.get("keys") or {}
            if not peer_device_key or not master_keys:
                return False, "无法从服务器读取对端设备 key 或 master key"

            master_key_id, master_key = next(iter(master_keys.items()))
            current_device_key = self.olm.ed25519_key
            session["master_key_id"] = master_key_id
            session["master_key"] = master_key
            session["fingerprint"] = peer_device_key

            key1_b64 = _encode_unpadded_base64(parsed["key1"])
            key2_b64 = _encode_unpadded_base64(parsed["key2"])
            mode = int(parsed["mode"])
            if mode == QR_CODE_MODE_SELF_VERIFICATION_TRUSTED_MASTER:
                expected_key1 = master_key
                expected_key2 = current_device_key
            elif mode == QR_CODE_MODE_SELF_VERIFICATION_UNTRUSTED_MASTER:
                expected_key1 = peer_device_key
                expected_key2 = master_key
            else:
                return False, f"暂不支持的二维码模式：0x{mode:02x}"

            if key1_b64 != expected_key1 or key2_b64 != expected_key2:
                return (
                    False,
                    "二维码载荷与当前验证会话不匹配，请确认扫描的是对应设备展示的验证二维码",
                )

            secret_b64 = _encode_unpadded_base64(parsed["secret"])
            session["state"] = "started"
            session["method"] = M_RECIPROCATE_V1_METHOD
            session["qr_scanned_by_us"] = True
            session["qr_confirmed"] = True
            session["qr_mode"] = mode
            session["qr_shared_secret"] = bytes(parsed["secret"])
            session["qr_shared_secret_b64"] = secret_b64

            content = {
                "from_device": self.device_id,
                "method": M_RECIPROCATE_V1_METHOD,
                "transaction_id": resolved_txn_id,
                "secret": secret_b64,
            }
            await self._send_to_device(
                M_KEY_VERIFICATION_START,
                user_id,
                device_id,
                content,
            )
            logger.info(
                "[E2EE-Verify] 已发送 QR reciprocate："
                f"device={device_id} txn={resolved_txn_id[:8]}..."
            )
            return (
                True,
                f"已发送 QR 扫码确认，等待对端 done（txn={resolved_txn_id[:8]}...）",
            )
        except Exception as e:
            logger.warning(f"[E2EE-Verify] 扫描验证二维码失败：{e}")
            return False, str(e)


__all__ = ["SASVerificationQRMixin"]
