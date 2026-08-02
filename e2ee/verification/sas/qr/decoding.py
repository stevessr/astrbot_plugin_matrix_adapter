"""QR payload and image decoding helpers."""

import base64
from pathlib import Path

from .....constants import (
    QR_CODE_HEADER,
    QR_CODE_VERSION,
)


class SASVerificationQRDecodingMixin:
    """解码二维码 Base64、图片与 Matrix 验证载荷。"""

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
