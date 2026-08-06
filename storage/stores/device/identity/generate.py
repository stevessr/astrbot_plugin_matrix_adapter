"""Device ID generation."""

import base64
import secrets

from astrbot.api import logger


class MatrixDeviceIdentityGenerateMixin:
    """Generate fresh Matrix device IDs."""

    def _generate_device_id(self) -> str:
        """
        生成新的设备 ID

        Returns:
            设备 ID 字符串
        """
        # 生成符合 Matrix 标准的设备 ID
        # 使用 Base64 编码的随机字节，但使用 URL 和文件名安全的字符集

        # 生成 9 字节的随机数据，Base64 编码后得到 12 个字符
        random_bytes = secrets.token_bytes(9)
        # 使用标准 Base64，然后替换字符使其更符合 Matrix 风格
        device_id = base64.b64encode(random_bytes).decode("ascii")

        # 移除末尾可能的 '=' 填充
        device_id = device_id.rstrip("=")

        # 替换一些字符使其更像 Matrix 设备 ID
        device_id = device_id.replace("+", "").replace("/", "")

        # 确保长度在合理范围内（10-15 个字符）
        if len(device_id) < 10:
            # 如果太短，添加更多随机字符
            device_id += secrets.token_urlsafe(5)[: 15 - len(device_id)]
        elif len(device_id) > 15:
            # 如果太长，截断
            device_id = device_id[:15]

        logger.info(
            f"生成新的 Matrix 设备 ID: {device_id}",
            extra={"plugin_tag": "matrix", "short_levelname": "INFO"},
        )

        return device_id


__all__ = ["MatrixDeviceIdentityGenerateMixin"]
