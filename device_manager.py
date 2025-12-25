"""
Matrix Device ID 管理器
负责生成、存储和恢复 Matrix 设备 ID
"""

import base64
import json
import secrets
from pathlib import Path

from astrbot.api import logger


class MatrixDeviceManager:
    """
    Matrix 设备 ID 管理器

    功能：
    - 基于用户信息和服务器信息生成稳定的设备 ID
    - 持久化存储设备 ID
    - 在需要时生成新的设备 ID
    """

    def __init__(
        self, user_id: str, homeserver: str, store_path: str = "./data/matrix_store"
    ):
        """
        初始化设备管理器

        Args:
            user_id: Matrix 用户 ID
            homeserver: Matrix 服务器地址
            store_path: 存储路径
        """

        self.user_id = user_id

        self.homeserver = homeserver.rstrip("/")

        self.store_path = Path(store_path)

        # 使用新的存储路径逻辑

        from .storage_paths import MatrixStoragePaths

        # 获取用户的存储目录

        self.user_store_path = MatrixStoragePaths.get_user_storage_dir(
            store_path, homeserver, user_id
        )

        # 确保目录存在

        MatrixStoragePaths.ensure_directory(self.user_store_path)

        # 设备信息文件路径

        self.device_info_path = self.user_store_path / "device_info.json"

        self._device_id: str | None = None

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

    def _load_device_info(self) -> dict | None:
        """
        从磁盘加载设备信息

        Returns:
            设备信息字典，如果不存在则返回 None
        """
        try:
            if not self.device_info_path.exists():
                return None

            with open(self.device_info_path) as f:
                device_info = json.load(f)

            # 验证设备信息是否匹配当前用户和服务器
            if (
                device_info.get("user_id") != self.user_id
                or device_info.get("homeserver") != self.homeserver
            ):
                logger.warning(
                    "存储的设备信息与当前用户/服务器不匹配，将生成新的设备 ID",
                    extra={"plugin_tag": "matrix", "short_levelname": "WARN"},
                )
                return None

            logger.debug(
                f"从磁盘加载设备信息：device_id={device_info.get('device_id')}",
                extra={"plugin_tag": "matrix", "short_levelname": "DBUG"},
            )

            return device_info

        except Exception as e:
            logger.error(
                f"加载设备信息失败：{e}",
                extra={"plugin_tag": "matrix", "short_levelname": "ERRO"},
            )
            return None

    def _save_device_info(self, device_id: str):
        """
        保存设备信息到磁盘

        Args:
            device_id: 要保存的设备 ID
        """
        try:
            device_info = {
                "device_id": device_id,
                "user_id": self.user_id,
                "homeserver": self.homeserver,
                "created_at": int(__import__("time").time() * 1000),  # 毫秒时间戳
            }
            # 确保目录存在
            Path(self.device_info_path).parent.mkdir(parents=True, exist_ok=True)

            with open(self.device_info_path, "w") as f:
                json.dump(device_info, f, indent=2)

            logger.debug(
                f"设备信息已保存到：{self.device_info_path}",
                extra={"plugin_tag": "matrix", "short_levelname": "DBUG"},
            )

        except Exception as e:
            logger.error(
                f"保存设备信息失败：{e}",
                extra={"plugin_tag": "matrix", "short_levelname": "ERRO"},
            )

    def get_or_create_device_id(self, force_new: bool = False) -> str:
        """
        获取现有设备 ID 或创建新的设备 ID

        Args:
            force_new: 是否强制生成新的设备 ID

        Returns:
            设备 ID
        """
        # 如果已经有缓存的设备 ID 且不强制重新生成，直接返回
        if self._device_id and not force_new:
            return self._device_id

        # 尝试从磁盘加载现有设备信息
        if not force_new:
            device_info = self._load_device_info()
            if device_info and "device_id" in device_info:
                self._device_id = device_info["device_id"]
                logger.info(
                    f"使用已存储的设备 ID: {self._device_id}",
                    extra={"plugin_tag": "matrix", "short_levelname": "INFO"},
                )
                return self._device_id

        # 生成新的设备 ID
        self._device_id = self._generate_device_id()

        # 保存到磁盘
        self._save_device_info(self._device_id)

        return self._device_id

    def get_device_id(self) -> str | None:
        """
        获取当前设备 ID（不自动生成）

        Returns:
            当前设备 ID，如果不存在则返回 None
        """
        if self._device_id:
            return self._device_id

        device_info = self._load_device_info()
        if device_info and "device_id" in device_info:
            self._device_id = device_info["device_id"]

        return self._device_id

    def reset_device_id(self) -> str:
        """
        重置设备 ID（生成新的设备 ID）

        Returns:
            新的设备 ID
        """
        logger.info(
            "重置 Matrix 设备 ID",
            extra={"plugin_tag": "matrix", "short_levelname": "INFO"},
        )
        return self.get_or_create_device_id(force_new=True)

    def set_device_id(self, device_id: str):
        """设置设备 ID"""
        self._device_id = device_id
        # 保存到文件
        device_info = {"device_id": device_id}
        self.device_info_path.write_text(json.dumps(device_info, indent=2))

    def delete_device_info(self):
        """删除存储的设备信息"""
        try:
            if self.device_info_path.exists():
                self.device_info_path.unlink()
                logger.info(
                    "已删除存储的设备信息",
                    extra={"plugin_tag": "matrix", "short_levelname": "INFO"},
                )
            self._device_id = None
        except Exception as e:
            logger.error(
                f"删除设备信息失败：{e}",
                extra={"plugin_tag": "matrix", "short_levelname": "ERRO"},
            )
