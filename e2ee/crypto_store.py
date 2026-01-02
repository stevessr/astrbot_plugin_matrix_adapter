"""
Crypto Store - E2EE 密钥和会话的持久化存储

使用 JSON 文件存储加密状态，包括：
- Olm 账户 (pickle 格式)
- Megolm 入站/出站会话
- 设备密钥
- 一次性密钥
"""

import json
from pathlib import Path
from typing import Any

from astrbot.api import logger


class CryptoStore:
    """E2EE 加密状态存储"""

    def __init__(self, store_path: str | Path, user_id: str, device_id: str):
        """
        初始化加密存储

        Args:
            store_path: 存储目录路径
            user_id: 用户 ID (如 @bot:example.com)
            device_id: 设备 ID
        """
        self.store_path = Path(store_path)
        self.user_id = user_id
        self.device_id = device_id

        # 创建存储目录
        self.store_path.mkdir(parents=True, exist_ok=True)

        # 各种存储文件
        self._account_file = self.store_path / "olm_account.json"
        self._sessions_file = self.store_path / "olm_sessions.json"
        self._megolm_inbound_file = self.store_path / "megolm_inbound.json"
        self._megolm_outbound_file = self.store_path / "megolm_outbound.json"
        self._device_keys_file = self.store_path / "device_keys.json"
        self._stored_device_id_file = self.store_path / "stored_device_id.json"

        # 内存缓存
        self._account_pickle: str | None = None
        self._olm_sessions: dict[str, list[str]] = {}  # sender_key -> [session_pickles]
        self._megolm_inbound: dict[str, str] = {}  # session_id -> pickle
        self._megolm_outbound: dict[str, str] = {}  # room_id -> pickle
        self._device_keys: dict[str, dict] = {}  # user_id -> {device_id: keys}

        # 检查 device_id 是否变化
        self._device_id_changed = self._check_device_id_change()

        # 加载现有数据
        self._load_all()

    def _check_device_id_change(self) -> bool:
        """
        检查 device_id 是否发生变化

        Returns:
            True 如果 device_id 变化了（需要清除旧数据）
        """
        if not self._stored_device_id_file.exists():
            # 第一次运行，保存当前 device_id
            self._save_device_id()
            return False

        try:
            data = json.loads(self._stored_device_id_file.read_text())
            stored_device_id = data.get("device_id")

            if stored_device_id != self.device_id:
                logger.warning(
                    f"检测到 device_id 变化：{stored_device_id} -> {self.device_id}"
                )
                logger.warning("将清除旧的 Olm 账户和会话数据，创建新的密钥")
                # 清除旧数据
                self._clear_olm_data()
                # 保存新的 device_id
                self._save_device_id()
                return True

            return False
        except Exception as e:
            logger.warning(f"检查 device_id 变化失败：{e}")
            self._save_device_id()
            return False

    def _save_device_id(self):
        """保存当前 device_id 到文件"""
        try:
            self._stored_device_id_file.write_text(
                json.dumps({"device_id": self.device_id}, ensure_ascii=False)
            )
        except Exception as e:
            logger.error(f"保存 device_id 失败：{e}")

    def _clear_olm_data(self):
        """清除 Olm 账户和会话数据（当 device_id 变化时）"""
        try:
            # 只清除 Olm 相关数据，保留 Megolm 会话（可以继续解密历史消息）
            if self._account_file.exists():
                self._account_file.unlink()
                logger.info("已删除旧的 Olm 账户")

            if self._sessions_file.exists():
                self._sessions_file.unlink()
                logger.info("已删除旧的 Olm 会话")

            # 注意：不删除 Megolm 入站会话，因为它们仍然可以解密历史消息
            # 但需要删除出站会话，因为需要为新设备创建新的
            if self._megolm_outbound_file.exists():
                self._megolm_outbound_file.unlink()
                logger.info("已删除旧的 Megolm 出站会话")

        except Exception as e:
            logger.error(f"清除旧数据失败：{e}")

    @property
    def device_id_changed(self) -> bool:
        """返回 device_id 是否发生了变化"""
        return self._device_id_changed

    def _load_all(self):
        """从磁盘加载所有存储数据"""
        try:
            if self._account_file.exists():
                data = json.loads(self._account_file.read_text())
                self._account_pickle = data.get("pickle")
                logger.debug("加载了 Olm 账户")

            if self._sessions_file.exists():
                self._olm_sessions = json.loads(self._sessions_file.read_text())
                logger.debug(f"加载了 {len(self._olm_sessions)} 个 Olm 会话")

            if self._megolm_inbound_file.exists():
                self._megolm_inbound = json.loads(self._megolm_inbound_file.read_text())
                logger.debug(f"加载了 {len(self._megolm_inbound)} 个 Megolm 入站会话")

            if self._megolm_outbound_file.exists():
                self._megolm_outbound = json.loads(
                    self._megolm_outbound_file.read_text()
                )
                logger.debug(f"加载了 {len(self._megolm_outbound)} 个 Megolm 出站会话")

            if self._device_keys_file.exists():
                self._device_keys = json.loads(self._device_keys_file.read_text())
                logger.debug(f"加载了 {len(self._device_keys)} 个用户的设备密钥")

        except Exception as e:
            logger.error(f"加载加密存储失败: {e}")

    def _save_json(self, file_path: Path, data: Any):
        """保存 JSON 数据到文件"""
        try:
            file_path.write_text(json.dumps(data, ensure_ascii=False, indent=2))
        except Exception as e:
            logger.error(f"保存 {file_path.name} 失败: {e}")

    # ========== Olm 账户 ==========

    def get_account_pickle(self) -> str | None:
        """获取 Olm 账户的 pickle"""
        return self._account_pickle

    def save_account_pickle(self, pickle: str):
        """保存 Olm 账户的 pickle"""
        self._account_pickle = pickle
        self._save_json(self._account_file, {"pickle": pickle})

    # ========== Olm 会话 ==========

    def get_olm_sessions(self, sender_key: str) -> list[str]:
        """获取与特定发送者的 Olm 会话列表"""
        return self._olm_sessions.get(sender_key, [])

    def add_olm_session(self, sender_key: str, session_pickle: str):
        """添加 Olm 会话"""
        if sender_key not in self._olm_sessions:
            self._olm_sessions[sender_key] = []
        self._olm_sessions[sender_key].append(session_pickle)
        self._save_json(self._sessions_file, self._olm_sessions)

    def update_olm_session(self, sender_key: str, index: int, session_pickle: str):
        """更新 Olm 会话"""
        if sender_key in self._olm_sessions and index < len(
            self._olm_sessions[sender_key]
        ):
            self._olm_sessions[sender_key][index] = session_pickle
            self._save_json(self._sessions_file, self._olm_sessions)

    def clear_olm_sessions(self, sender_key: str):
        """清除与特定发送者的所有 Olm 会话"""
        if sender_key in self._olm_sessions:
            del self._olm_sessions[sender_key]
            self._save_json(self._sessions_file, self._olm_sessions)

    # ========== Megolm 入站会话 ==========

    def get_megolm_inbound(self, session_id: str) -> str | None:
        """获取 Megolm 入站会话"""
        return self._megolm_inbound.get(session_id)

    def save_megolm_inbound(self, session_id: str, session_pickle: str):
        """保存 Megolm 入站会话"""
        self._megolm_inbound[session_id] = session_pickle
        self._save_json(self._megolm_inbound_file, self._megolm_inbound)

    # ========== Megolm 出站会话 ==========

    def get_megolm_outbound(self, room_id: str) -> str | None:
        """获取房间的 Megolm 出站会话"""
        return self._megolm_outbound.get(room_id)

    def save_megolm_outbound(self, room_id: str, session_pickle: str):
        """保存房间的 Megolm 出站会话"""
        self._megolm_outbound[room_id] = session_pickle
        self._save_json(self._megolm_outbound_file, self._megolm_outbound)

    # ========== 设备密钥 ==========

    def get_device_keys(self, user_id: str) -> dict[str, dict]:
        """获取用户的所有设备密钥"""
        return self._device_keys.get(user_id, {})

    def save_device_keys(self, user_id: str, device_id: str, keys: dict):
        """保存设备密钥"""
        if user_id not in self._device_keys:
            self._device_keys[user_id] = {}
        self._device_keys[user_id][device_id] = keys
        self._save_json(self._device_keys_file, self._device_keys)

    def get_all_device_keys(self) -> dict[str, dict]:
        """获取所有已知的设备密钥"""
        return self._device_keys
