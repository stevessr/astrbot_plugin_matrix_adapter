"""
Olm Machine - Olm/Megolm 加密操作封装

使用 vodozemac 实现加密/解密操作。
注意：此模块需要安装 vodozemac 库。
"""

import json
from typing import Any

from astrbot.api import logger

from ..constants import (
    DEFAULT_ONE_TIME_KEYS_COUNT,
    MEGOLM_ALGO,
    OLM_ALGO,
    OLM_ALGO_SHA256,
)
from .crypto_store import CryptoStore

# 尝试导入 vodozemac
try:
    from vodozemac import (
        Account,
        Curve25519PublicKey,
        ExportedSessionKey,  # 构造函数接受 base64 字符串
        GroupSession,  # 出站会话 (vodozemac 中称为 GroupSession)
        InboundGroupSession,
        MegolmMessage,  # 解密时需要将密文转换为此类型
        Session,
    )

    VODOZEMAC_AVAILABLE = True
except ImportError:
    VODOZEMAC_AVAILABLE = False
    logger.warning("vodozemac 未安装，E2EE 功能将不可用。请运行：pip install vodozemac")


class OlmMachine:
    """
    Olm/Megolm 加密操作封装

    提供：
    - 设备密钥生成
    - Olm 会话管理
    - Megolm 加密/解密
    """

    def __init__(self, store: CryptoStore, user_id: str, device_id: str):
        """
        初始化 OlmMachine

        Args:
            store: 加密存储
            user_id: 用户 ID
            device_id: 设备 ID
        """
        if not VODOZEMAC_AVAILABLE:
            raise RuntimeError("vodozemac 未安装，无法使用 E2EE")

        self.store = store
        self.user_id = user_id
        self.device_id = device_id

        # 生成 pickle key (用于加密存储的 Olm 状态)
        # 基于 user_id 和 device_id 生成稳定的密钥
        import hashlib

        key_material = f"{user_id}:{device_id}:astrbot_e2ee".encode()
        self._pickle_key = hashlib.sha256(key_material).digest()

        # Olm 账户
        self._account: Account | None = None

        # Olm 会话缓存：sender_key -> [Session]
        self._olm_sessions: dict[str, list[Session]] = {}

        # Megolm 会话缓存
        self._megolm_inbound: dict[str, InboundGroupSession] = {}
        self._megolm_outbound: dict[str, GroupSession] = {}

        # 初始化或加载账户
        self._init_account()

    def _init_account(self):
        """初始化或加载 Olm 账户"""
        pickle = self.store.get_account_pickle()

        if pickle:
            # 从 pickle 恢复账户
            try:
                self._account = Account.from_pickle(pickle, self._pickle_key)
                logger.info("从存储恢复 Olm 账户")
            except Exception as e:
                logger.warning(f"恢复 Olm 账户失败（可能是密钥不匹配或数据损坏）：{e}")
                logger.info("将创建新的 Olm 账户")
                # 删除损坏的 pickle 文件
                try:
                    self.store._account_file.unlink(missing_ok=True)
                    logger.info("已删除损坏的账户文件")
                except Exception as cleanup_e:
                    logger.warning(f"删除损坏文件失败：{cleanup_e}")
                self._create_new_account()
        else:
            self._create_new_account()

    def _create_new_account(self):
        """创建新的 Olm 账户"""
        self._account = Account()
        self._save_account()
        logger.info("创建了新的 Olm 账户")

    def _save_account(self):
        """保存 Olm 账户到存储"""
        if self._account:
            pickle = self._account.pickle(self._pickle_key)
            self.store.save_account_pickle(pickle)

    # ========== 设备密钥 ==========

    def get_identity_keys(self) -> dict[str, str]:
        """获取设备身份密钥"""
        if not self._account:
            raise RuntimeError("Olm 账户未初始化")

        # vodozemac 返回的是 Key 对象，需要转换为字符串
        curve25519 = self._account.curve25519_key.to_base64()
        ed25519 = self._account.ed25519_key.to_base64()

        return {
            f"curve25519:{self.device_id}": curve25519,
            f"ed25519:{self.device_id}": ed25519,
        }

    def get_device_keys(self) -> dict[str, Any]:
        """
        获取用于上传的设备密钥

        返回符合 Matrix 规范的设备密钥格式
        """
        if not self._account:
            raise RuntimeError("Olm 账户未初始化")

        keys = self.get_identity_keys()

        device_keys = {
            "user_id": self.user_id,
            "device_id": self.device_id,
            "algorithms": [OLM_ALGO, OLM_ALGO_SHA256, MEGOLM_ALGO],
            "keys": keys,
            # 设备显示名称，帮助用户识别设备
            "unsigned": {
                "device_display_name": "AstrBot",
                "device_id": self.device_id,
            },
        }

        # 生成签名 (vodozemac sign 需要 bytes 输入，返回 Ed25519Signature 对象)
        device_keys_json = self._canonical_json(device_keys)
        signature = self._account.sign(device_keys_json.encode()).to_base64()

        device_keys["signatures"] = {
            self.user_id: {f"ed25519:{self.device_id}": signature}
        }

        return device_keys

    def generate_one_time_keys(
        self, count: int = DEFAULT_ONE_TIME_KEYS_COUNT
    ) -> dict[str, dict]:
        """
        生成一次性密钥

        Args:
            count: 要生成的密钥数量

        Returns:
            签名的一次性密钥字典
        """
        if not self._account:
            raise RuntimeError("Olm 账户未初始化")

        # 生成新的一次性密钥
        self._account.generate_one_time_keys(count)

        # 获取一次性密钥
        one_time_keys = self._account.one_time_keys

        # 签名每个密钥 (key 是 Curve25519PublicKey 对象，需要转为字符串)
        signed_keys = {}
        for key_id, key in one_time_keys.items():
            key_str = key.to_base64()  # 转换为字符串
            signed_key = {
                "key": key_str,
            }

            # 生成签名 (vodozemac sign 需要 bytes 输入)
            key_json = self._canonical_json(signed_key)
            signature = self._account.sign(key_json.encode()).to_base64()
            signed_key["signatures"] = {
                self.user_id: {f"ed25519:{self.device_id}": signature}
            }

            # 标记为已签名的 curve25519
            signed_keys[f"signed_curve25519:{key_id}"] = signed_key

        return signed_keys

    def mark_keys_as_published(self):
        """标记一次性密钥为已发布"""
        if self._account:
            self._account.mark_keys_as_published()
            self._save_account()

    # ========== Olm 会话 ==========

    def create_outbound_session(
        self, their_identity_key: str, their_one_time_key: str
    ) -> Session:
        """
        创建出站 Olm 会话

        Args:
            their_identity_key: 对方的 curve25519 身份密钥
            their_one_time_key: 对方的一次性密钥

        Returns:
            新的 Olm 会话
        """
        if not self._account:
            raise RuntimeError("Olm 账户未初始化")

        # Convert keys from base64 string to Curve25519PublicKey
        identity_key = Curve25519PublicKey(their_identity_key)
        one_time_key = Curve25519PublicKey(their_one_time_key)

        session = self._account.create_outbound_session(identity_key, one_time_key)

        # 缓存会话
        if their_identity_key not in self._olm_sessions:
            self._olm_sessions[their_identity_key] = []
        self._olm_sessions[their_identity_key].append(session)

        # 保存会话
        self.store.add_olm_session(their_identity_key, session.pickle(self._pickle_key))
        self._save_account()

        return session

    def encrypt_olm(
        self,
        their_identity_key: str,
        content: dict,
        session: Session | None = None,
        recipient_user_id: str = "unknown",
        event_type: str = "m.room_key",
    ) -> dict:
        """
        使用 Olm 加密内容并添加 Matrix 协议外壳

        Args:
            their_identity_key: 对方的 curve25519 密钥
            content: 要加密的内容 (m.room_key 等)
            session: 可选，已有的 Olm 会话
            recipient_user_id: 接收者用户 ID
            event_type: 事件类型（默认 m.room_key）

        Returns:
            符合 m.room.encrypted (Olm) 格式 a 字典
        """
        if not session:
            # 尝试使用现有会话
            sessions = self._olm_sessions.get(their_identity_key, [])
            if sessions:
                session = sessions[0]
                logger.debug(f"使用现有 Olm 会话对 {their_identity_key[:8]}... 加密")
            else:
                logger.warning(f"没有可用于 {their_identity_key[:8]}... 的 Olm 会话")
                raise RuntimeError(f"没有可用于 {their_identity_key} 的 Olm 会话")

        # 构造 Matrix 协议外壳
        # 根据 Matrix 规范，type 应放在外层，content 中不应重复
        wrapper = {
            "sender": self.user_id,
            "sender_device": self.device_id,
            "keys": {"ed25519": self.ed25519_key},
            "recipient": recipient_user_id,
            "recipient_keys": {"ed25519": "unknown"},
            "type": event_type,
            "content": content,
        }

        # 加密
        payload_json = json.dumps(wrapper, ensure_ascii=False)
        ciphertext = session.encrypt(payload_json.encode())

        logger.debug(
            f"Olm 加密完成：type={ciphertext.message_type} payload_len={len(payload_json)}"
        )

        # 更新存储
        self.store.update_olm_session(
            their_identity_key, 0, session.pickle(self._pickle_key)
        )

        return {
            "algorithm": OLM_ALGO,
            "sender_key": self.curve25519_key,
            "ciphertext": {
                their_identity_key: {
                    "type": ciphertext.message_type,
                    "body": ciphertext.ciphertext,
                }
            },
        }

    def decrypt_olm_message(
        self, sender_key: str, message_type: int, ciphertext: str
    ) -> str:
        """
        解密 Olm 消息

        Args:
            sender_key: 发送者的 curve25519 密钥
            message_type: 消息类型 (0=prekey, 1=normal)
            ciphertext: 密文

        Returns:
            明文
        """
        if not self._account:
            raise RuntimeError("Olm 账户未初始化")

        logger.debug(f"开始 Olm 解密：sender={sender_key[:8]}... type={message_type}")

        # 尝试使用现有会话解密
        sessions = self._olm_sessions.get(sender_key, [])
        for i, session in enumerate(sessions):
            try:
                plaintext = session.decrypt(message_type, ciphertext)
                logger.debug(f"使用现有会话 {i} 解密成功")
                # 更新会话
                self.store.update_olm_session(
                    sender_key, i, session.pickle(self._pickle_key)
                )
                return plaintext
            except Exception as e:
                logger.debug(f"会话 {i} 解密失败：{e}")
                continue

        # 如果是 prekey 消息，创建新的入站会话
        if message_type == 0:
            logger.info(f"收到 PreKey 消息，尝试从 {sender_key[:8]}... 创建入站会话")
            try:
                session = self._account.create_inbound_session(sender_key, ciphertext)
                plaintext = session.decrypt(message_type, ciphertext)
                logger.info("创建入站会话并解密成功")

                # 移除已使用的一次性密钥
                self._account.remove_one_time_keys(session)

                # 缓存和保存会话
                if sender_key not in self._olm_sessions:
                    self._olm_sessions[sender_key] = []
                self._olm_sessions[sender_key].append(session)
                self.store.add_olm_session(sender_key, session.pickle(self._pickle_key))
                self._save_account()

                return plaintext
            except Exception as e:
                logger.error(f"创建入站会话失败：{e}")
                raise

        raise RuntimeError(f"无法解密来自 {sender_key} 的 Olm 消息")

    # ========== Megolm 会话 ==========

    def add_megolm_inbound_session(
        self, room_id: str, session_id: str, session_key: str, sender_key: str
    ):
        """
        添加 Megolm 入站会话 (从 m.room_key 事件或备份恢复)

        Args:
            room_id: 房间 ID
            session_id: 会话 ID
            session_key: 会话密钥 (base64 编码的字符串)
            sender_key: 发送者的 curve25519 密钥
        """
        try:
            # vodozemac ExportedSessionKey constructor accepts base64 strings
            # Matrix key backups store exported session keys (starting with "AQ")
            if isinstance(session_key, str):
                # Use ExportedSessionKey constructor which implements from_base64
                exported_key = ExportedSessionKey(session_key)
                session = InboundGroupSession.import_session(exported_key)
                self._megolm_inbound[session_id] = session
                self.store.save_megolm_inbound(
                    session_id, session.pickle(self._pickle_key)
                )
                logger.info(
                    f"添加 Megolm 入站会话：{session_id[:8]}... 房间：{room_id}"
                )
            else:
                # vodozemac SessionKey object (from m.room_key events)
                session = InboundGroupSession(session_key)
                self._megolm_inbound[session_id] = session
                self.store.save_megolm_inbound(
                    session_id, session.pickle(self._pickle_key)
                )
                logger.debug(
                    f"添加 Megolm 入站会话：{session_id[:8]}... 房间：{room_id}"
                )
        except Exception as e:
            logger.error(f"添加 Megolm 入站会话失败：{e}")

    def decrypt_megolm(self, session_id: str, ciphertext: str) -> dict | None:
        """
        解密 Megolm 消息

        Args:
            session_id: 会话 ID
            ciphertext: 密文

        Returns:
            解密后的事件内容，或 None
        """
        # 尝试从缓存获取会话
        session = self._megolm_inbound.get(session_id)

        # 尝试从存储加载 vodozemac session
        if not session:
            pickle = self.store.get_megolm_inbound(session_id)
            if pickle:
                try:
                    session = InboundGroupSession.from_pickle(pickle, self._pickle_key)
                    self._megolm_inbound[session_id] = session
                except Exception as e:
                    logger.error(f"加载 Megolm 会话失败：{e}")
                    return None

        if not session:
            logger.warning(f"未找到 Megolm 会话：{session_id[:8]}...")
            return None

        try:
            # Convert ciphertext string to MegolmMessage
            if isinstance(ciphertext, str):
                message = MegolmMessage.from_base64(ciphertext)
            else:
                message = ciphertext
            plaintext = session.decrypt(message)
            # 解析解密后的 JSON
            return json.loads(plaintext.plaintext)
        except Exception as e:
            logger.error(f"Megolm 解密失败：{e}")
            return None

    def get_megolm_inbound_session(self, session_id: str):
        """
        获取 Megolm 入站会话对象（用于导出会话密钥等操作）

        Args:
            session_id: 会话 ID

        Returns:
            InboundGroupSession 或 None
        """
        # 先从缓存获取
        session = self._megolm_inbound.get(session_id)
        if session:
            return session

        # 尝试从存储加载
        pickle = self.store.get_megolm_inbound(session_id)
        if pickle:
            try:
                session = InboundGroupSession.from_pickle(pickle, self._pickle_key)
                self._megolm_inbound[session_id] = session
                return session
            except Exception as e:
                logger.error(f"加载 Megolm 会话失败：{e}")
                return None

        return None

    def create_megolm_outbound_session(self, room_id: str) -> tuple[str, str]:
        """
        创建 Megolm 出站会话

        Args:
            room_id: 房间 ID

        Returns:
            (session_id, session_key_base64) 元组
        """
        session = GroupSession()
        self._megolm_outbound[room_id] = session
        self.store.save_megolm_outbound(room_id, session.pickle(self._pickle_key))

        return session.session_id, session.session_key.to_base64()

    def encrypt_megolm(self, room_id: str, event_type: str, content: dict) -> dict:
        """
        使用 Megolm 加密消息

        Args:
            room_id: 房间 ID
            event_type: 事件类型
            content: 事件内容

        Returns:
            加密后的 m.room.encrypted 内容
        """
        session = self._megolm_outbound.get(room_id)
        if not session:
            # Try to load from store
            pickle = self.store.get_megolm_outbound(room_id)
            if pickle:
                try:
                    session = GroupSession.from_pickle(pickle, self._pickle_key)
                    self._megolm_outbound[room_id] = session
                except Exception as e:
                    logger.error(f"加载 Megolm 出站会话失败：{e}")

        if not session:
            raise RuntimeError(f"房间 {room_id} 没有 Megolm 出站会话")

        # 构造要加密的有效载荷
        payload = {
            "type": event_type,
            "content": content,
            "room_id": room_id,
        }
        payload_json = json.dumps(payload, ensure_ascii=False)

        # 加密
        ciphertext = session.encrypt(payload_json.encode())

        # 更新存储
        self.store.save_megolm_outbound(room_id, session.pickle(self._pickle_key))

        return {
            "algorithm": MEGOLM_ALGO,
            "sender_key": self._account.curve25519_key.to_base64()
            if self._account
            else "",
            "session_id": session.session_id,
            "ciphertext": ciphertext.to_base64(),
            "device_id": self.device_id,
        }

    # ========== 辅助方法 ==========

    @staticmethod
    def _canonical_json(obj: dict) -> str:
        """生成规范化的 JSON 字符串 (用于签名)"""
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )

    @property
    def curve25519_key(self) -> str:
        """获取本设备的 curve25519 密钥"""
        if not self._account:
            raise RuntimeError("Olm 账户未初始化")
        return self._account.curve25519_key.to_base64()

    @property
    def ed25519_key(self) -> str:
        """获取本设备的 ed25519 密钥"""
        if not self._account:
            raise RuntimeError("Olm 账户未初始化")
        return self._account.ed25519_key.to_base64()
