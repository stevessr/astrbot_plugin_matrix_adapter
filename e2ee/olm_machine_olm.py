import base64
import json

from astrbot.api import logger

from ..constants import OLM_ALGO
from .olm_machine_types import (
    AnyOlmMessage,
    Curve25519PublicKey,
    PreKeyMessage,
    Session,
)


class OlmMachineOlmMixin:
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
        identity_key = Curve25519PublicKey.from_base64(their_identity_key)
        one_time_key = Curve25519PublicKey.from_base64(their_one_time_key)

        session = self._account.create_outbound_session(identity_key, one_time_key)

        # 缓存会话
        if their_identity_key not in self._olm_sessions:
            self._olm_sessions[their_identity_key] = []
        self._olm_sessions[their_identity_key].append(session)

        # 保存会话
        self.store.add_olm_session(their_identity_key, session.pickle(self._pickle_key))
        self._save_account()

        return session

    def get_olm_session(self, their_identity_key: str) -> Session | None:
        """
        获取与指定设备的现有 Olm 会话

        Args:
            their_identity_key: 对方的 curve25519 身份密钥

        Returns:
            现有的 Olm 会话，如果不存在则返回 None
        """
        sessions = self._olm_sessions.get(their_identity_key, [])
        if sessions:
            return sessions[0]

        # 尝试从存储加载
        pickles = self.store.get_olm_sessions(their_identity_key)
        if pickles:
            try:
                session = Session.from_pickle(pickles[0], self._pickle_key)
                if their_identity_key not in self._olm_sessions:
                    self._olm_sessions[their_identity_key] = []
                self._olm_sessions[their_identity_key].append(session)
                return session
            except Exception as e:
                logger.debug(f"加载 Olm 会话失败：{e}")

        return None

    def encrypt_olm(
        self,
        their_identity_key: str,
        content: dict,
        session: Session | None = None,
        recipient_user_id: str = "unknown",
        recipient_ed25519_key: str = "unknown",
        event_type: str = "m.room_key",
    ) -> dict:
        """
        使用 Olm 加密内容并添加 Matrix 协议外壳

        Args:
            their_identity_key: 对方的 curve25519 密钥
            content: 要加密的内容 (m.room_key 等)
            session: 可选，已有的 Olm 会话
            recipient_user_id: 接收者用户 ID
            recipient_ed25519_key: 接收者的 ed25519 密钥
            event_type: 事件类型（默认 m.room_key）

        Returns:
            符合 m.room.encrypted (Olm) 格式的字典
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
        wrapper = {
            "sender": self.user_id,
            "sender_device": self.device_id,
            "keys": {"ed25519": self.ed25519_key},
            "recipient": recipient_user_id,
            "recipient_keys": {"ed25519": recipient_ed25519_key},
            "type": event_type,
            "content": content,
        }

        # 加密
        payload_json = json.dumps(wrapper, ensure_ascii=False)
        ciphertext = session.encrypt(payload_json.encode())

        # vodozemac 返回 AnyOlmMessage，需要使用 to_parts() 获取消息类型和密文
        # to_parts() 返回 (message_type: int, ciphertext: bytes)
        message_type, ciphertext_bytes = ciphertext.to_parts()

        # 将密文转换为 base64 字符串
        import base64

        ciphertext_b64 = base64.b64encode(ciphertext_bytes).decode()

        logger.debug(
            f"Olm 加密完成：type={message_type} payload_len={len(payload_json)}"
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
                    "type": message_type,
                    "body": ciphertext_b64,
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

        # 将 base64 密文转换为 bytes，然后创建 AnyOlmMessage
        # Matrix 使用 unpadded base64，需要添加填充
        # 添加 base64 填充
        padded_ciphertext = ciphertext + "=" * (-len(ciphertext) % 4)
        ciphertext_bytes = base64.b64decode(padded_ciphertext)

        # 尝试使用现有会话解密
        sessions = self._olm_sessions.get(sender_key, [])
        mac_length_error = False
        for i, session in enumerate(sessions):
            try:
                # 使用 AnyOlmMessage.from_parts 创建消息对象
                message = AnyOlmMessage.from_parts(message_type, ciphertext_bytes)
                plaintext = session.decrypt(message)
                logger.debug(f"使用现有会话 {i} 解密成功")
                # 更新会话
                self.store.update_olm_session(
                    sender_key, i, session.pickle(self._pickle_key)
                )
                return plaintext
            except Exception as e:
                error_msg = str(e).lower()
                logger.debug(f"会话 {i} 解密失败：{e}")
                # 检测 MAC 长度不匹配错误（vodozemac 与 libolm 兼容性问题）
                if "mac length" in error_msg or "invalid mac" in error_msg:
                    mac_length_error = True
                    logger.warning(
                        f"检测到 MAC 长度不匹配（vodozemac/libolm 兼容性问题）：{e}"
                    )
                continue

        # 如果 MAC 长度错误，清除该发送者的旧会话并等待新的 PreKey 消息
        if mac_length_error and sender_key in self._olm_sessions:
            logger.warning(
                f"清除与 {sender_key[:8]}... 的旧 Olm 会话（MAC 格式不兼容）"
            )
            self._olm_sessions[sender_key] = []
            # 同时清除存储中的会话
            self.store.clear_olm_sessions(sender_key)

        # 如果是 prekey 消息，创建新的入站会话
        if message_type == 0:
            logger.info(f"收到 PreKey 消息，尝试从 {sender_key[:8]}... 创建入站会话")

            # 调试：显示当前账户中的一次性密钥信息
            try:
                unpublished_otks = self._account.one_time_keys
                logger.debug(
                    f"账户中未发布的一次性密钥数量：{len(unpublished_otks) if unpublished_otks else 0}"
                )
                # 注意：已发布的密钥存储在账户内部，无法直接查询数量
                # 但 create_inbound_session 会查找所有已发布的密钥
            except Exception as debug_e:
                logger.debug(f"获取一次性密钥信息失败：{debug_e}")

            try:
                identity_key = Curve25519PublicKey.from_base64(sender_key)
                message = PreKeyMessage.from_base64(ciphertext)

                # 尝试从 PreKey 消息中提取一次性密钥信息用于调试
                try:
                    # PreKeyMessage 包含使用的一次性密钥的公钥
                    otk_used = (
                        message.one_time_key.to_base64()
                        if hasattr(message, "one_time_key")
                        else "未知"
                    )
                    logger.debug(f"PreKey 消息中使用的一次性密钥：{otk_used[:16]}...")
                except Exception:
                    pass

                session, plaintext = self._account.create_inbound_session(
                    identity_key, message
                )
                logger.info("创建入站会话并解密成功")

                # 移除已使用的一次性密钥 (vodozemac 会自动处理)
                # self._account.remove_one_time_keys(session)

                # 缓存和保存会话
                if sender_key not in self._olm_sessions:
                    self._olm_sessions[sender_key] = []
                self._olm_sessions[sender_key].append(session)
                self.store.add_olm_session(sender_key, session.pickle(self._pickle_key))
                self._save_account()

                return plaintext
            except Exception as e:
                error_msg = str(e)
                logger.error(f"创建入站会话失败：{e}")

                # 提供更详细的错误诊断
                if "unknown one-time key" in error_msg.lower():
                    logger.error(
                        "诊断：发送方使用的一次性密钥不在本账户中。"
                        "可能原因：1) 账户被重新创建导致密钥丢失 "
                        "2) 发送方缓存了旧密钥 "
                        "3) 一次性密钥已被其他会话使用"
                    )
                    logger.info("正在尝试主动建立新的 Olm 会话...")
                raise

        # 普通消息（type=1）但没有可用的会话
        if message_type == 1:
            logger.warning(
                f"收到普通 Olm 消息但没有可用的会话：sender={sender_key[:8]}... "
                "可能原因：对方认为已有会话，但本端没有。需要请求新会话。"
            )

        raise RuntimeError(f"无法解密来自 {sender_key} 的 Olm 消息")

    # ========== Megolm 会话 ==========
