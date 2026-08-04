"""Create an inbound Olm session from a PreKey message."""

from astrbot.api import logger

from ....types import Curve25519PublicKey, PreKeyMessage
from ...sessions import MAX_OLM_SESSIONS_PER_PEER


class OlmMachineMessageDecryptionPreKeyMixin:
    def _create_inbound_session(
        self,
        sender_key: str,
        ciphertext: str,
        masked_sender_key: str,
    ) -> str:
        logger.info(f"收到 PreKey 消息，尝试从 {masked_sender_key}... 创建入站会话")

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
                logger.debug(
                    f"PreKey 消息中使用的一次性密钥：{(otk_used or '')[:16]}..."
                )
            except Exception:
                pass

            session, plaintext = self._account.create_inbound_session(
                identity_key, message
            )
            logger.info("创建入站会话并解密成功")

            # 移除已使用的一次性密钥 (vodozemac 会自动处理)
            # self._account.remove_one_time_keys(session)

            # 缓存和保存会话 (cap per-peer to prevent memory exhaustion)
            if sender_key not in self._olm_sessions:
                self._olm_sessions[sender_key] = []
            sessions = self._olm_sessions[sender_key]
            sessions.append(session)
            if len(sessions) > MAX_OLM_SESSIONS_PER_PEER:
                sessions.pop(0)
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
