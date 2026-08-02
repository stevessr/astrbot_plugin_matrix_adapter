"""SAS ephemeral key exchange and shared-secret calculation."""

import hashlib
import sys

from astrbot.api import logger

from ....constants import INFO_PREFIX_SAS
from ..constants import (
    SAS_EMOJIS,
    VODOZEMAC_SAS_AVAILABLE,
    Curve25519PublicKey,
)
from ..crypto_utils import _canonical_json, _encode_unpadded_base64


def _vodozemac_sas_available() -> bool:
    package = sys.modules.get(__package__)
    if package is not None:
        return bool(
            getattr(package, "VODOZEMAC_SAS_AVAILABLE", VODOZEMAC_SAS_AVAILABLE)
        )
    return VODOZEMAC_SAS_AVAILABLE


class SASVerificationFlowKeyExchangeMixin:
    """处理 commitment、公钥交换和 SAS 共享密钥计算。"""

    async def _handle_key(self, sender: str, content: dict, transaction_id: str):
        """处理密钥交换 - 使用真正的 X25519"""
        their_key = content.get("key")

        if not isinstance(their_key, str) or not their_key:
            logger.warning("[E2EE-Verify] 对方公钥缺失或格式不正确")
            return
        logger.info("[E2EE-Verify] 收到对方公钥")

        session = self._sessions.get(transaction_id, {})

        # 根据 Matrix 规范验证 commitment
        # commitment = SHA256(公钥 || canonical_json(start_content))
        # 参考：https://spec.matrix.org/latest/client-server-api/#sas-verification
        their_commitment = session.get("their_commitment")
        start_content = session.get("start_content")
        if their_commitment and start_content and session.get("we_are_initiator"):
            # The start sender validates the accept sender's commitment once it
            # receives that sender's public key. Hash the exact start *content*
            # object and encode the digest as unpadded Base64 (Matrix v1.19).
            combined = (their_key + _canonical_json(start_content)).encode("utf-8")
            computed = _encode_unpadded_base64(hashlib.sha256(combined).digest())

            if computed != their_commitment:
                logger.warning(
                    "[E2EE-Verify] Commitment 验证失败！"
                    f"expected={(their_commitment if isinstance(their_commitment, str) else '')[:16]}... "
                    f"computed={(computed or '')[:16]}..."
                )
                # 根据规范，commitment 不匹配应该取消验证
                if session.get("is_in_room") and session.get("room_id"):
                    await self._send_in_room_cancel(
                        session["room_id"],
                        transaction_id,
                        "m.mismatched_commitment",
                        "Commitment verification failed",
                    )
                else:
                    their_device = session.get(
                        "from_device", session.get("their_device", "")
                    )
                    await self._send_cancel(
                        sender,
                        their_device,
                        transaction_id,
                        "m.mismatched_commitment",
                        "Commitment verification failed",
                    )
                return
            else:
                logger.info("[E2EE-Verify] ✅ Commitment 验证通过")

        session["their_key"] = their_key
        session["state"] = "key_exchanged"

        # Check if this is an in-room verification
        is_in_room = session.get("is_in_room", False)
        room_id = session.get("room_id")
        their_device = session.get("from_device", session.get("their_device", ""))

        # 如果我们还没发送自己的公钥，先发送
        if not session.get("key_sent"):
            if self.auto_verify_mode in ("auto_accept", "manual"):
                if is_in_room and room_id:
                    await self._send_in_room_key(room_id, transaction_id)
                else:
                    await self._send_key(sender, their_device, transaction_id)
                session["key_sent"] = True

        sas = session.get("sas")
        our_key = session.get("our_public_key")

        # Safety check: Skip if SAS already computed (defensive measure)
        if session.get("established_sas") or session.get("sas_emojis"):
            logger.debug("[E2EE-Verify] SAS 已计算，跳过重复计算")
            return

        if sas and _vodozemac_sas_available() and their_key:
            try:
                # 使用 vodozemac 计算共享密钥
                # 构造 SAS info 字符串
                their_user = sender

                # 确定 Initiator 和 Recipient
                # 发送 m.key.verification.start 的是 Initiator
                if session.get("we_are_initiator"):
                    init_user, init_dev, init_key = (
                        self.user_id,
                        self.device_id,
                        our_key,
                    )
                    rec_user, rec_dev, rec_key = their_user, their_device, their_key
                else:
                    init_user, init_dev, init_key = their_user, their_device, their_key
                    rec_user, rec_dev, rec_key = self.user_id, self.device_id, our_key

                info = (
                    f"{INFO_PREFIX_SAS}"
                    f"{init_user}|{init_dev}|{init_key}|"
                    f"{rec_user}|{rec_dev}|{rec_key}|"
                    f"{transaction_id}"
                )

                # 使用 vodozemac 的 diffie_hellman 方法完成密钥交换
                # 这会返回一个 EstablishedSas 对象
                their_public_key = Curve25519PublicKey.from_base64(their_key)
                established_sas = sas.diffie_hellman(their_public_key)

                # 保存 established_sas 用于后续 MAC 计算
                session["established_sas"] = established_sas

                # 使用 established_sas.bytes(info) 获取 SAS 字节对象
                sas_bytes_obj = established_sas.bytes(info)

                # vodozemac SasBytes 对象有 emoji_indices (bytes) 和 decimals (tuple) 属性
                # emoji_indices 是 7 个字节，每个字节是 0-63 的索引
                emoji_indices = sas_bytes_obj.emoji_indices
                emojis = [SAS_EMOJIS[idx] for idx in emoji_indices]

                # decimals 是一个包含 3 个数字的元组
                decimals_tuple = sas_bytes_obj.decimals
                if len(decimals_tuple) >= 3:
                    decimals = (
                        f"{decimals_tuple[0]} {decimals_tuple[1]} {decimals_tuple[2]}"
                    )
                else:
                    decimals = " ".join(map(str, decimals_tuple))

                session["sas_bytes"] = emoji_indices  # 保存原始字节用于回退
                session["sas_emojis"] = emojis
                session["sas_decimals"] = decimals

                emoji_str = " ".join(e[0] for e in emojis)
                logger.info(f"[E2EE-Verify] SAS 验证码：{emoji_str} | 数字：{decimals}")

            except Exception as e:
                logger.error(f"[E2EE-Verify] 计算 SAS 失败：{e}")
                # 回退到简化实现
                self._compute_sas_fallback(session, their_key)
        else:
            # 使用简化实现
            self._compute_sas_fallback(session, their_key)

        if self.auto_verify_mode == "manual" and not session.get("manual_notified"):
            session["manual_notified"] = True
            await self._notify_admin_for_verification(session, transaction_id)

        # Send MAC only if not already sent
        if self.auto_verify_mode == "auto_accept" and not session.get("mac_sent"):
            session["mac_sent"] = True
            if is_in_room and room_id:
                await self._send_in_room_mac(room_id, transaction_id, session)
            else:
                await self._send_mac(
                    sender,
                    their_device,
                    transaction_id,
                    session,
                )


__all__ = ["SASVerificationFlowKeyExchangeMixin"]
