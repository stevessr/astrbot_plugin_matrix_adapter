"""SAS key-exchange orchestration."""

from astrbot.api import logger

from .compat import _vodozemac_sas_available


class SASVerificationFlowKeyCoreMixin:
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
            if not self._verify_commitment(
                their_key,
                start_content,
                their_commitment,
            ):
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

        # Safety check: Skip if SAS already computed (defensive measure)
        if session.get("established_sas") or session.get("sas_emojis"):
            logger.debug("[E2EE-Verify] SAS 已计算，跳过重复计算")
            return

        if sas and _vodozemac_sas_available() and their_key:
            if not await self._compute_vodozemac_sas(
                session,
                sas=sas,
                sender=sender,
                their_device=their_device,
                their_key=their_key,
                transaction_id=transaction_id,
            ):
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
