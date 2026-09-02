"""SAS start event handling."""

from astrbot.api import logger

from .....constants import M_RECIPROCATE_V1_METHOD, M_SAS_V1_METHOD
from ...constants import Sas, VODOZEMAC_SAS_AVAILABLE


class SASVerificationFlowStartEventMixin:
    """处理 SAS start 事件并发送 accept。"""

    async def _create_legacy_standalone_sas_session(
        self,
        sender: str,
        from_device: str,
        transaction_id: str,
    ) -> dict:
        """Create the deprecated-but-still-receivable standalone SAS flow."""
        sas = None
        if VODOZEMAC_SAS_AVAILABLE and Sas is not None:
            try:
                sas = Sas()
            except Exception as e:
                logger.warning(f"[E2EE-Verify] 创建 legacy standalone SAS 失败：{e}")

        session = {
            "sender": sender,
            "from_device": from_device,
            "their_device": from_device,
            "methods": [M_SAS_V1_METHOD],
            "state": "legacy_start",
            "sas": sas,
            "legacy_standalone_start": True,
            "we_started_it": False,
            "we_are_initiator": False,
        }
        self._sessions[transaction_id] = session

        query_keys = getattr(self, "_query_request_verification_keys", None)
        if callable(query_keys):
            await query_keys(session, sender, from_device)
        return session

    async def _resolve_simultaneous_start(
        self,
        session: dict,
        sender: str,
        from_device: str,
        method: str | None,
        transaction_id: str,
    ) -> bool:
        """Return True when the received start must be ignored/cancelled."""
        if not session.get("we_are_initiator") or not session.get("start_content"):
            return False

        our_method = session.get("start_content", {}).get("method")
        if our_method != method:
            await self._send_cancel(
                sender,
                from_device,
                transaction_id,
                "m.unexpected_message",
                "Simultaneous verification starts selected different methods",
            )
            session["state"] = "cancelled"
            session["cancel_code"] = "m.unexpected_message"
            return True

        # The lexicographically largest sender's start is ignored. For self-
        # verification, compare device IDs because the user IDs are equal.
        if sender == self.user_id:
            remote_wins = from_device < self.device_id
        else:
            remote_wins = sender < self.user_id

        if not remote_wins:
            logger.debug(
                "[E2EE-Verify] 同时收到 start；按 Matrix tie-break 忽略对端 start"
            )
            return True

        logger.debug(
            "[E2EE-Verify] 同时收到 start；按 Matrix tie-break 放弃本地 initiator 角色"
        )
        return False

    async def _handle_start(self, sender: str, content: dict, transaction_id: str):
        """处理验证开始"""
        from_device = content.get("from_device")
        method = content.get("method")
        their_commitment = content.get("commitment")

        session = self._sessions.get(transaction_id)
        if session is None:
            # Standalone starts are deprecated, but the stable spec still requires
            # clients to handle them for older peers. Only standalone SAS can form
            # a meaningful flow without a preceding QR/request context.
            if not from_device:
                logger.warning("[E2EE-Verify] standalone start 缺少 from_device，忽略")
                return
            if method != M_SAS_V1_METHOD:
                code = (
                    "m.unknown_transaction"
                    if method == M_RECIPROCATE_V1_METHOD
                    else "m.unknown_method"
                )
                await self._send_cancel(
                    sender,
                    from_device,
                    transaction_id,
                    code,
                    "Standalone verification method requires an existing request"
                    if method == M_RECIPROCATE_V1_METHOD
                    else "Unsupported standalone verification method",
                )
                return
            session = await self._create_legacy_standalone_sas_session(
                sender,
                from_device,
                transaction_id,
            )
        else:
            session = self._get_bound_verification_session(
                transaction_id,
                sender,
                from_device,
            )
            if session is None:
                return

        if from_device and await self._resolve_simultaneous_start(
            session,
            sender,
            from_device,
            method,
            transaction_id,
        ):
            return

        masked_their_commitment = (
            their_commitment[:16] if isinstance(their_commitment, str) else "None"
        )
        logger.info(
            f"[E2EE-Verify] 验证开始：method={method} "
            f"commitment={masked_their_commitment}..."
        )

        session["state"] = "started"
        session["method"] = method
        session["their_commitment"] = their_commitment
        session["start_content"] = content
        session["we_are_initiator"] = False  # 收到 start，说明对方是 Initiator

        if method == M_RECIPROCATE_V1_METHOD:
            handled = await self._handle_reciprocate_start(
                sender,
                from_device,
                content,
                transaction_id,
                session,
            )
            if handled:
                return

        # Check if this is an in-room verification
        is_in_room = session.get("is_in_room", False)
        room_id = session.get("room_id")

        if self.auto_verify_mode in ("auto_accept", "manual"):
            if from_device:
                if is_in_room and room_id:
                    await self._send_in_room_accept(room_id, transaction_id, content)
                else:
                    await self._send_accept(
                        sender, from_device, transaction_id, content
                    )
