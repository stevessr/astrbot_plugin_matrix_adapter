import base64
import hashlib
import secrets

from astrbot.api import logger

from ..constants import (
    INFO_PREFIX_MAC,
    KEY_AGREEMENT_PROTOCOLS,
    M_KEY_VERIFICATION_ACCEPT,
    M_KEY_VERIFICATION_CANCEL,
    M_KEY_VERIFICATION_DONE,
    M_KEY_VERIFICATION_KEY,
    M_KEY_VERIFICATION_MAC,
    M_KEY_VERIFICATION_READY,
    M_ROOM_ENCRYPTED,
)
from .verification_constants import (
    HASHES,
    MESSAGE_AUTHENTICATION_CODES,
    SAS_METHODS,
    SHORT_AUTHENTICATION_STRING,
    VODOZEMAC_SAS_AVAILABLE,
    Sas,
)
from .verification_utils import _canonical_json, _compute_hkdf


class SASVerificationSendRoomMixin:
    @staticmethod
    def _normalize_algorithm_values(value: object) -> list[str]:
        if isinstance(value, str):
            normalized = value.strip()
            return [normalized] if normalized else []
        if isinstance(value, (list, tuple, set)):
            values: list[str] = []
            for item in value:
                if not isinstance(item, str):
                    continue
                normalized = item.strip()
                if normalized:
                    values.append(normalized)
            return values
        return []

    @staticmethod
    def _pick_algorithm(
        supported: list[str], peer_supported: list[str], fallback: str = ""
    ) -> str:
        for algorithm in supported:
            if algorithm in peer_supported:
                return algorithm
        if supported:
            return supported[0]
        if peer_supported:
            return peer_supported[0]
        return fallback

    async def _send_in_room_event(
        self, room_id: str, event_type: str, content: dict, transaction_id: str
    ):
        """发送房间内验证事件"""
        try:
            # Add m.relates_to to link to the original request
            # Matrix spec: in-room verification events should use m.reference relationship
            content["m.relates_to"] = {
                "rel_type": "m.reference",
                "event_id": transaction_id,
            }

            # Determine if we should encrypt based on session context
            # Check if we have an existing outbound session for this room
            should_encrypt = False
            encrypted_content = None

            if hasattr(self, "e2ee_manager") and self.e2ee_manager:
                try:
                    # Check if room has encryption enabled by looking for existing outbound session
                    if (
                        self.e2ee_manager._store
                        and self.e2ee_manager._store.get_megolm_outbound(room_id)
                    ):
                        should_encrypt = True

                    if should_encrypt:
                        encrypted_content = await self.e2ee_manager.encrypt_message(
                            room_id, event_type, content
                        )

                except Exception as e:
                    logger.warning(f"[E2EE-Verify] Failed to encrypt event: {e}")
                    # Fall back to unencrypted if encryption fails

            if encrypted_content:
                await self.client.send_room_event(
                    room_id, M_ROOM_ENCRYPTED, encrypted_content
                )
                logger.debug(f"[E2EE-Verify] 已发送加密的房间内事件：{event_type}")
            else:
                await self.client.send_room_event(room_id, event_type, content)
                logger.debug(f"[E2EE-Verify] 已发送房间内事件：{event_type}")

        except Exception as e:
            logger.error(f"[E2EE-Verify] 发送房间内事件 {event_type} 失败：{e}")

    async def _send_in_room_ready(self, room_id: str, transaction_id: str):
        """发送房间内 ready 响应"""
        content = {
            "from_device": self.device_id,
            "methods": SAS_METHODS,
        }
        await self._send_in_room_event(
            room_id, M_KEY_VERIFICATION_READY, content, transaction_id
        )
        logger.info("[E2EE-Verify] 已发送 ready")

    async def _send_in_room_accept(
        self, room_id: str, transaction_id: str, start_content: dict
    ):
        """发送房间内 accept"""
        their_key_agreement = self._normalize_algorithm_values(
            start_content.get("key_agreement_protocols", [])
        )
        their_hashes = self._normalize_algorithm_values(start_content.get("hashes", []))
        their_macs = self._normalize_algorithm_values(
            start_content.get("message_authentication_codes", [])
        )
        their_sas = self._normalize_algorithm_values(
            start_content.get("short_authentication_string", [])
        )

        key_agreement = self._pick_algorithm(
            KEY_AGREEMENT_PROTOCOLS,
            their_key_agreement,
            fallback="curve25519-hkdf-sha256",
        )
        hash_algo = self._pick_algorithm(HASHES, their_hashes, fallback="sha256")
        mac = self._pick_algorithm(
            MESSAGE_AUTHENTICATION_CODES,
            their_macs,
            fallback="hkdf-hmac-sha256.v2",
        )
        sas_methods = [s for s in SHORT_AUTHENTICATION_STRING if s in their_sas]
        if not sas_methods:
            sas_methods = list(SHORT_AUTHENTICATION_STRING)

        session = self._sessions.get(transaction_id, {})

        sas = session.get("sas")
        if sas and VODOZEMAC_SAS_AVAILABLE:
            our_public_key = sas.public_key.to_base64()
        elif VODOZEMAC_SAS_AVAILABLE:
            logger.warning(
                "[E2EE-Verify] SAS object not in session, creating new SAS for accept"
            )
            try:
                sas = Sas()
                our_public_key = sas.public_key.to_base64()
                session["sas"] = sas
            except Exception as e:
                logger.error(f"[E2EE-Verify] Failed to create SAS: {e}")
                our_public_key = base64.b64encode(secrets.token_bytes(32)).decode()
        else:
            logger.warning(
                "[E2EE-Verify] vodozemac not available, using fallback random key"
            )
            our_public_key = base64.b64encode(secrets.token_bytes(32)).decode()

        session["our_public_key"] = our_public_key
        session["key_agreement"] = key_agreement
        session["hash"] = hash_algo
        session["mac"] = mac
        session["sas_methods"] = sas_methods

        # 计算 commitment = UnpaddedBase64(SHA256(public_key || canonical_json(start_content)))
        # 根据 Matrix 规范和 matrix-rust-sdk 实现，m.relates_to 应该包含在 canonical JSON 中
        canonical_start = _canonical_json(start_content)
        commitment_data = our_public_key + canonical_start
        commitment = (
            base64.b64encode(hashlib.sha256(commitment_data.encode("utf-8")).digest())
            .decode()
            .rstrip("=")
        )

        logger.debug(
            f"[E2EE-Verify] Commitment: public_key={our_public_key[:16]}..., "
            f"has_m.relates_to={'m.relates_to' in start_content}"
        )

        content = {
            "method": "m.sas.v1",
            "key_agreement_protocol": key_agreement,
            "hash": hash_algo,
            "message_authentication_code": mac,
            "short_authentication_string": sas_methods,
            "commitment": commitment,
        }

        await self._send_in_room_event(
            room_id, M_KEY_VERIFICATION_ACCEPT, content, transaction_id
        )
        logger.info(
            f"[E2EE-Verify] 已发送房间内 accept (commitment: {commitment[:16]}...)"
        )

    async def _send_in_room_key(self, room_id: str, transaction_id: str):
        """发送房间内公钥"""
        session = self._sessions.get(transaction_id, {})

        # 优先使用已存储的公钥（在 accept 中计算 commitment 时使用的同一个）
        our_public_key = session.get("our_public_key")
        if not our_public_key:
            sas = session.get("sas")
            if sas and VODOZEMAC_SAS_AVAILABLE:
                our_public_key = sas.public_key.to_base64()
            else:
                our_public_key = base64.b64encode(secrets.token_bytes(32)).decode()
            session["our_public_key"] = our_public_key

        session["key_sent"] = True

        content = {
            "key": our_public_key,
        }

        await self._send_in_room_event(
            room_id, M_KEY_VERIFICATION_KEY, content, transaction_id
        )
        logger.info("[E2EE-Verify] 已发送 key")

    async def _send_in_room_mac(self, room_id: str, transaction_id: str, session: dict):
        """发送房间内 MAC - 使用 HKDF-HMAC-SHA256.v2"""
        established_sas = session.get("established_sas")
        sas_bytes = session.get("sas_bytes", b"\x00" * 32)
        our_device_key_id = f"ed25519:{self.device_id}"

        # Get their user and device info from session
        to_user = session.get("sender")
        to_device = session.get("from_device", session.get("their_device", ""))

        if established_sas and VODOZEMAC_SAS_AVAILABLE:
            try:
                # 根据 Matrix 规范，info 格式为：
                # MATRIX_KEY_VERIFICATION_MAC + user_id + device_id + other_user_id + other_device_id + transaction_id + key_id
                base_info = f"{INFO_PREFIX_MAC}{self.user_id}{self.device_id}{to_user}{to_device}{transaction_id}"

                if self.olm:
                    device_key = self.olm.ed25519_key
                    # MAC for the device key
                    # vodozemac calculate_mac 直接返回 base64 字符串
                    key_mac = established_sas.calculate_mac(
                        device_key, (base_info + our_device_key_id)
                    )
                    # MAC for the key ID list
                    keys_mac = established_sas.calculate_mac(
                        our_device_key_id, (base_info + "KEY_IDS")
                    )
                else:
                    key_mac = base64.b64encode(
                        hashlib.sha256(our_device_key_id.encode()).digest()
                    ).decode()
                    keys_mac = base64.b64encode(
                        hashlib.sha256(our_device_key_id.encode()).digest()
                    ).decode()

                mac_content = {our_device_key_id: key_mac}
            except Exception as e:
                logger.warning(f"[E2EE-Verify] vodozemac MAC 计算失败，使用回退：{e}")
                mac_content = {
                    our_device_key_id: base64.b64encode(
                        _compute_hkdf(sas_bytes, b"", our_device_key_id.encode())
                    ).decode()
                }
                keys_mac = base64.b64encode(
                    hashlib.sha256(our_device_key_id.encode()).digest()
                ).decode()
        else:
            mac_content = {
                our_device_key_id: base64.b64encode(
                    _compute_hkdf(sas_bytes, b"", our_device_key_id.encode())
                ).decode()
            }
            keys_mac = base64.b64encode(
                hashlib.sha256(our_device_key_id.encode()).digest()
            ).decode()

        content = {
            "mac": mac_content,
            "keys": keys_mac,
        }

        await self._send_in_room_event(
            room_id, M_KEY_VERIFICATION_MAC, content, transaction_id
        )
        logger.info("[E2EE-Verify] 已发送 mac")

    async def _send_in_room_done(self, room_id: str, transaction_id: str):
        """发送房间内 done"""
        content = {}
        await self._send_in_room_event(
            room_id, M_KEY_VERIFICATION_DONE, content, transaction_id
        )
        logger.info("[E2EE-Verify] 已发送 done")

    async def _send_in_room_cancel(
        self, room_id: str, transaction_id: str, code: str, reason: str
    ):
        """发送房间内取消"""
        content = {
            "code": code,
            "reason": reason,
        }
        await self._send_in_room_event(
            room_id, M_KEY_VERIFICATION_CANCEL, content, transaction_id
        )
        logger.info(f"[E2EE-Verify] 已发送房间内 cancel: {code} - {reason}")

    # ========== SAS 计算 ==========
