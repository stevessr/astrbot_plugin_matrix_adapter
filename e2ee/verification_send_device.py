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
    M_KEY_VERIFICATION_START,
    M_SAS_V1_METHOD,
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


class SASVerificationSendDeviceMixin:
    async def _send_ready(self, to_user: str, to_device: str, transaction_id: str):
        """发送 ready 响应"""
        content = {
            "from_device": self.device_id,
            "methods": SAS_METHODS,
            "transaction_id": transaction_id,
        }
        await self._send_to_device(
            M_KEY_VERIFICATION_READY, to_user, to_device, content
        )
        logger.info("[E2EE-Verify] 已发送 ready")

    async def _send_start(self, to_user: str, to_device: str, transaction_id: str):
        """发送 start 消息 (作为发起者)"""
        # 生成 commitment
        import secrets

        # 1. 生成公钥 (start 时不发送，但在 start 后发送 key 时会用到)
        # 此时我们需要创建一个 SAS 对象
        sas = None
        if VODOZEMAC_SAS_AVAILABLE:
            try:
                sas = Sas()
                our_public_key = sas.public_key.to_base64()
            except Exception as e:
                logger.warning(f"Failed to create SAS: {e}")
                our_public_key = base64.b64encode(secrets.token_bytes(32)).decode()
        else:
            our_public_key = base64.b64encode(secrets.token_bytes(32)).decode()

        session = self._sessions.get(transaction_id, {})
        session["sas"] = sas
        session["our_public_key"] = our_public_key

        # 2. 构造 start 内容
        content = {
            "from_device": self.device_id,
            "method": M_SAS_V1_METHOD,
            "key_agreement_protocols": KEY_AGREEMENT_PROTOCOLS,
            "hashes": HASHES,
            "message_authentication_codes": MESSAGE_AUTHENTICATION_CODES,
            "short_authentication_string": SHORT_AUTHENTICATION_STRING,
            "transaction_id": transaction_id,
        }

        # 3. 计算 commitment (注意：start 消息本身不包含 commitment，
        # 而是 accept 消息包含。但是等等，根据 Matrix 流程：
        # Initiator sends start.
        # Responder sends accept (with commitment).
        # Initiator sends key.
        # Responder sends key.
        # 所以 start 消息只需要包含支持的算法)

        # 实际上 start 消息不需要 commitment。
        # Commitment 是 Responder 发送的。

        await self._send_to_device(
            M_KEY_VERIFICATION_START, to_user, to_device, content
        )
        logger.info("[E2EE-Verify] 已发送 start")

    async def _send_accept(
        self, to_user: str, to_device: str, transaction_id: str, start_content: dict
    ):
        """发送 accept - 使用真正的密钥协商"""
        their_key_agreement = start_content.get("key_agreement_protocols", [])
        their_hashes = start_content.get("hashes", [])
        their_macs = start_content.get("message_authentication_codes", [])
        their_sas = start_content.get("short_authentication_string", [])

        key_agreement = next(
            (k for k in KEY_AGREEMENT_PROTOCOLS if k in their_key_agreement),
            KEY_AGREEMENT_PROTOCOLS[0],
        )
        hash_algo = next((h for h in HASHES if h in their_hashes), HASHES[0])
        mac = next(
            (m for m in MESSAGE_AUTHENTICATION_CODES if m in their_macs),
            MESSAGE_AUTHENTICATION_CODES[0],
        )
        sas_methods = [s for s in SHORT_AUTHENTICATION_STRING if s in their_sas]

        session = self._sessions.get(transaction_id, {})

        # 生成我们的公钥
        sas = session.get("sas")
        if sas and VODOZEMAC_SAS_AVAILABLE:
            # vodozemac 返回 Key 对象，需要转换为 base64 字符串
            our_public_key = sas.public_key.to_base64()
            logger.info(
                f"[E2EE-Verify] Using existing SAS object, public_key: {our_public_key}"
            )
        elif VODOZEMAC_SAS_AVAILABLE:
            # SAS object not in session, create new one
            logger.warning(
                "[E2EE-Verify] SAS object not in session, creating new SAS for accept"
            )
            try:
                sas = Sas()
                our_public_key = sas.public_key.to_base64()
                session["sas"] = sas
                logger.info(
                    f"[E2EE-Verify] Created new SAS, public_key: {our_public_key}"
                )
            except Exception as e:
                logger.error(f"[E2EE-Verify] Failed to create SAS: {e}")
                our_public_key = base64.b64encode(secrets.token_bytes(32)).decode()
                logger.warning(
                    "[E2EE-Verify] Using fallback random key (commitment will fail!)"
                )
        else:
            logger.warning(
                "[E2EE-Verify] vodozemac not available, using fallback random key"
            )
            # 回退：生成随机密钥 (仅用于显示)
            our_public_key = base64.b64encode(secrets.token_bytes(32)).decode()

        session["our_public_key"] = our_public_key
        session["key_agreement"] = key_agreement
        session["hash"] = hash_algo
        session["mac"] = mac
        session["sas_methods"] = sas_methods

        # 计算 commitment = UnpaddedBase64(SHA256(public_key || canonical_json(start_content)))
        # 根据 Matrix 规范，public_key 使用 unpadded base64 编码
        commitment_data = our_public_key + _canonical_json(start_content)
        commitment = (
            base64.b64encode(hashlib.sha256(commitment_data.encode()).digest())
            .decode()
            .rstrip("=")
        )

        content = {
            "transaction_id": transaction_id,
            "method": "m.sas.v1",
            "key_agreement_protocol": key_agreement,
            "hash": hash_algo,
            "message_authentication_code": mac,
            "short_authentication_string": sas_methods,
            "commitment": commitment,
        }

        await self._send_to_device(
            M_KEY_VERIFICATION_ACCEPT, to_user, to_device, content
        )
        logger.info(f"[E2EE-Verify] 已发送 accept (commitment: {commitment[:16]}...)")

    async def _send_key(self, to_user: str, to_device: str, transaction_id: str):
        """发送公钥"""
        session = self._sessions.get(transaction_id, {})

        sas = session.get("sas")
        if sas and VODOZEMAC_SAS_AVAILABLE:
            # vodozemac 返回 Key 对象，需要转换为 base64 字符串
            our_public_key = sas.public_key.to_base64()
        else:
            our_public_key = session.get(
                "our_public_key", base64.b64encode(secrets.token_bytes(32)).decode()
            )

        session["our_public_key"] = our_public_key
        session["key_sent"] = True

        content = {
            "transaction_id": transaction_id,
            "key": our_public_key,
        }

        await self._send_to_device(M_KEY_VERIFICATION_KEY, to_user, to_device, content)
        logger.info(f"[E2EE-Verify] 已发送 key: {our_public_key[:20]}...")

    async def _send_mac(
        self, to_user: str, to_device: str, transaction_id: str, session: dict
    ):
        """发送 MAC - 使用 HKDF-HMAC-SHA256.v2"""
        established_sas = session.get("established_sas")
        sas_bytes = session.get("sas_bytes", b"\x00" * 32)

        # 生成 MAC 的基础密钥
        our_device_key_id = f"ed25519:{self.device_id}"

        if established_sas and VODOZEMAC_SAS_AVAILABLE:
            try:
                # 根据 Matrix 规范，info 格式为：
                # MATRIX_KEY_VERIFICATION_MAC + user_id + device_id + other_user_id + other_device_id + transaction_id + key_id
                base_info = f"{INFO_PREFIX_MAC}{self.user_id}{self.device_id}{to_user}{to_device}{transaction_id}"

                # 计算设备密钥的 MAC
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
                # 回退实现
                mac_content = {
                    our_device_key_id: base64.b64encode(
                        _compute_hkdf(sas_bytes, b"", our_device_key_id.encode())
                    ).decode()
                }
                keys_mac = base64.b64encode(
                    hashlib.sha256(our_device_key_id.encode()).digest()
                ).decode()
        else:
            # 回退实现
            mac_content = {
                our_device_key_id: base64.b64encode(
                    _compute_hkdf(sas_bytes, b"", our_device_key_id.encode())
                ).decode()
            }
            keys_mac = base64.b64encode(
                hashlib.sha256(our_device_key_id.encode()).digest()
            ).decode()

        content = {
            "transaction_id": transaction_id,
            "mac": mac_content,
            "keys": keys_mac,
        }

        await self._send_to_device(M_KEY_VERIFICATION_MAC, to_user, to_device, content)
        logger.info("[E2EE-Verify] 已发送 mac")

    async def _send_done(self, to_user: str, to_device: str, transaction_id: str):
        """发送 done"""
        content = {"transaction_id": transaction_id}
        await self._send_to_device(M_KEY_VERIFICATION_DONE, to_user, to_device, content)
        logger.info("[E2EE-Verify] 已发送 done")

    async def _send_cancel(
        self, to_user: str, to_device: str, transaction_id: str, code: str, reason: str
    ):
        """发送取消"""
        content = {
            "transaction_id": transaction_id,
            "code": code,
            "reason": reason,
        }
        await self._send_to_device(
            M_KEY_VERIFICATION_CANCEL, to_user, to_device, content
        )
        logger.info(f"[E2EE-Verify] 已发送 cancel: {code} - {reason}")

    async def _send_to_device(
        self, event_type: str, to_user: str, to_device: str, content: dict
    ):
        """发送 to_device 消息"""
        try:
            txn_id = secrets.token_hex(16)
            messages = {to_user: {to_device: content}}
            await self.client.send_to_device(event_type, messages, txn_id)
        except Exception as e:
            logger.error(f"[E2EE-Verify] 发送 {event_type} 失败：{e}")

    # ========== In-Room 验证消息发送 ==========
