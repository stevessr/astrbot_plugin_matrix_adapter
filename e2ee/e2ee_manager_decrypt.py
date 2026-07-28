import hashlib
import json

from astrbot.api import logger

from ..constants import MEGOLM_ALGO, OLM_ALGO
from .constants import (
    MEGOLM_MESSAGE_INDEX_FIELD,
    VALID_WITHHELD_CODES,
    WITHHELD_NO_OLM,
)


class E2EEManagerDecryptMixin:
    async def decrypt_event(
        self,
        event_content: dict,
        sender: str | None,
        room_id: str,
        event_id: str | None = None,
    ) -> dict | None:
        """
        解密加密事件

        Args:
            event_content: m.room.encrypted 事件的 content
            sender: 发送者 ID
            room_id: 房间 ID

        Returns:
            解密后的事件内容，或 None
        """
        if not self._olm or not self._initialized:
            logger.warning("E2EE 未初始化，无法解密")
            return None
        if not isinstance(event_content, dict):
            return None

        algorithm = event_content.get("algorithm")

        if algorithm == MEGOLM_ALGO:
            session_id = event_content.get("session_id")
            ciphertext = event_content.get("ciphertext")
            sender_key = event_content.get("sender_key")
            masked_session_id = (session_id or "")[:8]

            if (
                not isinstance(session_id, str)
                or not session_id
                or not isinstance(ciphertext, str)
                or not ciphertext
            ):
                logger.warning("缺少 session_id 或 ciphertext")
                return None

            decrypted = self._olm.decrypt_megolm(session_id, ciphertext)
            if decrypted and await self._validate_incoming_megolm_plaintext(
                decrypted,
                sender=sender,
                room_id=room_id,
                session_id=session_id,
                ciphertext=ciphertext,
                event_id=event_id,
            ):
                logger.debug(f"成功解密 Megolm 消息 (session: {masked_session_id}...)")
                return decrypted
            if decrypted:
                logger.warning(
                    "Discarded Megolm plaintext with invalid room/sender binding"
                )
                return None

            # 解密失败，尝试请求密钥
            logger.info(f"尝试请求房间密钥：session={masked_session_id}...")

            # 1. 仅在本账户缺失密钥时尝试从服务器备份恢复
            if self._key_backup and self._key_backup.should_restore_for_session(
                session_id=session_id
            ):
                await self._key_backup.restore_room_keys_if_needed(
                    session_id=session_id,
                    reason="decrypt_failed",
                )
                # 再次尝试解密
                decrypted = self._olm.decrypt_megolm(session_id, ciphertext)
                if decrypted and await self._validate_incoming_megolm_plaintext(
                    decrypted,
                    sender=sender,
                    room_id=room_id,
                    session_id=session_id,
                    ciphertext=ciphertext,
                    event_id=event_id,
                ):
                    logger.info(f"从备份恢复后成功解密：{masked_session_id}...")
                    return decrypted
                if decrypted:
                    return None

            # 2. 发送 m.room_key_request
            await self._request_room_key(room_id, session_id, sender_key)

            return None

        if algorithm == OLM_ALGO:
            # Olm 消息解密
            sender_key = event_content.get("sender_key")
            ciphertext_data = event_content.get("ciphertext", {})
            if not isinstance(ciphertext_data, dict):
                logger.warning("Olm ciphertext is not an object")
                return None

            # Debug log
            masked_sender_key = (sender_key or "")[:8]
            logger.debug(
                f"尝试解密 Olm 消息：algorithm={algorithm} sender_key={masked_sender_key}..."
            )

            # 找到发给本设备的密文
            my_key = self._olm.curve25519_key
            if my_key not in ciphertext_data:
                target_keys = list(ciphertext_data.keys())
                masked_my_key = (my_key or "")[:16]
                masked_target_keys = [((k or "")[:16] + "...") for k in target_keys]
                logger.debug(
                    f"消息不是发给本设备的：本设备密钥={masked_my_key}... "
                    f"目标密钥={masked_target_keys}"
                )
                return None

            my_ciphertext = ciphertext_data.get(my_key)
            if not isinstance(my_ciphertext, dict):
                logger.warning(
                    f"Olm ciphertext for this device is not a dictionary: {type(my_ciphertext)}"
                )
                return None
            message_type = my_ciphertext.get("type")
            body = my_ciphertext.get("body")

            # 基本校验
            if (
                not isinstance(sender_key, str)
                or not sender_key
                or type(message_type) is not int
                or message_type not in (0, 1)
                or not isinstance(body, str)
                or not body
            ):
                logger.warning("Olm 密文缺少必要字段")
                return None

            try:
                plaintext = self._olm.decrypt_olm_message(
                    sender_key, message_type, body
                )

                logger.info(
                    f"Olm 解密成功，明文长度：{len(plaintext) if plaintext else 0}"
                )
                logger.debug(f"Olm 解密明文类型：{type(plaintext)}")

                # 解析 JSON
                if isinstance(plaintext, bytes):
                    plaintext = plaintext.decode("utf-8")

                decrypted = json.loads(plaintext)
                if not await self._validate_incoming_olm_plaintext(
                    decrypted,
                    sender,
                    sender_key,
                ):
                    logger.warning(
                        "Discarded an Olm event with invalid plaintext binding"
                    )
                    return None
                inner_type = decrypted.get("type")
                logger.info(f"Olm 解密后事件类型：{inner_type}")

                return decrypted
            except json.JSONDecodeError as je:
                logger.error(f"Olm 解密后 JSON 解析失败：{je}")
                logger.error(
                    f"明文内容（前 200 字符）：{str(plaintext)[:200] if plaintext else 'None'}"
                )
                return None
            except Exception as e:
                logger.error(f"Olm 解密失败：{e}")

                # 对于任何 Olm 解密失败，都尝试请求新会话
                # 包括：未知一次性密钥、没有可用会话等情况
                if sender:
                    await self._request_new_session(sender_key, sender)
                else:
                    logger.warning("Olm 解密失败但缺少 sender_user_id，跳过请求新会话")

                return None

        logger.warning(f"不支持的加密算法：{algorithm}")
        return None

    async def _validate_incoming_megolm_plaintext(
        self,
        plaintext: object,
        *,
        sender: str | None,
        room_id: str,
        session_id: str,
        ciphertext: str,
        event_id: str | None,
    ) -> bool:
        """Bind Megolm plaintext to its room, sender, session, and event index."""
        if not isinstance(plaintext, dict) or not isinstance(sender, str) or not sender:
            return False
        message_index = plaintext.pop(MEGOLM_MESSAGE_INDEX_FIELD, None)
        if plaintext.get("room_id") != room_id:
            return False
        if not isinstance(plaintext.get("type"), str) or not plaintext.get("type"):
            return False
        if not isinstance(plaintext.get("content"), dict):
            return False

        get_metadata = getattr(self._store, "get_megolm_inbound_metadata", None)
        metadata = get_metadata(session_id) if callable(get_metadata) else None
        if not isinstance(metadata, dict) or metadata.get("room_id") != room_id:
            return False
        bound_sender = metadata.get("sender_user_id")
        if isinstance(bound_sender, str) and bound_sender:
            if bound_sender != sender:
                return False
        else:
            sender_curve = metadata.get("sender_key")
            claimed_keys = metadata.get("sender_claimed_keys")
            sender_ed25519 = (
                claimed_keys.get("ed25519") if isinstance(claimed_keys, dict) else None
            )
            if not isinstance(sender_curve, str) or not isinstance(
                sender_ed25519,
                str,
            ):
                return False

            candidates = {}
            if self._store:
                get_all = getattr(self._store, "get_all_device_keys", None)
                if callable(get_all):
                    all_keys = get_all()
                    if isinstance(all_keys, dict):
                        candidates = all_keys.get(sender) or {}
            matching = self._find_validated_sender_device(
                sender,
                sender_curve,
                sender_ed25519,
                candidates,
            )
            if not matching:
                try:
                    response = await self.client.query_keys({sender: []})
                except Exception:
                    return False
                candidates = (response.get("device_keys") or {}).get(sender) or {}
                matching = self._find_validated_sender_device(
                    sender,
                    sender_curve,
                    sender_ed25519,
                    candidates,
                )
                if not matching:
                    return False

            bind_sender = getattr(
                self._store,
                "bind_megolm_inbound_sender_user",
                None,
            )
            if callable(bind_sender) and not bind_sender(session_id, sender):
                return False

        if message_index is None:
            # Compatibility with test/custom Olm implementations which do not
            # expose the vodozemac message index. Production always does.
            return True
        check_replay = getattr(
            self._store,
            "check_and_record_megolm_message_index",
            None,
        )
        if not callable(check_replay):
            return False
        identifier = (
            event_id
            if isinstance(event_id, str) and event_id
            else hashlib.sha256(ciphertext.encode("utf-8")).hexdigest()
        )
        return bool(check_replay(session_id, message_index, identifier))

    async def _validate_incoming_olm_plaintext(
        self,
        plaintext: object,
        event_sender: str | None,
        sender_curve25519_key: str,
    ) -> bool:
        """Apply Matrix v1.19/MSC4147 mandatory Olm plaintext checks."""
        if not isinstance(plaintext, dict) or not isinstance(event_sender, str):
            return False
        if plaintext.get("sender") != event_sender:
            return False
        if plaintext.get("recipient") != self.user_id:
            return False
        recipient_keys = plaintext.get("recipient_keys")
        if not isinstance(recipient_keys, dict) or recipient_keys.get("ed25519") != str(
            self._olm.ed25519_key
        ):
            return False
        sender_claimed_keys = plaintext.get("keys")
        if not isinstance(sender_claimed_keys, dict):
            return False
        claimed_ed25519 = sender_claimed_keys.get("ed25519")
        if not isinstance(claimed_ed25519, str) or not claimed_ed25519:
            return False
        if not isinstance(plaintext.get("type"), str) or not plaintext.get("type"):
            return False
        if not isinstance(plaintext.get("content"), dict):
            return False

        sender_device_keys = plaintext.get("sender_device_keys")
        if sender_device_keys is not None:
            if not isinstance(sender_device_keys, dict):
                return False
            device_id = sender_device_keys.get("device_id")
            if not isinstance(device_id, str) or not device_id:
                return False
            keys = sender_device_keys.get("keys")
            if not isinstance(keys, dict):
                return False
            if sender_device_keys.get("user_id") != event_sender:
                return False
            if keys.get(f"curve25519:{device_id}") != sender_curve25519_key:
                return False
            if keys.get(f"ed25519:{device_id}") != claimed_ed25519:
                return False
            if not self._olm.verify_device_keys(
                event_sender,
                device_id,
                sender_device_keys,
            ):
                return False
            if self._store:
                self._store.save_device_keys(
                    event_sender,
                    device_id,
                    sender_device_keys,
                )
            mark_succeeded = getattr(self, "_mark_olm_send_succeeded", None)
            if callable(mark_succeeded):
                mark_succeeded(event_sender, device_id)
            return True

        # Older senders may omit MSC4147 sender_device_keys. Resolve the exact
        # Curve25519 + Ed25519 pair from a signed /keys/query device object.
        candidates: dict = {}
        if self._store:
            get_all = getattr(self._store, "get_all_device_keys", None)
            if callable(get_all):
                all_keys = get_all()
                if isinstance(all_keys, dict):
                    candidates = all_keys.get(event_sender) or {}

        matching = self._find_validated_sender_device(
            event_sender,
            sender_curve25519_key,
            claimed_ed25519,
            candidates,
        )
        if matching:
            mark_succeeded = getattr(self, "_mark_olm_send_succeeded", None)
            if callable(mark_succeeded):
                mark_succeeded(event_sender, matching[0])
            return True
        try:
            response = await self.client.query_keys({event_sender: []})
        except Exception as e:
            logger.warning(f"Unable to validate Olm sender device keys: {e}")
            return False
        candidates = (response.get("device_keys") or {}).get(event_sender) or {}
        matching = self._find_validated_sender_device(
            event_sender,
            sender_curve25519_key,
            claimed_ed25519,
            candidates,
        )
        if not matching:
            return False
        device_id, device_info = matching
        if self._store:
            self._store.save_device_keys(event_sender, device_id, device_info)
        mark_succeeded = getattr(self, "_mark_olm_send_succeeded", None)
        if callable(mark_succeeded):
            mark_succeeded(event_sender, device_id)
        return True

    def _find_validated_sender_device(
        self,
        user_id: str,
        curve25519_key: str,
        ed25519_key: str,
        candidates: object,
    ) -> tuple[str, dict] | None:
        if not isinstance(candidates, dict):
            return None
        for device_id, device_info in candidates.items():
            if not isinstance(device_id, str) or not self._olm.verify_device_keys(
                user_id,
                device_id,
                device_info,
            ):
                continue
            keys = device_info.get("keys", {})
            if (
                keys.get(f"curve25519:{device_id}") == curve25519_key
                and keys.get(f"ed25519:{device_id}") == ed25519_key
            ):
                return device_id, device_info
        return None

    async def handle_room_key(
        self,
        event: dict,
        sender_key: str,
        *,
        sender_claimed_keys: dict[str, str] | None = None,
        sender_user_id: str | None = None,
        forwarded: bool = False,
    ):
        """
        处理 m.room_key 事件 (接收 Megolm 会话密钥)

        Args:
            event: 解密后的 m.room_key 事件内容
            sender_key: 发送者的 curve25519 密钥
            sender_claimed_keys: Olm 载荷中发送设备声明的签名密钥
            sender_user_id: Sender user ID authenticated by the Olm plaintext
            forwarded: Whether the decrypted event was m.forwarded_room_key.
        """
        if not self._olm or not self._initialized:
            return

        if not isinstance(event, dict):
            return

        room_id = event.get("room_id")
        session_id = event.get("session_id")
        session_key = event.get("session_key")
        algorithm = event.get("algorithm")

        if algorithm != MEGOLM_ALGO:
            logger.warning(f"不支持的密钥算法：{algorithm}")
            return

        if not all(
            isinstance(value, str) and value
            for value in (room_id, session_id, session_key, sender_key)
        ):
            logger.warning("m.room_key 事件缺少必要字段")
            return

        withheld = None
        if forwarded:
            forwarded_chain = event.get("forwarding_curve25519_key_chain")
            original_sender_key = event.get("sender_key")
            forwarded_ed25519 = event.get("sender_claimed_ed25519_key")
            if (
                sender_user_id != self.user_id
                or not isinstance(forwarded_chain, list)
                or not all(isinstance(key, str) and key for key in forwarded_chain)
                or not isinstance(original_sender_key, str)
                or not original_sender_key
                or not isinstance(forwarded_ed25519, str)
                or not forwarded_ed25519
            ):
                logger.warning("Rejected malformed or cross-user forwarded room key")
                return

            source = await self._find_device_by_sender_key(
                sender_key,
                sender_user_id,
            )
            if not source or source[0] != self.user_id:
                logger.warning("Rejected forwarded room key from an unknown device")
                return
            source_device = source[1]
            device_info = await self._get_validated_device_info(
                self.user_id,
                source_device,
            )
            if not device_info or not await self._is_own_device_trusted(
                source_device,
                device_info,
            ):
                logger.warning("Rejected forwarded room key from an unverified device")
                return

            raw_withheld = event.get("withheld")
            if raw_withheld is not None:
                if (
                    not isinstance(raw_withheld, dict)
                    or raw_withheld.get("code") not in VALID_WITHHELD_CODES
                    or raw_withheld.get("code") == WITHHELD_NO_OLM
                    or not isinstance(raw_withheld.get("reason"), str)
                ):
                    logger.warning("Rejected malformed forwarded-key withheld data")
                    return
                withheld = {
                    "code": raw_withheld["code"],
                    "reason": raw_withheld["reason"],
                }
        else:
            if not isinstance(sender_user_id, str) or not sender_user_id:
                logger.warning("Rejected room key without an authenticated sender")
                return
            forwarded_chain = []
            original_sender_key = sender_key
            forwarded_ed25519 = None

        claimed_keys = sender_claimed_keys
        if isinstance(forwarded_ed25519, str) and forwarded_ed25519:
            claimed_keys = {"ed25519": forwarded_ed25519}
        if not isinstance(claimed_keys, dict):
            claimed_keys = {}
        else:
            claimed_keys = {
                str(algorithm): key
                for algorithm, key in claimed_keys.items()
                if isinstance(key, str)
            }
        if not isinstance(claimed_keys.get("ed25519"), str) or not claimed_keys.get(
            "ed25519"
        ):
            logger.warning("Rejected room key without an authenticated Ed25519 key")
            return

        # Only a direct m.room_key can declare shareability. A forwarded key
        # lacks this authenticated assertion and is therefore conservative.
        shared_history = not forwarded and event.get("shared_history") is True
        stored_forwarding_chain = list(forwarded_chain)
        if (
            forwarded
            and isinstance(sender_key, str)
            and sender_key
            and (
                not stored_forwarding_chain or stored_forwarding_chain[-1] != sender_key
            )
        ):
            # The content omits its current Olm sender. Persist that device as
            # the newest hop so a subsequent forward retains full provenance.
            stored_forwarding_chain.append(sender_key)

        imported = self._olm.add_megolm_inbound_session(
            room_id,
            session_id,
            session_key,
            original_sender_key,
            claimed_keys,
            stored_forwarding_chain,
            shared_history,
            None if forwarded else sender_user_id,
            withheld if forwarded else {},
        )
        if imported is False:
            logger.warning(
                f"Failed to import the Megolm key for room {room_id}; "
                "keeping the room-key request pending"
            )
            return
        logger.info(f"收到房间 {room_id} 的 Megolm 密钥")

        # Matrix requires the requester to cancel the outstanding request once
        # any device supplies the session. This also prevents repeated replies.
        await self._cancel_room_key_request(room_id, session_id)

        # 自动备份新接收到的密钥
        if self._key_backup and self.enable_key_backup:
            try:
                await self._key_backup.upload_single_key(
                    room_id=room_id,
                    session_id=session_id,
                    session_key=session_key,
                    sender_key=original_sender_key,
                    sender_claimed_keys=claimed_keys,
                    forwarding_curve25519_key_chain=stored_forwarding_chain,
                    shared_history=shared_history,
                )
            except Exception as e:
                logger.warning(f"自动备份密钥失败：{e}")

    async def _find_device_by_sender_key(
        self, sender_key: str, sender_user_id: str | None = None
    ) -> tuple[str, str] | None:
        """
        通过 sender_key 查找对应的用户和设备

        首先检查本地缓存，如果找不到则尝试从服务器查询。

        Args:
            sender_key: 发送者的 curve25519 密钥
            sender_user_id: 可选的发送者用户 ID（如果已知）

        Returns:
            (user_id, device_id) 元组，或 None
        """
        # 1. 首先从本地缓存查找
        if self._store:
            device_keys = self._store.get_all_device_keys()
            for user_id, devices in device_keys.items():
                for device_id, keys in devices.items():
                    if sender_user_id and user_id != sender_user_id:
                        continue
                    if not self._olm.verify_device_keys(user_id, device_id, keys):
                        continue
                    device_curve_key = keys.get("keys", {}).get(
                        f"curve25519:{device_id}"
                    )
                    if device_curve_key == sender_key:
                        return (user_id, device_id)

        # 2. 如果本地没有，且知道发送者用户 ID，则从服务器查询
        if sender_user_id:
            try:
                logger.info(
                    f"本地缓存中未找到 sender_key，正在查询 {sender_user_id} 的设备..."
                )
                response = await self.client.query_keys({sender_user_id: []})
                user_devices = (response.get("device_keys") or {}).get(
                    sender_user_id
                ) or {}

                for device_id, device_info in user_devices.items():
                    if not self._olm.verify_device_keys(
                        sender_user_id,
                        device_id,
                        device_info,
                    ):
                        logger.warning(
                            "Ignoring device with an invalid self-signature while "
                            f"resolving sender key: {sender_user_id}/{device_id}"
                        )
                        continue
                    keys = device_info.get("keys", {})
                    curve_key = keys.get(f"curve25519:{device_id}")

                    # 缓存到本地
                    if self._store:
                        self._store.save_device_keys(
                            sender_user_id, device_id, device_info
                        )
                        logger.debug(f"缓存设备密钥：{sender_user_id}/{device_id}")

                    if curve_key == sender_key:
                        logger.info(
                            f"从服务器找到 sender_key 对应的设备：{sender_user_id}/{device_id}"
                        )
                        return (sender_user_id, device_id)

                logger.warning(
                    f"服务器返回的设备中没有匹配的 sender_key：{(sender_key or '')[:8]}..."
                )
            except Exception as e:
                logger.warning(f"从服务器查询设备密钥失败：{e}")

        return None
