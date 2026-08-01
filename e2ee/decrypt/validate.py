import hashlib

from astrbot.api import logger

from ..constants import MEGOLM_MESSAGE_INDEX_FIELD


class E2EEManagerDecryptValidateMixin:
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
