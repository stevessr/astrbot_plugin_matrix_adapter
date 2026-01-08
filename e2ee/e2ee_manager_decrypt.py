import json

from astrbot.api import logger

from ..constants import MEGOLM_ALGO, OLM_ALGO


class E2EEManagerDecryptMixin:
    async def decrypt_event(
        self, event_content: dict, sender: str, room_id: str
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

        algorithm = event_content.get("algorithm")

        if algorithm == MEGOLM_ALGO:
            session_id = event_content.get("session_id")
            ciphertext = event_content.get("ciphertext")
            sender_key = event_content.get("sender_key")

            if not session_id or not ciphertext:
                logger.warning("缺少 session_id 或 ciphertext")
                return None

            decrypted = self._olm.decrypt_megolm(session_id, ciphertext)
            if decrypted:
                logger.debug(f"成功解密 Megolm 消息 (session: {session_id[:8]}...)")
                return decrypted

            # 解密失败，尝试请求密钥
            logger.info(f"尝试请求房间密钥：session={session_id[:8]}...")

            # 1. 尝试从服务器备份恢复
            if self._key_backup and self._key_backup._backup_version:
                await self._key_backup.restore_room_keys()
                # 再次尝试解密
                decrypted = self._olm.decrypt_megolm(session_id, ciphertext)
                if decrypted:
                    logger.info(f"从备份恢复后成功解密：{session_id[:8]}...")
                    return decrypted

            # 2. 发送 m.room_key_request
            await self._request_room_key(room_id, session_id, sender_key, sender)

            return None

        if algorithm == OLM_ALGO:
            # Olm 消息解密
            sender_key = event_content.get("sender_key")
            ciphertext_data = event_content.get("ciphertext", {})

            # Debug log
            logger.debug(
                f"尝试解密 Olm 消息：algorithm={algorithm} sender_key={sender_key[:8]}..."
            )

            # 找到发给本设备的密文
            my_key = self._olm.curve25519_key
            if my_key not in ciphertext_data:
                logger.warning("消息不是发给本设备的")
                return None

            my_ciphertext = ciphertext_data[my_key]
            message_type = my_ciphertext.get("type")
            body = my_ciphertext.get("body")

            # 基本校验
            if not sender_key or message_type is None or body is None:
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
                await self._request_new_session(sender_key, sender)

                return None

        logger.warning(f"不支持的加密算法：{algorithm}")
        return None

    async def handle_room_key(self, event: dict, sender_key: str):
        """
        处理 m.room_key 事件 (接收 Megolm 会话密钥)

        Args:
            event: 解密后的 m.room_key 事件内容
            sender_key: 发送者的 curve25519 密钥
        """
        if not self._olm or not self._initialized:
            return

        room_id = event.get("room_id")
        session_id = event.get("session_id")
        session_key = event.get("session_key")
        algorithm = event.get("algorithm")

        if algorithm != MEGOLM_ALGO:
            logger.warning(f"不支持的密钥算法：{algorithm}")
            return

        if not all([room_id, session_id, session_key]):
            logger.warning("m.room_key 事件缺少必要字段")
            return

        self._olm.add_megolm_inbound_session(
            room_id, session_id, session_key, sender_key
        )
        logger.info(f"收到房间 {room_id} 的 Megolm 密钥")

        # 自动备份新接收到的密钥
        if self._key_backup and self.enable_key_backup:
            try:
                await self._key_backup.upload_single_key(
                    room_id=room_id,
                    session_id=session_id,
                    session_key=session_key,
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
        device_keys = self._store.get_all_device_keys()
        for user_id, devices in device_keys.items():
            for device_id, keys in devices.items():
                device_curve_key = keys.get("keys", {}).get(f"curve25519:{device_id}")
                if device_curve_key == sender_key:
                    return (user_id, device_id)

        # 2. 如果本地没有，且知道发送者用户 ID，则从服务器查询
        if sender_user_id:
            try:
                logger.info(
                    f"本地缓存中未找到 sender_key，正在查询 {sender_user_id} 的设备..."
                )
                response = await self.client.query_keys({sender_user_id: []})
                user_devices = response.get("device_keys", {}).get(sender_user_id, {})

                for device_id, device_info in user_devices.items():
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
                    f"服务器返回的设备中没有匹配的 sender_key：{sender_key[:8]}..."
                )
            except Exception as e:
                logger.warning(f"从服务器查询设备密钥失败：{e}")

        return None
