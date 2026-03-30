"""
E2EE Manager verification helpers.
"""

import time

from astrbot.api import logger

from ..constants import (
    M_KEY_VERIFICATION_REQUEST,
    M_QR_CODE_SCAN_V1_METHOD,
    M_QR_CODE_SHOW_V1_METHOD,
    M_RECIPROCATE_V1_METHOD,
    M_SAS_V1_METHOD,
    PREFIX_ED25519,
    SECRET_MEGOLM_BACKUP_V1,
)


class E2EEManagerVerificationMixin:
    @staticmethod
    def _extract_cross_signing_key_id(key_payload: dict | None) -> str | None:
        if not isinstance(key_payload, dict):
            return None
        keys = key_payload.get("keys")
        if not isinstance(keys, dict) or not keys:
            return None
        return next(iter(keys.keys()))

    def _classify_own_device_cross_signing_state(
        self, response: dict
    ) -> dict[str, dict[str, bool]]:
        device_keys = (response.get("device_keys") or {}).get(self.user_id) or {}
        self_signing_key_id = self._extract_cross_signing_key_id(
            (response.get("self_signing_keys") or {}).get(self.user_id)
        )
        master_key = (response.get("master_keys") or {}).get(self.user_id) or {}
        master_signatures = (master_key.get("signatures") or {}).get(
            self.user_id, {}
        ) or {}

        states: dict[str, dict[str, bool]] = {}
        for device_id, device_info in device_keys.items():
            signatures = (device_info.get("signatures") or {}).get(self.user_id, {})
            states[device_id] = {
                "owner_signed": bool(
                    self_signing_key_id and self_signing_key_id in signatures
                ),
                "master_signed": f"{PREFIX_ED25519}{device_id}" in master_signatures,
            }
        return states

    def _format_masked_device_ids(self, device_ids: list[str]) -> str:
        mask = getattr(self, "_mask_device_id", None)
        if callable(mask):
            return ", ".join(mask(device_id) for device_id in device_ids)
        return ", ".join(device_ids)

    def _log_manual_same_user_verification_required(
        self, device_ids: list[str], reason: str
    ) -> None:
        if not device_ids:
            return
        logger.info(f"{reason}：{self._format_masked_device_ids(device_ids)}")
        logger.info(
            "这些同账号设备需要在对应客户端本地完成“验证此设备 / Use another device”，"
            "或使用恢复密钥恢复；当前设备不再主动发起通用 device verification。"
        )

    async def _log_same_user_verification_gap(self, device_id: str) -> None:
        current_device_id = getattr(self, "device_id", "")
        if not device_id or device_id == current_device_id:
            return
        client = getattr(self, "client", None)
        if not client or not hasattr(client, "_request"):
            return
        try:
            response = await client._request(
                "POST",
                "/_matrix/client/v3/keys/query",
                {"device_keys": {self.user_id: []}},
            )
            state = self._classify_own_device_cross_signing_state(response).get(
                device_id, {}
            )
            if state.get("owner_signed") and not state.get("master_signed"):
                logger.debug(
                    "目标设备已被 owner-signed，但服务器上暂无对应 device->master 签名："
                    f"{self._format_masked_device_ids([device_id])}"
                )
        except Exception as e:
            logger.debug(f"查询同账号设备主密钥验证状态失败：{e}")

    async def _maybe_republish_current_device_keys_after_verification(
        self, verified_device_id: str
    ) -> None:
        current_device_id = getattr(self, "device_id", "")
        if (
            not verified_device_id
            or not current_device_id
            or verified_device_id == current_device_id
        ):
            return

        cross_signing = getattr(self, "_cross_signing", None)
        republish = getattr(cross_signing, "_republish_current_device_keys", None)
        if not callable(republish):
            return

        now = time.monotonic()
        last_ts = float(
            getattr(
                self,
                "_last_current_device_key_refresh_after_verification_ts",
                0.0,
            )
        )
        cooldown_sec = 60.0
        if now - last_ts < cooldown_sec:
            return

        self._last_current_device_key_refresh_after_verification_ts = now
        try:
            await republish()
        except Exception as e:
            logger.debug(f"验证后重发布当前设备 device_keys 失败：{e}")

    async def publish_trusted_device(self, user_id: str, device_id: str) -> bool:
        """Publish cross-signing trust for a same-account device."""
        if user_id != self.user_id:
            logger.debug("跳过发布设备信任：不是同账号设备")
            return False
        if not device_id:
            logger.debug("跳过发布设备信任：缺少 device_id")
            return False
        if not self._cross_signing:
            logger.debug("跳过发布设备信任：cross-signing 未初始化")
            return False
        if not self._cross_signing.self_signing_private_key:
            logger.debug(
                f"跳过发布设备信任：self-signing 私钥不可用 device={device_id}"
            )
            return False

        device_ok = await self._cross_signing.sign_device(device_id)
        if not device_ok:
            logger.warning(f"发布设备信任失败：{device_id}")
            return False

        master_ok = True
        sign_master = getattr(self._cross_signing, "sign_master_key_with_device", None)
        if callable(sign_master):
            master_ok = await sign_master(self.user_id)
            if not master_ok:
                logger.debug(
                    "发布 master key 设备签名未生效，但不影响同账号设备 owner-sign 状态："
                    f"{device_id}"
                )

        logger.info(f"已发布设备信任：{device_id}")
        await self._maybe_republish_current_device_keys_after_verification(device_id)
        if not master_ok:
            await self._log_same_user_verification_gap(device_id)
        return True

    async def handle_verification_event(
        self, event_type: str, sender: str, content: dict
    ) -> bool:
        """Handle verification events (m.key.verification.*)."""
        if self._verification:
            return await self._verification.handle_verification_event(
                event_type, sender, content
            )
        return False

    async def handle_in_room_verification_event(
        self,
        event_type: str,
        sender: str,
        content: dict,
        room_id: str,
        event_id: str,
    ) -> bool:
        """Handle in-room verification events."""
        if self._verification:
            return await self._verification.handle_in_room_verification_event(
                event_type, sender, content, room_id, event_id
            )
        return False

    async def request_missing_secrets_after_verification(self, user_id: str) -> None:
        """After same-user verification, request any missing bootstrap secrets once."""
        if user_id != self.user_id:
            return

        cross_signing = getattr(self, "_cross_signing", None)
        if (
            cross_signing
            and hasattr(cross_signing, "_query_server_cross_signing_state")
            and hasattr(cross_signing, "_request_missing_private_keys_from_devices")
        ):
            try:
                (
                    server_master,
                    server_self_signing,
                    server_user_signing,
                    _keys_need_regen,
                ) = await cross_signing._query_server_cross_signing_state()
                await cross_signing._request_missing_private_keys_from_devices(
                    server_master,
                    server_self_signing,
                    server_user_signing,
                )
            except Exception as e:
                logger.debug(f"验证后请求缺失交叉签名私钥失败：{e}")

        key_backup = getattr(self, "_key_backup", None)
        if not key_backup or not getattr(key_backup, "backup_version", None):
            return

        try:
            local_backup_key = getattr(key_backup, "recovery_key_bytes", None)
            if not local_backup_key and hasattr(key_backup, "load_extracted_key"):
                local_backup_key = key_backup.load_extracted_key()
            if local_backup_key:
                return

            request_id = await self.request_secret_from_devices(SECRET_MEGOLM_BACKUP_V1)
            if request_id:
                logger.info("[E2EE-Secrets] 验证完成后已请求备份密钥")
        except Exception as e:
            logger.debug(f"验证后请求缺失备份密钥失败：{e}")

    async def _verify_untrusted_own_devices(self):
        """Query own devices and report same-user sessions that still need local verification."""
        if not self._verification:
            return

        try:
            response = await self.client._request(
                "POST",
                "/_matrix/client/v3/keys/query",
                {"device_keys": {self.user_id: []}},
            )

            device_keys = (response.get("device_keys") or {}).get(self.user_id) or {}
            if not device_keys:
                logger.debug("未找到其他设备")
                return

            untrusted_devices = []
            owner_signed_but_not_master_verified = []
            device_states = self._classify_own_device_cross_signing_state(response)
            for device_id in device_keys.keys():
                if device_id == self.device_id:
                    continue
                state = device_states.get(device_id, {})
                if not state.get("owner_signed"):
                    untrusted_devices.append(device_id)
                elif not state.get("master_signed"):
                    owner_signed_but_not_master_verified.append(device_id)

            if not untrusted_devices and not owner_signed_but_not_master_verified:
                logger.info("所有其他设备已验证")
                return
            if untrusted_devices:
                self._log_manual_same_user_verification_required(
                    untrusted_devices,
                    "发现尚未被 owner-signed 的同账号设备",
                )
            if owner_signed_but_not_master_verified:
                self._log_manual_same_user_verification_required(
                    owner_signed_but_not_master_verified,
                    "同账号设备已 owner-signed，但对端会话尚未完成本机主密钥验证",
                )

        except Exception as e:
            logger.warning(f"查询设备验证状态失败：{e}")

    async def _initiate_verification_for_device(
        self, target_device_id: str, methods: list[str] | None = None
    ):
        """Initiate SAS verification for device."""
        if not self._verification:
            return

        import secrets

        txn_id = secrets.token_hex(16)
        request_methods = methods or [
            M_SAS_V1_METHOD,
            M_QR_CODE_SCAN_V1_METHOD,
            M_QR_CODE_SHOW_V1_METHOD,
            M_RECIPROCATE_V1_METHOD,
        ]

        request_content = {
            "from_device": self.device_id,
            "methods": request_methods,
            "timestamp": int(__import__("time").time() * 1000),
            "transaction_id": txn_id,
        }

        await self.client.send_to_device(
            M_KEY_VERIFICATION_REQUEST,
            {self.user_id: {target_device_id: request_content}},
            txn_id,
        )

        if self._verification:
            self._verification.initiate_verification(
                txn_id, self.user_id, target_device_id
            )

        logger.info(
            f"已向设备 {target_device_id} 发起验证请求 (txn={(txn_id or '')[:8]}...)"
        )
