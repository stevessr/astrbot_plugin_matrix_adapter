"""Device-signing operations for cross-signing."""

import copy

from astrbot.api import logger

from .....client.http_client import MatrixAPIError


class CrossSigningDeviceSignCoreMixin:
    """为设备上传 self-signing 签名。"""

    async def sign_device(self, device_id: str) -> bool:
        if not self._self_signing_priv or not self._self_signing_key:
            logger.debug("[E2EE-CrossSign] self-signing key 不可用，跳过设备签名")
            return False
        try:
            signing_key_id = f"ed25519:{self._self_signing_key}"
            repaired_current_device = False
            while True:
                response = await self.client.query_keys({self.user_id: [device_id]})
                device_keys = (
                    (response.get("device_keys") or {})
                    .get(self.user_id, {})
                    .get(device_id)
                )
                if not device_keys:
                    if (
                        device_id == self.device_id
                        and not repaired_current_device
                        and await self._repair_current_device_keys_once()
                    ):
                        repaired_current_device = True
                        continue
                    logger.debug("[E2EE-CrossSign] 未找到设备密钥，无法签名")
                    return False

                if device_id != self.device_id:
                    break

                (
                    matches,
                    local_ed25519,
                    local_curve25519,
                    server_ed25519,
                    server_curve25519,
                ) = self._current_device_matches_server(device_keys)
                if matches:
                    break

                if (
                    not repaired_current_device
                    and await self._repair_current_device_keys_once()
                ):
                    repaired_current_device = True
                    continue

                logger.warning(
                    "[E2EE-CrossSign] 当前设备身份密钥与服务器不一致，跳过设备签名"
                )
                logger.debug(
                    "[E2EE-CrossSign] 设备签名失败细节："
                    f"device_id={device_id} "
                    f"local_ed25519={local_ed25519} server_ed25519={server_ed25519} "
                    f"local_curve25519={local_curve25519} server_curve25519={server_curve25519}"
                )
                return False

            existing_signatures = (device_keys.get("signatures") or {}).get(
                self.user_id, {}
            ) or {}
            if signing_key_id in existing_signatures:
                logger.debug(
                    f"[E2EE-CrossSign] 设备已存在 owner-sign，跳过重复上传：{device_id}"
                )
                return True

            device_keys_to_upload = copy.deepcopy(device_keys)
            device_keys_to_upload.pop("unsigned", None)
            sig = self._sign(self._self_signing_priv, device_keys_to_upload)
            # 仅包含本次自签名密钥的签名，不携带旧的签名，
            # 避免服务器重新验证旧签名导致 M_INVALID_SIGNATURE。
            device_keys_to_upload["signatures"] = {self.user_id: {signing_key_id: sig}}

            upload_payload = {self.user_id: {device_id: device_keys_to_upload}}
            ok = await self._upload_signature_and_confirm(
                upload_payload,
                lambda: self._verify_uploaded_device_signature(
                    device_id, signing_key_id
                ),
                f"设备签名 device={device_id} ",
            )
            if not ok:
                return False

            if device_id == self.device_id:
                await self._republish_current_device_keys()

            logger.debug(f"[E2EE-CrossSign] 已签名设备：{device_id}")
            return True
        except MatrixAPIError as e:
            logger.warning(f"[E2EE-CrossSign] 设备签名失败：{e}")
            return False
        except Exception as e:
            logger.warning(f"[E2EE-CrossSign] 设备签名异常：{e}")
            return False
