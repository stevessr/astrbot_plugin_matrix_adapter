"""Master-key device-signing operations for cross-signing."""

import copy

from astrbot.api import logger

from .....client.http_client import MatrixAPIError


class CrossSigningMasterSignCoreMixin:
    """为当前账号 master key 上传当前设备签名。"""

    async def sign_master_key_with_device(self, user_id: str | None = None) -> bool:
        target_user_id = user_id or self.user_id
        if target_user_id != self.user_id:
            logger.debug("[E2EE-CrossSign] 仅支持为当前账号的 master key 添加设备签名")
            return False
        if not self.olm or not self._master_key:
            logger.debug(
                "[E2EE-CrossSign] master key 或 olm 账户不可用，跳过设备签名 master key"
            )
            return False

        try:
            context = await self._load_current_master_signing_context(target_user_id)
            if not context:
                return False
            (
                master_key,
                keys,
                (
                    local_ed25519,
                    local_curve25519,
                    server_ed25519,
                    server_curve25519,
                ),
            ) = context

            master_key_id, _master_key_value = next(iter(keys.items()))
            master_pubkey_b64 = _master_key_value

            signing_key_id = self.device_key_id
            existing_signatures = (master_key.get("signatures") or {}).get(
                target_user_id, {}
            ) or {}
            if signing_key_id in existing_signatures:
                logger.debug(
                    "[E2EE-CrossSign] master key 已存在当前设备签名，跳过重复上传"
                )
                return True

            signature = self._sign_device_object(master_key)
            logger.debug(
                "[E2EE-CrossSign] 签名诊断信息：\n"
                f"  local_device_ed25519={local_ed25519}\n"
                f"  server_device_ed25519={server_ed25519}\n"
                f"  signing_key_id={signing_key_id}\n"
                f"  device_id(olm)={self.olm.device_id}\n"
                f"  device_id(self)={self.device_id}\n"
                f"  master_key_id={master_key_id}\n"
                f"  master_pubkey_b64={master_pubkey_b64}\n"
                f"  signature={signature}"
            )

            master_key_to_upload = copy.deepcopy(master_key)
            master_key_to_upload.pop("unsigned", None)
            # 仅包含本次设备签名，不携带旧的签名。
            # 服务器会重新验证上传载荷中的所有签名，
            # 如果携带了旧的（已失效的）签名会导致 M_INVALID_SIGNATURE。
            master_key_to_upload["signatures"] = {
                target_user_id: {signing_key_id: signature}
            }

            # 验证：上传载荷剥离 signatures/unsigned 后的规范化 JSON
            # 应该与签名时使用的规范化 JSON 完全一致
            verify_payload = copy.deepcopy(master_key_to_upload)
            verify_payload.pop("signatures", None)
            verify_payload.pop("unsigned", None)
            verify_canonical = self._canonical(verify_payload)
            logger.debug(
                f"[E2EE-CrossSign] 上传载荷验证 canonical JSON：{verify_canonical}"
            )

            logger.debug(
                "[E2EE-CrossSign] 上传 master key 设备签名："
                f"master={master_key_id} signer={signing_key_id}"
            )

            ok = await self._upload_signature_and_confirm(
                {target_user_id: {master_pubkey_b64: master_key_to_upload}},
                lambda: self._verify_uploaded_master_signature(
                    target_user_id, signing_key_id
                ),
                "master key 设备签名 ",
            )
            if not ok:
                return False

            logger.debug("[E2EE-CrossSign] 已为 master key 添加设备签名")
            return True
        except MatrixAPIError as e:
            logger.warning(f"[E2EE-CrossSign] master key 设备签名失败：{e}")
            return False
        except Exception as e:
            logger.warning(f"[E2EE-CrossSign] master key 设备签名异常：{e}")
            return False

    async def _verify_uploaded_master_signature(
        self, target_user_id: str, signing_key_id: str
    ) -> bool:
        refreshed = await self.client.query_keys({target_user_id: []})
        refreshed_master_key = (refreshed.get("master_keys") or {}).get(
            target_user_id
        ) or {}
        refreshed_signatures = (refreshed_master_key.get("signatures") or {}).get(
            target_user_id, {}
        )
        return signing_key_id in refreshed_signatures
