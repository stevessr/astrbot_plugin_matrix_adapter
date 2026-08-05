"""Master-key signature payload construction."""

import copy

from astrbot.api import logger


class CrossSigningMasterSignPayloadMixin:
    """Build the signed master-key upload payload."""

    def _prepare_master_signature_payload(
        self,
        target_user_id: str,
        context,
    ):
        """Return ``None`` (no context), ``True`` (already signed), or the payload tuple."""
        if not context:
            return None
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
            logger.debug("[E2EE-CrossSign] master key 已存在当前设备签名，跳过重复上传")
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

        return master_key_to_upload, signing_key_id, master_pubkey_b64


__all__ = ["CrossSigningMasterSignPayloadMixin"]
