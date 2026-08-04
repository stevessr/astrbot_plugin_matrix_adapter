"""Vodozemac SAS shared-secret calculation."""

from astrbot.api import logger

from .....constants import INFO_PREFIX_SAS
from ...constants import SAS_EMOJIS, Curve25519PublicKey


class SASVerificationFlowKeySasMixin:
    """Compute the SAS bytes via vodozemac diffie-hellman."""

    async def _compute_vodozemac_sas(
        self,
        session: dict,
        *,
        sas,
        sender: str,
        their_device: str,
        their_key: str,
        transaction_id: str,
    ) -> bool:
        """Compute and store the SAS; return False to fall back."""
        try:
            # 使用 vodozemac 计算共享密钥
            # 构造 SAS info 字符串
            their_user = sender

            # 确定 Initiator 和 Recipient
            # 发送 m.key.verification.start 的是 Initiator
            our_key = session.get("our_public_key")
            if session.get("we_are_initiator"):
                init_user, init_dev, init_key = (
                    self.user_id,
                    self.device_id,
                    our_key,
                )
                rec_user, rec_dev, rec_key = their_user, their_device, their_key
            else:
                init_user, init_dev, init_key = their_user, their_device, their_key
                rec_user, rec_dev, rec_key = self.user_id, self.device_id, our_key

            info = (
                f"{INFO_PREFIX_SAS}"
                f"{init_user}|{init_dev}|{init_key}|"
                f"{rec_user}|{rec_dev}|{rec_key}|"
                f"{transaction_id}"
            )

            # 使用 vodozemac 的 diffie_hellman 方法完成密钥交换
            # 这会返回一个 EstablishedSas 对象
            their_public_key = Curve25519PublicKey.from_base64(their_key)
            established_sas = sas.diffie_hellman(their_public_key)

            # 保存 established_sas 用于后续 MAC 计算
            session["established_sas"] = established_sas

            # 使用 established_sas.bytes(info) 获取 SAS 字节对象
            sas_bytes_obj = established_sas.bytes(info)

            # vodozemac SasBytes 对象有 emoji_indices (bytes) 和 decimals (tuple) 属性
            # emoji_indices 是 7 个字节，每个字节是 0-63 的索引
            emoji_indices = sas_bytes_obj.emoji_indices
            emojis = [SAS_EMOJIS[idx] for idx in emoji_indices]

            # decimals 是一个包含 3 个数字的元组
            decimals_tuple = sas_bytes_obj.decimals
            if len(decimals_tuple) >= 3:
                decimals = (
                    f"{decimals_tuple[0]} {decimals_tuple[1]} {decimals_tuple[2]}"
                )
            else:
                decimals = " ".join(map(str, decimals_tuple))

            session["sas_bytes"] = emoji_indices  # 保存原始字节用于回退
            session["sas_emojis"] = emojis
            session["sas_decimals"] = decimals

            emoji_str = " ".join(e[0] for e in emojis)
            logger.info(f"[E2EE-Verify] SAS 验证码：{emoji_str} | 数字：{decimals}")
            return True
        except Exception as e:
            logger.error(f"[E2EE-Verify] 计算 SAS 失败：{e}")
            return False
