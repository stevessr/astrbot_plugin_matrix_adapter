from astrbot.api import logger


class CryptoStorePersistLifecycleMixin:
    def _check_device_id_change(self) -> bool:
        """
        检查 device_id 是否发生变化

        Returns:
            True 如果 device_id 变化了（需要清除旧数据）
        """
        stored = self._read_record(self._RECORD_STORED_DEVICE_ID)
        if not isinstance(stored, dict):
            # 第一次运行，保存当前 device_id
            self._save_device_id()
            return False

        try:
            stored_device_id = stored.get("device_id")

            if stored_device_id != self.device_id:
                logger.warning(
                    "检测到 device_id 变化："
                    f"{self._redact_device_id(stored_device_id)} -> "
                    f"{self._redact_device_id(self.device_id)}"
                )
                logger.warning("将清除旧的 Olm 账户和会话数据，创建新的密钥")
                # 清除旧数据
                self._clear_olm_data()
                # 保存新的 device_id
                self._save_device_id()
                return True

            return False
        except Exception as e:
            logger.warning(f"检查 device_id 变化失败：{e}")
            self._save_device_id()
            return False

    def _save_device_id(self):
        """保存当前 device_id 到文件"""
        self._save_record(self._RECORD_STORED_DEVICE_ID, {"device_id": self.device_id})

    def _clear_olm_data(self):
        """清除 Olm 账户和会话数据（当 device_id 变化时）"""
        try:
            # 只清除 Olm 相关数据，保留 Megolm 会话（可以继续解密历史消息）
            self._delete_record(self._RECORD_ACCOUNT)
            self._account_pickle = None
            logger.info("已删除旧的 Olm 账户")

            self._delete_record(self._RECORD_SESSIONS)
            self._olm_sessions = {}
            logger.info("已删除旧的 Olm 会话")

            # 注意：不删除 Megolm 入站会话，因为它们仍然可以解密历史消息
            # 但需要删除出站会话，因为需要为新设备创建新的
            self._delete_record(self._RECORD_MEGOLM_OUTBOUND)
            self._megolm_outbound = {}
            self._delete_record(self._RECORD_MEGOLM_OUTBOUND_META)
            self._megolm_outbound_meta = {}
            logger.info("已删除旧的 Megolm 出站会话")

        except Exception as e:
            logger.error(f"清除旧数据失败：{e}")

    @property
    def device_id_changed(self) -> bool:
        """返回 device_id 是否发生了变化"""
        return self._device_id_changed
