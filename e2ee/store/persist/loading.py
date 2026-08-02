from astrbot.api import logger


class CryptoStorePersistLoadingMixin:
    def _load_all(self):
        """从磁盘加载所有存储数据"""
        try:
            account_data = self._read_record(self._RECORD_ACCOUNT)
            if isinstance(account_data, dict):
                pickle = account_data.get("pickle")
                if isinstance(pickle, str):
                    self._account_pickle = pickle
                logger.debug("加载了 Olm 账户")

            sessions_data = self._read_record(self._RECORD_SESSIONS)
            if isinstance(sessions_data, dict):
                self._olm_sessions = sessions_data
                logger.debug(f"加载了 {len(self._olm_sessions)} 个 Olm 会话")

            megolm_inbound_data = self._read_record(self._RECORD_MEGOLM_INBOUND)
            if isinstance(megolm_inbound_data, dict):
                self._megolm_inbound = megolm_inbound_data
                logger.debug(f"加载了 {len(self._megolm_inbound)} 个 Megolm 入站会话")

            megolm_inbound_meta = self._read_record(self._RECORD_MEGOLM_INBOUND_META)
            if isinstance(megolm_inbound_meta, dict):
                self._megolm_inbound_meta = megolm_inbound_meta

            megolm_replay = self._read_record(self._RECORD_MEGOLM_REPLAY)
            if isinstance(megolm_replay, dict):
                self._megolm_replay = megolm_replay

            megolm_outbound_data = self._read_record(self._RECORD_MEGOLM_OUTBOUND)
            if isinstance(megolm_outbound_data, dict):
                self._megolm_outbound = megolm_outbound_data
                logger.debug(f"加载了 {len(self._megolm_outbound)} 个 Megolm 出站会话")

            megolm_outbound_meta = self._read_record(self._RECORD_MEGOLM_OUTBOUND_META)
            if isinstance(megolm_outbound_meta, dict):
                self._megolm_outbound_meta = megolm_outbound_meta

            device_keys_data = self._read_record(self._RECORD_DEVICE_KEYS)
            if isinstance(device_keys_data, dict):
                self._device_keys = device_keys_data
                logger.debug(f"加载了 {len(self._device_keys)} 个用户的设备密钥")

        except Exception as e:
            logger.error(f"加载加密存储失败：{e}")
