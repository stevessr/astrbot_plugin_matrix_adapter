class CryptoStoreAccountSessionsMixin:
    def get_account_pickle(self) -> str | None:
        """获取 Olm 账户的 pickle"""
        return self._account_pickle

    def save_account_pickle(self, pickle: str):
        """保存 Olm 账户的 pickle"""
        self._account_pickle = pickle
        self._save_record(self._RECORD_ACCOUNT, {"pickle": pickle})

    def clear_account_pickle(self):
        """删除持久化的 Olm 账户 pickle。"""
        self._account_pickle = None
        self._delete_record(self._RECORD_ACCOUNT)
