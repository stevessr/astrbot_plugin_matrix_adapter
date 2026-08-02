class CryptoStoreOlmSessionsMixin:
    def get_olm_sessions(self, sender_key: str) -> list[str]:
        """获取与特定发送者的 Olm 会话列表"""
        return self._olm_sessions.get(sender_key, [])

    def add_olm_session(self, sender_key: str, session_pickle: str):
        """添加 Olm 会话"""
        if sender_key not in self._olm_sessions:
            self._olm_sessions[sender_key] = []
        self._olm_sessions[sender_key].append(session_pickle)
        self._save_record(self._RECORD_SESSIONS, self._olm_sessions)

    def update_olm_session(self, sender_key: str, index: int, session_pickle: str):
        """更新 Olm 会话"""
        if sender_key in self._olm_sessions and index < len(
            self._olm_sessions[sender_key]
        ):
            self._olm_sessions[sender_key][index] = session_pickle
            self._save_record(self._RECORD_SESSIONS, self._olm_sessions)

    def replace_olm_sessions(self, sender_key: str, session_pickles: list[str]) -> None:
        """Persist Olm sessions in most-recently-received order."""
        self._olm_sessions[sender_key] = list(session_pickles)
        self._save_record(self._RECORD_SESSIONS, self._olm_sessions)

    def clear_olm_sessions(self, sender_key: str):
        """清除与特定发送者的所有 Olm 会话"""
        if sender_key in self._olm_sessions:
            del self._olm_sessions[sender_key]
            self._save_record(self._RECORD_SESSIONS, self._olm_sessions)
