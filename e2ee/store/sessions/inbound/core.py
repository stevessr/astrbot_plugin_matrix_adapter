"""Megolm inbound-session storage accessors."""


class CryptoStoreMegolmInboundSessionsCoreMixin:
    def get_megolm_inbound(self, session_id: str) -> str | None:
        """获取 Megolm 入站会话"""
        return self._megolm_inbound.get(session_id)

    def get_megolm_inbound_ids(self) -> list[str]:
        """返回全部 Megolm 入站会话 ID 的快照。"""
        return list(self._megolm_inbound)

    def save_megolm_inbound(self, session_id: str, session_pickle: str):
        """保存 Megolm 入站会话"""
        self._megolm_inbound[session_id] = session_pickle
        self._save_record(self._RECORD_MEGOLM_INBOUND, self._megolm_inbound)

    def has_megolm_inbound(self, session_id: str) -> bool:
        """检查是否存在指定 Megolm 入站会话"""
        return session_id in self._megolm_inbound

    def get_megolm_inbound_count(self) -> int:
        """获取本地 Megolm 入站会话数量"""
        return len(self._megolm_inbound)
