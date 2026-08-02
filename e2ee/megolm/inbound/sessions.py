from astrbot.api import logger

from ...olm.types import InboundGroupSession


class OlmMachineMegolmInboundSessionsMixin:
    def get_megolm_inbound_session(self, session_id: str):
        """
        获取 Megolm 入站会话对象（用于导出会话密钥等操作）

        Args:
            session_id: 会话 ID

        Returns:
            InboundGroupSession 或 None
        """
        # 先从缓存获取
        session = self._megolm_inbound.get(session_id)
        if session:
            return session

        # 尝试从存储加载
        pickle = self.store.get_megolm_inbound(session_id)
        if pickle:
            try:
                session = InboundGroupSession.from_pickle(pickle, self._pickle_key)
                self._megolm_inbound[session_id] = session
                return session
            except Exception as e:
                logger.error(f"加载 Megolm 会话失败：{e}")
                return None

        return None
