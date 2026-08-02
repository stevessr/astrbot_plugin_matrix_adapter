"""Olm session creation and persistence helpers."""

from astrbot.api import logger

from ..types import Curve25519PublicKey, Session

# from repeated PreKey messages.  Per the spec, a single active session
# suffices; older sessions are retained for decryption of out-of-order
# messages that may still arrive.
MAX_OLM_SESSIONS_PER_PEER = 20


class OlmMachineSessionMixin:
    """Olm 出站会话创建与会话缓存管理能力。"""

    def create_outbound_session(
        self, their_identity_key: str, their_one_time_key: str
    ) -> Session:
        """
        创建出站 Olm 会话

        Args:
            their_identity_key: 对方的 curve25519 身份密钥
            their_one_time_key: 对方的一次性密钥

        Returns:
            新的 Olm 会话
        """
        if not self._account:
            raise RuntimeError("Olm 账户未初始化")

        # Convert keys from base64 string to Curve25519PublicKey
        identity_key = Curve25519PublicKey.from_base64(their_identity_key)
        one_time_key = Curve25519PublicKey.from_base64(their_one_time_key)

        session = self._account.create_outbound_session(identity_key, one_time_key)

        # 缓存会话 (cap per-peer to prevent memory exhaustion)
        if their_identity_key not in self._olm_sessions:
            self._olm_sessions[their_identity_key] = []
        sessions = self._olm_sessions[their_identity_key]
        sessions.append(session)
        if len(sessions) > MAX_OLM_SESSIONS_PER_PEER:
            sessions.pop(0)

        # 保存会话
        self.store.add_olm_session(their_identity_key, session.pickle(self._pickle_key))
        self._save_account()

        return session

    def get_olm_session(self, their_identity_key: str) -> Session | None:
        """
        获取与指定设备的现有 Olm 会话

        Args:
            their_identity_key: 对方的 curve25519 身份密钥

        Returns:
            现有的 Olm 会话，如果不存在则返回 None
        """
        sessions = self._olm_sessions.get(their_identity_key, [])
        if sessions:
            return sessions[-1]

        # 尝试从存储加载
        pickles = self.store.get_olm_sessions(their_identity_key)
        if pickles:
            try:
                loaded_sessions: list[Session] = []
                for pickle_data in pickles:
                    loaded_sessions.append(
                        Session.from_pickle(pickle_data, self._pickle_key)
                    )
                self._olm_sessions[their_identity_key] = loaded_sessions
                return loaded_sessions[-1]
            except Exception as e:
                logger.debug(f"加载 Olm 会话失败：{e}")

        return None
