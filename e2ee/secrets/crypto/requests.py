"""Pending secret-request bookkeeping helpers."""


class E2EEManagerSecretsRequestsMixin:
    """待处理秘密请求的内存状态管理能力。"""

    @staticmethod
    def _mask_request_id(request_id: str | None) -> str:
        if not isinstance(request_id, str) or not request_id:
            return "<empty>"
        normalized = request_id.strip()
        if len(normalized) <= 8:
            return "***"
        return f"{normalized[:8]}..."

    def _get_pending_secret_request(self, request_id: str) -> dict | None:
        """获取待处理的秘密请求"""
        if not hasattr(self, "_pending_secret_requests"):
            self._pending_secret_requests = {}
        return self._pending_secret_requests.get(request_id)

    def _remove_pending_secret_request(self, request_id: str):
        """移除待处理的秘密请求"""
        if hasattr(self, "_pending_secret_requests"):
            self._pending_secret_requests.pop(request_id, None)

    def _add_pending_secret_request(self, request_id: str, secret_name: str):
        """添加待处理的秘密请求"""
        if not hasattr(self, "_pending_secret_requests"):
            self._pending_secret_requests = {}
        self._pending_secret_requests[request_id] = {"name": secret_name}
