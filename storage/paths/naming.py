"""Storage path component sanitization helpers."""

import re


class StoragePathNamingMixin:
    @staticmethod
    def sanitize_homeserver(homeserver: str) -> str:
        """清理 homeserver URL 为目录名。"""
        homeserver = homeserver.replace("https://", "").replace("http://", "")
        homeserver = homeserver.rstrip("/")
        return re.sub(r"[^\w\-\.]", "_", homeserver)

    @staticmethod
    def sanitize_username(user_id: str) -> str:
        """清理用户 ID 为目录名。"""
        username = user_id.replace("@", "").replace(":", "_")
        return re.sub(r"[^\w\-\.]", "_", username)


__all__ = ["StoragePathNamingMixin"]
