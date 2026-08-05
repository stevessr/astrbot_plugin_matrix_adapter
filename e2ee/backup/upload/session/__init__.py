"""Single-room-session upload operations for key backups."""

from .core import KeyBackupUploadSessionOrchestratorMixin
from .fallback import KeyBackupUploadSessionFallbackMixin
from .guard import KeyBackupUploadSessionGuardMixin


class KeyBackupUploadSessionMixin(
    KeyBackupUploadSessionOrchestratorMixin,
    KeyBackupUploadSessionFallbackMixin,
    KeyBackupUploadSessionGuardMixin,
):
    """上传单个房间会话密钥并处理接口回退。"""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    KeyBackupUploadSessionOrchestratorMixin,
    KeyBackupUploadSessionFallbackMixin,
    KeyBackupUploadSessionGuardMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(KeyBackupUploadSessionMixin, _method_name, _method)


__all__ = [
    "KeyBackupUploadSessionFallbackMixin",
    "KeyBackupUploadSessionGuardMixin",
    "KeyBackupUploadSessionMixin",
    "KeyBackupUploadSessionOrchestratorMixin",
]
