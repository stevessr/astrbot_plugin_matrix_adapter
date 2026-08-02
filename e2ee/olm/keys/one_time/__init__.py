"""Composable Olm one-time and fallback-key mixins."""

from astrbot.api import logger

from .....constants import DEFAULT_ONE_TIME_KEYS_COUNT
from ....verification.crypto_utils import _canonical_json
from .fallback import OlmMachineFallbackKeyMixin
from .generation import OlmMachineOneTimeKeyGenerationMixin
from .publishing import OlmMachineOneTimeKeyPublishingMixin


class OlmMachineOneTimeKeysMixin(
    OlmMachineOneTimeKeyGenerationMixin,
    OlmMachineOneTimeKeyPublishingMixin,
    OlmMachineFallbackKeyMixin,
):
    """一次性密钥、fallback key 生成与发布状态管理能力。"""

    pass


OlmMachineOneTimeKeysMixin.generate_one_time_keys = (
    OlmMachineOneTimeKeyGenerationMixin.__dict__["generate_one_time_keys"]
)
OlmMachineOneTimeKeysMixin.mark_keys_as_published = (
    OlmMachineOneTimeKeyPublishingMixin.__dict__["mark_keys_as_published"]
)
OlmMachineOneTimeKeysMixin.generate_fallback_key = OlmMachineFallbackKeyMixin.__dict__[
    "generate_fallback_key"
]
OlmMachineOneTimeKeysMixin.get_unpublished_fallback_key_count = (
    OlmMachineFallbackKeyMixin.__dict__["get_unpublished_fallback_key_count"]
)


__all__ = [
    "DEFAULT_ONE_TIME_KEYS_COUNT",
    "OlmMachineFallbackKeyMixin",
    "OlmMachineOneTimeKeyGenerationMixin",
    "OlmMachineOneTimeKeyPublishingMixin",
    "OlmMachineOneTimeKeysMixin",
    "_canonical_json",
    "logger",
]
