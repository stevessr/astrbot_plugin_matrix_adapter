"""Room history visibility and encryption-state cache helpers."""

from .cache import E2EEManagerSessionShareEventsVisibilityCacheMixin
from .policy import E2EEManagerSessionShareEventsVisibilityPolicyMixin
from .rotate import E2EEManagerSessionShareEventsVisibilityRotateMixin


class E2EEManagerSessionShareEventsVisibilityMixin(
    E2EEManagerSessionShareEventsVisibilityCacheMixin,
    E2EEManagerSessionShareEventsVisibilityPolicyMixin,
    E2EEManagerSessionShareEventsVisibilityRotateMixin,
):
    """缓存房间加密配置并解析历史可见性策略。"""

    pass


# Preserve direct method attributes exposed by the former monolithic module.
for _mixin in (
    E2EEManagerSessionShareEventsVisibilityCacheMixin,
    E2EEManagerSessionShareEventsVisibilityPolicyMixin,
    E2EEManagerSessionShareEventsVisibilityRotateMixin,
):
    for _name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(E2EEManagerSessionShareEventsVisibilityMixin, _name, _method)

__all__ = ["E2EEManagerSessionShareEventsVisibilityMixin"]
