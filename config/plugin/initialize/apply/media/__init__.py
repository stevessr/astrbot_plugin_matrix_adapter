"""Plugin matrix_media configuration extraction and normalization."""

from .extract import _extract_media_settings
from .normalize import PluginConfigInitializationMediaNormalizeMixin


class PluginConfigInitializationMediaMixin(
    PluginConfigInitializationMediaNormalizeMixin,
):
    """Apply matrix_media settings from the config dictionary."""

    def _initialize_media_settings(self, config: dict) -> None:
        values = _extract_media_settings(config)
        self._apply_media_settings(values)


# Preserve direct method attributes exposed by the former monolithic module.
for _mixin in (PluginConfigInitializationMediaNormalizeMixin,):
    for _name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod, property)) or callable(
            _method
        ):
            setattr(PluginConfigInitializationMediaMixin, _name, _method)

__all__ = ["PluginConfigInitializationMediaMixin"]
