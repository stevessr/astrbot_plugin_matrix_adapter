"""Platform metadata and localization resource loaders."""

import json
from pathlib import Path

from astrbot.api import logger

_PLUGIN_ROOT = Path(__file__).resolve().parents[2]


def _inject_astrbot_field_metadata() -> dict | None:
    """注入 Matrix 适配器的字段元数据到 AstrBot 配置系统。"""
    try:
        metadata_path = _PLUGIN_ROOT / "config_metadata.json"
        try:
            matrix_items = json.loads(metadata_path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.debug(f"读取 Matrix 字段元数据失败：{e}")
            return
        if not isinstance(matrix_items, dict):
            logger.debug("Matrix 字段元数据格式错误，期望为 dict")
            return

        return matrix_items

    except Exception as e:
        logger.error(f"注入 AstrBot 字段元数据失败：{e}")
        return None


def _load_i18n_resources() -> dict[str, dict]:
    """加载 i18n 资源文件。"""
    languages = ["zh-CN", "en-US", "ru-RU"]
    i18n_data = {}
    try:
        for language in languages:
            path = _PLUGIN_ROOT / "i18n" / f"{language}.json"
            if path.exists():
                i18n_data[language] = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.debug(f"加载 i18n 资源失败：{e}")

    return i18n_data


__all__ = ["_inject_astrbot_field_metadata", "_load_i18n_resources"]
