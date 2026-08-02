"""
Matrix 工具方法组件
"""

from ..utils_lib import MatrixUtilsMixin
from .helpers import _extract_text_repr, mask_device_id, parse_bool
from .image import compress_image_if_needed


class MatrixUtils(MatrixUtilsMixin):
    """
    Matrix 工具类（静态工具类）。

    The protocol-specific operations live in ``utils_lib`` mixins; this
    compatibility class keeps the historical import path and constructor
    contract.
    """

    def __init__(self):
        raise TypeError(
            "MatrixUtils is a static utility class and should not be instantiated"
        )


__all__ = [
    "MatrixUtils",
    "parse_bool",
    "mask_device_id",
    "_extract_text_repr",
    "compress_image_if_needed",
]
